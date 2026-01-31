package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-redsync/redsync/v4"
	gors "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/common"
	mConvert "zotregistry.dev/zot/v2/pkg/meta/convert"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/meta/version"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

const (
	ImageMetaBucket       = "ImageMeta"
	RepoMetaBucket        = "RepoMeta"
	RepoBlobsBucket       = "RepoBlobsMeta"
	RepoLastUpdatedBucket = "RepoLastUpdated"
	UserDataBucket        = "UserData"
	VersionBucket         = "Version"
	UserAPIKeysBucket     = "UserAPIKeys"
	LocksBucket           = "Locks"
)

type RedisDB struct {
	Client             redis.UniversalClient
	imgTrustStore      mTypes.ImageTrustStore
	Patches            []func(client redis.UniversalClient) error
	Version            string
	Log                log.Logger
	RS                 *redsync.Redsync
	ImageMetaKey       string
	RepoMetaKey        string
	RepoBlobsKey       string
	RepoLastUpdatedKey string
	UserDataKey        string
	VersionKey         string
	UserAPIKeysKey     string
	LocksKey           string
}

type DBDriverParameters struct {
	KeyPrefix string
}

func New(client redis.UniversalClient, params DBDriverParameters, log log.Logger) (*RedisDB, error) {
	redisWrapper := RedisDB{
		Client:             client,
		Log:                log,
		Patches:            version.GetRedisDBPatches(),
		Version:            version.CurrentVersion,
		imgTrustStore:      nil,
		ImageMetaKey:       join(params.KeyPrefix, ImageMetaBucket),
		RepoMetaKey:        join(params.KeyPrefix, RepoMetaBucket),
		RepoBlobsKey:       join(params.KeyPrefix, RepoBlobsBucket),
		RepoLastUpdatedKey: join(params.KeyPrefix, RepoLastUpdatedBucket),
		UserDataKey:        join(params.KeyPrefix, UserDataBucket),
		VersionKey:         join(params.KeyPrefix, VersionBucket),
		UserAPIKeysKey:     join(params.KeyPrefix, UserAPIKeysBucket),
		LocksKey:           join(params.KeyPrefix, LocksBucket),
	}

	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Error().Err(err).Msg("failed to ping redis DB")

		return nil, err
	}

	// Create an instance of redisync to be used to obtain locks
	// these locks would be used only for writes in the DB
	// Depending on what resource/ bucket we want to lock,
	// the key used for locking can be:
	// - repo name
	// - image digest
	// - user ID
	// - version
	pool := gors.NewPool(client)
	redisWrapper.RS = redsync.New(pool)

	return &redisWrapper, nil
}

// GetStarredRepos returns starred repos and takes current user in consideration.
func (rc *RedisDB) GetStarredRepos(ctx context.Context) ([]string, error) {
	userData, err := rc.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.StarredRepos, err
}

// GetBookmarkedRepos returns bookmarked repos and takes current user in consideration.
func (rc *RedisDB) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	userData, err := rc.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.BookmarkedRepos, err
}

// ToggleStarRepo adds/removes stars on repos.
func (rc *RedisDB) ToggleStarRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var res mTypes.ToggleState

	err = rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo), rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			res = mTypes.NotChanged

			return err
		}

		isRepoStarred := slices.Contains(userData.StarredRepos, repo)

		if isRepoStarred {
			res = mTypes.Removed

			userData.StarredRepos = zcommon.RemoveFrom(userData.StarredRepos, repo)
		} else {
			res = mTypes.Added

			userData.StarredRepos = append(userData.StarredRepos, repo)
		}

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			res = mTypes.NotChanged

			return err
		}

		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			res = mTypes.NotChanged

			return err
		}

		switch res {
		case mTypes.Added:
			protoRepoMeta.Stars++
		case mTypes.Removed:
			protoRepoMeta.Stars--
		}

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			res = mTypes.NotChanged

			return err
		}

		_, err = rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err = txrp.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
					Msg("failed to set user data record")

				return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
			}

			if err := txrp.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to put repo meta record")

				return fmt.Errorf("failed to set repometa for repo %s: %w", repo, err)
			}

			return nil
		})

		return err
	})

	return res, err
}

// ToggleBookmarkRepo adds/removes bookmarks on repos.
func (rc *RedisDB) ToggleBookmarkRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var res mTypes.ToggleState

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			res = mTypes.NotChanged

			return err
		}

		isRepoBookmarked := slices.Contains(userData.BookmarkedRepos, repo)

		if isRepoBookmarked {
			res = mTypes.Removed

			userData.BookmarkedRepos = zcommon.RemoveFrom(userData.BookmarkedRepos, repo)
		} else {
			res = mTypes.Added

			userData.BookmarkedRepos = append(userData.BookmarkedRepos, repo)
		}

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			res = mTypes.NotChanged

			return err
		}

		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			res = mTypes.NotChanged

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return err
	})

	return res, err
}

func (rc *RedisDB) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	userData := mTypes.UserData{}
	userData.APIKeys = make(map[string]mTypes.APIKeyDetails)

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return userData, err
	}

	if userAc.IsAnonymous() {
		return userData, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	userDataBlob, err := rc.Client.HGet(ctx, rc.UserDataKey, userid).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		rc.Log.Error().Err(err).Str("hget", rc.UserDataKey).Str("userid", userid).
			Msg("failed to get user data record")

		return userData, fmt.Errorf("failed to get user data record for identity %s: %w", userid, err)
	}

	if errors.Is(err, redis.Nil) {
		return userData, zerr.ErrUserDataNotFound
	}

	err = json.Unmarshal(userDataBlob, &userData)

	if userData.APIKeys == nil {
		// Unmarshal may have reset the value
		userData.APIKeys = make(map[string]mTypes.APIKeyDetails)
	}

	return userData, err
}

// SetUserData should NEVER be used in production as both GetUserData and SetUserData
// should be locked for the duration of the entire transaction at a higher level in the app.
func (rc *RedisDB) SetUserData(ctx context.Context, userData mTypes.UserData) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	userDataBlob, err := json.Marshal(userData)
	if err != nil {
		return err
	}

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) SetUserGroups(ctx context.Context, groups []string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		userData.Groups = groups

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) GetUserGroups(ctx context.Context) ([]string, error) {
	userData, err := rc.GetUserData(ctx)

	return userData.Groups, err
}

func (rc *RedisDB) DeleteUserData(ctx context.Context) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		_, err = rc.GetUserData(ctx)
		if err != nil && errors.Is(err, zerr.ErrUserDataNotFound) {
			return zerr.ErrBucketDoesNotExist
		}

		err = rc.Client.HDel(ctx, rc.UserDataKey, userid).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hdel", rc.UserDataKey).Str("userid", userid).
				Msg("failed to delete user data record")

			return fmt.Errorf("failed to delete user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	ctx := context.Background()

	userid, err := rc.Client.HGet(ctx, rc.UserAPIKeysKey, hashedKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		rc.Log.Error().Err(err).Str("hget", rc.UserAPIKeysKey).Str("userid", userid).
			Msg("failed to get api key record")

		return userid, fmt.Errorf("failed to get api key record for identity %s: %w", userid, err)
	}

	if len(userid) == 0 || errors.Is(err, redis.Nil) {
		return userid, zerr.ErrUserAPIKeyNotFound
	}

	return userid, err
}

func (rc *RedisDB) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	apiKeys := make([]mTypes.APIKeyDetails, 0)

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if userAc.IsAnonymous() {
		return nil, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	// Lock used because getting API keys also updates their expired flag in the DB
	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		changed := false

		for hashedKey, apiKeyDetails := range userData.APIKeys {
			// if expiresAt is not nil value
			if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
				apiKeyDetails.IsExpired = true

				changed = true
			}

			userData.APIKeys[hashedKey] = apiKeyDetails

			apiKeys = append(apiKeys, apiKeyDetails)
		}

		if !changed {
			// return early, no need to make a call to update key expiry in the DB
			return nil
		}

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return apiKeys, err
}

func (rc *RedisDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		userData.APIKeys[hashedKey] = *apiKeyDetails

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			return err
		}

		_, err = rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err := txrp.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
					Msg("failed to set user data record")

				return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
			}

			if err := txrp.HSet(ctx, rc.UserAPIKeysKey, hashedKey, userid).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.UserAPIKeysKey).Str("userid", userid).
					Msg("failed to set api key record")

				return fmt.Errorf("failed to set api key for identity %s: %w", userid, err)
			}

			return nil
		})

		return err
	})

	return err
}

func (rc *RedisDB) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return false, err
	}

	if userAc.IsAnonymous() {
		return false, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var isExpired bool

	// Lock used because getting API keys also updates their expired flag in the DB
	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		apiKeyDetails := userData.APIKeys[hashedKey]
		if apiKeyDetails.IsExpired {
			isExpired = true

			return nil
		}

		// if expiresAt is not nil value
		if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
			isExpired = true
			apiKeyDetails.IsExpired = true
		}

		userData.APIKeys[hashedKey] = apiKeyDetails

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return isExpired, err
}

func (rc *RedisDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		apiKeyDetails := userData.APIKeys[hashedKey]
		apiKeyDetails.LastUsed = time.Now()

		userData.APIKeys[hashedKey] = apiKeyDetails

		userDataBlob, err := json.Marshal(userData)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
				Msg("failed to set user data record")

			return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) DeleteUserAPIKey(ctx context.Context, keyID string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = rc.withRSLocks(ctx, []string{rc.getUserLockKey(userid)}, func() error {
		userData, err := rc.GetUserData(ctx)
		if err != nil {
			return err
		}

		for hash, apiKeyDetails := range userData.APIKeys {
			if apiKeyDetails.UUID != keyID {
				continue
			}

			delete(userData.APIKeys, hash)

			userDataBlob, err := json.Marshal(userData)
			if err != nil {
				return err
			}

			_, err = rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
				if err = txrp.HSet(ctx, rc.UserDataKey, userid, userDataBlob).Err(); err != nil {
					rc.Log.Error().Err(err).Str("hset", rc.UserDataKey).Str("userid", userid).
						Msg("failed to set user data record")

					return fmt.Errorf("failed to set user data for identity %s: %w", userid, err)
				}

				if err = txrp.HDel(ctx, rc.UserAPIKeysKey, hash).Err(); err != nil {
					rc.Log.Error().Err(err).Str("hdel", rc.UserAPIKeysKey).Str("userid", userid).
						Msg("failed to delete api key record")

					return fmt.Errorf("failed to delete api key record for identity %s: %w", userid, err)
				}

				return nil
			})
		}

		return nil
	})

	return err
}

// SetImageMeta should NEVER be used in production as both GetImageMeta and SetImageMeta
// should be locked for the duration of the entire transaction at a higher level in the app.
func (rc *RedisDB) SetImageMeta(digest godigest.Digest, imageMeta mTypes.ImageMeta) error {
	protoImageMeta := &proto_go.ImageMeta{}
	ctx := context.Background()

	if imageMeta.MediaType == ispec.MediaTypeImageManifest ||
		compat.IsCompatibleManifestMediaType(imageMeta.MediaType) {
		manifest := imageMeta.Manifests[0]
		protoImageMeta = mConvert.GetProtoImageManifestData(manifest.Manifest, manifest.Config,
			manifest.Size, manifest.Digest.String())
	} else if imageMeta.MediaType == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(imageMeta.MediaType) {
		protoImageMeta = mConvert.GetProtoImageIndexMeta(*imageMeta.Index, imageMeta.Size, imageMeta.Digest.String())
	}

	pImageMetaBlob, err := proto.Marshal(protoImageMeta)
	if err != nil {
		return fmt.Errorf("failed to calculate blob for manifest with digest %s %w", digest, err)
	}

	err = rc.withRSLocks(ctx, []string{rc.getImageLockKey(digest.String())}, func() error {
		err = rc.Client.HSet(ctx, rc.ImageMetaKey, digest.String(), pImageMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.ImageMetaKey).Str("digest", digest.String()).
				Msg("failed to set image meta record")

			return fmt.Errorf("failed to set image meta record for digest %s: %w", digest.String(), err)
		}

		return nil
	})

	return err
}

// SetRepoReference sets the given image data to the repo metadata.
//
//nolint:gocyclo // Complex function handling multiple metadata updates (referrers, tags, statistics, signatures, blobs)
func (rc *RedisDB) SetRepoReference(ctx context.Context, repo string,
	reference string, imageMeta mTypes.ImageMeta,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, imageMeta.Digest); err != nil {
		return err
	}

	var userid string

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err == nil {
		userid = userAc.GetUsername()
	}

	// 1. Add image data to db if needed
	protoImageMeta := mConvert.GetProtoImageMeta(imageMeta)

	imageMetaBlob, err := proto.Marshal(protoImageMeta)
	if err != nil {
		return err
	}

	err = rc.withRSLocks(ctx, []string{rc.getImageLockKey(imageMeta.Digest.String())}, func() error {
		err := rc.Client.HSet(ctx, rc.ImageMetaKey, imageMeta.Digest.String(), imageMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.ImageMetaKey).Str("digest", imageMeta.Digest.String()).
				Msg("failed to set image meta record")

			return fmt.Errorf("failed to set image meta record for digest %s: %w", imageMeta.Digest.String(), err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		// 2. Referrers
		if subject := mConvert.GetImageSubject(protoImageMeta); subject != nil {
			refInfo := &proto_go.ReferrersInfo{}
			if protoRepoMeta.Referrers[subject.Digest.String()] != nil {
				refInfo = protoRepoMeta.Referrers[subject.Digest.String()]
			}

			foundReferrer := false

			for i := range refInfo.List {
				if refInfo.List[i].Digest == mConvert.GetImageDigestStr(protoImageMeta) {
					foundReferrer = true
					refInfo.List[i].Count += 1

					break
				}
			}

			if !foundReferrer {
				refInfo.List = append(refInfo.List, &proto_go.ReferrerInfo{
					Count:        1,
					MediaType:    protoImageMeta.MediaType,
					Digest:       mConvert.GetImageDigestStr(protoImageMeta),
					ArtifactType: mConvert.GetImageArtifactType(protoImageMeta),
					Size:         mConvert.GetImageManifestSize(protoImageMeta),
					Annotations:  mConvert.GetImageAnnotations(protoImageMeta),
				})
			}

			protoRepoMeta.Referrers[subject.Digest.String()] = refInfo
		}

		// 3. Update tag
		if !common.ReferenceIsDigest(reference) {
			// Set TaggedTimestamp to now if this is a new tag, otherwise preserve existing timestamp
			// For old data without TaggedTimestamp, leave it nil so it falls back to PushTimestamp
			var taggedTimestamp *timestamppb.Timestamp
			if existingTag, exists := protoRepoMeta.Tags[reference]; exists {
				// Tag exists - preserve TaggedTimestamp if present, otherwise leave nil (old data)
				if existingTag.GetTaggedTimestamp() != nil {
					taggedTimestamp = existingTag.GetTaggedTimestamp()
				}
				// else leave taggedTimestamp as nil (old data without TaggedTimestamp)
			} else {
				// New tag - set timestamp to now
				taggedTimestamp = timestamppb.Now()
			}
			protoRepoMeta.Tags[reference] = &proto_go.TagDescriptor{
				Digest:          imageMeta.Digest.String(),
				MediaType:       imageMeta.MediaType,
				TaggedTimestamp: taggedTimestamp,
			}
		}

		digestStr := imageMeta.Digest.String()
		stats, ok := protoRepoMeta.Statistics[digestStr]

		if !ok {
			stats = &proto_go.DescriptorStatistics{
				DownloadCount:     0,
				LastPullTimestamp: &timestamppb.Timestamp{},
				PushTimestamp:     timestamppb.Now(),
				PushedBy:          userid,
			}
			protoRepoMeta.Statistics[digestStr] = stats
		} else {
			if stats.PushTimestamp.AsTime().IsZero() {
				stats.PushTimestamp = timestamppb.Now()
			}

			if userid != "" && stats.PushedBy == "" {
				stats.PushedBy = userid
			}
		}

		if _, ok := protoRepoMeta.Signatures[imageMeta.Digest.String()]; !ok {
			protoRepoMeta.Signatures[imageMeta.Digest.String()] = &proto_go.ManifestSignatures{
				Map: map[string]*proto_go.SignaturesInfo{"": {}},
			}
		}

		if _, ok := protoRepoMeta.Referrers[imageMeta.Digest.String()]; !ok {
			protoRepoMeta.Referrers[imageMeta.Digest.String()] = &proto_go.ReferrersInfo{
				List: []*proto_go.ReferrerInfo{},
			}
		}

		// 4. Blobs
		repoBlobsBytes, err := rc.Client.HGet(ctx, rc.RepoBlobsKey, repo).Bytes()
		if err != nil && !errors.Is(err, redis.Nil) {
			rc.Log.Error().Err(err).Str("hget", rc.RepoBlobsKey).Str("repo", repo).
				Msg("failed to get repo blobs record")

			return fmt.Errorf("failed to get repo blobs record for repo %s: %w", repo, err)
		}

		repoBlobs, err := unmarshalProtoRepoBlobs(repo, repoBlobsBytes)
		if err != nil {
			return err
		}

		protoRepoMeta, repoBlobs = common.AddImageMetaToRepoMeta(protoRepoMeta, repoBlobs, reference, imageMeta)
		protoTime := timestamppb.New(time.Now())

		protoTimeBlob, err := proto.Marshal(protoTime)
		if err != nil {
			return err
		}

		repoBlobsBytes, err = proto.Marshal(repoBlobs)
		if err != nil {
			return err
		}

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		_, err = rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err := txrp.HSet(ctx, rc.RepoLastUpdatedKey, repo, protoTimeBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoLastUpdatedKey).Str("repo", repo).
					Msg("failed to put repo last updated timestamp")

				return fmt.Errorf("failed to put repo last updated record for repo %s: %w", repo, err)
			}

			if err := txrp.HSet(ctx, rc.RepoBlobsKey, repo, repoBlobsBytes).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoBlobsKey).Str("repo", repo).
					Msg("failed to put repo blobs record")

				return fmt.Errorf("failed to set repo blobs record for repo %s: %w", repo, err)
			}

			if err := txrp.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to put repo meta record")

				return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
			}

			return nil
		})

		return err
	})

	return err
}

// SearchRepos searches for repos given a search string.
func (rc *RedisDB) SearchRepos(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
	foundRepos := []mTypes.RepoMeta{}

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return foundRepos, fmt.Errorf("failed to get all repo meta records: %w", err)
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	for repo, repoMetaBlob := range repoMetaEntries {
		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
			continue
		}

		rank := common.RankRepoName(searchText, repo)
		if rank == -1 {
			continue
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, []byte(repoMetaBlob))
		if err != nil {
			// similarly with other metadb implementations, do not return a partial result on error
			return []mTypes.RepoMeta{}, err
		}

		delete(protoRepoMeta.Tags, "")

		if len(protoRepoMeta.Tags) == 0 {
			continue
		}

		protoRepoMeta.Rank = int32(rank) //nolint:gosec // ignore overflow
		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)

		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)
		foundRepos = append(foundRepos, repoMeta)
	}

	return foundRepos, nil
}

// SearchTags searches for images(repo:tag) given a search string.
func (rc *RedisDB) SearchTags(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return images, fmt.Errorf("failed to parse search text, invalid format %w", err)
	}

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return images, fmt.Errorf("failed to get all repo meta records: %w", err)
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	for repo, repoMetaBlob := range repoMetaEntries {
		if repo != searchedRepo {
			continue
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
			return images, err
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, []byte(repoMetaBlob))
		if err != nil {
			return images, err
		}

		delete(protoRepoMeta.Tags, "")

		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)

		for tag, descriptor := range protoRepoMeta.Tags {
			if !strings.HasPrefix(tag, searchedTag) || tag == "" {
				continue
			}

			var protoImageMeta *proto_go.ImageMeta

			if descriptor.MediaType == ispec.MediaTypeImageManifest || //nolint:gocritic
				compat.IsCompatibleManifestMediaType(descriptor.MediaType) {
				manifestDigest := descriptor.Digest

				imageManifestData, err := rc.getProtoImageMeta(ctx, manifestDigest)
				if err != nil {
					return images, fmt.Errorf("failed to fetch manifest meta for manifest with digest %s %w",
						manifestDigest, err)
				}

				protoImageMeta = imageManifestData
			} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
				compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
				indexDigest := descriptor.Digest

				imageIndexData, err := rc.getProtoImageMeta(ctx, indexDigest)
				if err != nil {
					return images, fmt.Errorf("failed to fetch manifest meta for manifest with digest %s %w",
						indexDigest, err)
				}

				_, manifestDataList, err := rc.getAllContainedMeta(ctx, imageIndexData)
				if err != nil {
					return images, err
				}

				imageIndexData.Manifests = manifestDataList

				protoImageMeta = imageIndexData
			} else {
				rc.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

				continue
			}

			images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta))
		}
	}

	return images, nil
}

// FilterTags filters for images given a filter function.
func (rc *RedisDB) FilterTags(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
	filterFunc mTypes.FilterFunc,
) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return images, fmt.Errorf("failed to get all repo meta records: %w", err)
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	var unifiedErr error

	for repo, repoMetaBlob := range repoMetaEntries {
		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
			continue
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, []byte(repoMetaBlob))
		if err != nil {
			unifiedErr = errors.Join(unifiedErr, err)

			continue
		}

		delete(protoRepoMeta.Tags, "")
		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)
		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		for tag, descriptor := range protoRepoMeta.Tags {
			if !filterRepoTag(repo, tag) {
				continue
			}

			if descriptor.MediaType == ispec.MediaTypeImageManifest || //nolint:gocritic
				compat.IsCompatibleManifestMediaType(descriptor.MediaType) {
				manifestDigest := descriptor.Digest

				imageManifestData, err := rc.getProtoImageMeta(ctx, manifestDigest)
				if err != nil {
					unifiedErr = errors.Join(unifiedErr, err)

					continue
				}

				imageMeta := mConvert.GetImageMeta(imageManifestData)

				if filterFunc(repoMeta, imageMeta) {
					images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, imageManifestData))
				}
			} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
				compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
				indexDigest := descriptor.Digest

				protoImageIndexMeta, err := rc.getProtoImageMeta(ctx, indexDigest)
				if err != nil {
					unifiedErr = errors.Join(unifiedErr, err)

					continue
				}

				imageIndexMeta := mConvert.GetImageMeta(protoImageIndexMeta)
				matchedManifests := []*proto_go.ManifestMeta{}

				imageManifestDataList, _, err := rc.getAllContainedMeta(ctx, protoImageIndexMeta)
				if err != nil {
					unifiedErr = errors.Join(unifiedErr, err)

					continue
				}

				for _, imageManifestData := range imageManifestDataList {
					imageMeta := mConvert.GetImageMeta(imageManifestData)
					partialImageMeta := common.GetPartialImageMeta(imageIndexMeta, imageMeta)

					if filterFunc(repoMeta, partialImageMeta) {
						matchedManifests = append(matchedManifests, imageManifestData.Manifests[0])
					}
				}

				if len(matchedManifests) > 0 {
					protoImageIndexMeta.Manifests = matchedManifests

					images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageIndexMeta))
				}
			} else {
				rc.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

				continue
			}
		}
	}

	return images, unifiedErr
}

// FilterRepos filters for repos given a filter function.
func (rc *RedisDB) FilterRepos(ctx context.Context, acceptName mTypes.FilterRepoNameFunc,
	filterFunc mTypes.FilterFullRepoFunc,
) ([]mTypes.RepoMeta, error) {
	foundRepos := []mTypes.RepoMeta{}

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return foundRepos, fmt.Errorf("failed to get all repo meta records: %w", err)
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	for repo, repoMetaBlob := range repoMetaEntries {
		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
			continue
		}

		if !acceptName(repo) {
			continue
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, []byte(repoMetaBlob))
		if err != nil {
			// similarly with other metadb implementations, do not return a partial result on error
			return []mTypes.RepoMeta{}, err
		}

		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
		protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)

		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		if filterFunc(repoMeta) {
			foundRepos = append(foundRepos, repoMeta)
		}
	}

	return foundRepos, nil
}

// GetRepoMeta returns the full information about a repo.
func (rc *RedisDB) GetRepoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return mTypes.RepoMeta{}, err
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	delete(protoRepoMeta.Tags, "")
	protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, repo)
	protoRepoMeta.IsStarred = slices.Contains(userStars, repo)

	return mConvert.GetRepoMeta(protoRepoMeta), nil
}

// GetFullImageMeta returns the full information about an image.
func (rc *RedisDB) GetFullImageMeta(ctx context.Context, repo string, tag string) (mTypes.FullImageMeta, error) {
	protoImageMeta := &proto_go.ImageMeta{}

	protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), err
	}

	userBookmarks, userStars := rc.getUserBookmarksAndStarsNoError(ctx)

	delete(protoRepoMeta.Tags, "")
	protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, repo)
	protoRepoMeta.IsStarred = slices.Contains(userStars, repo)

	descriptor, ok := protoRepoMeta.Tags[tag]
	if !ok {
		return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta),
			fmt.Errorf("%w for tag %s in repo %s", zerr.ErrImageMetaNotFound, tag, repo)
	}

	protoImageMeta, err = rc.getProtoImageMeta(ctx, descriptor.Digest)
	if err != nil {
		return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), err
	}

	if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
		_, manifestDataList, err := rc.getAllContainedMeta(ctx, protoImageMeta)
		if err != nil {
			return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), err
		}

		protoImageMeta.Manifests = manifestDataList
	}

	return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), nil
}

// GetImageMeta returns the raw information about an image.
func (rc *RedisDB) GetImageMeta(digest godigest.Digest) (mTypes.ImageMeta, error) {
	imageMeta := mTypes.ImageMeta{}
	ctx := context.Background()

	protoImageMeta, err := rc.getProtoImageMeta(ctx, digest.String())
	if err != nil {
		return imageMeta, err
	}

	if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
		compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
		_, manifestDataList, err := rc.getAllContainedMeta(ctx, protoImageMeta)
		if err != nil {
			return imageMeta, err
		}

		protoImageMeta.Manifests = manifestDataList
	}

	imageMeta = mConvert.GetImageMeta(protoImageMeta)

	return imageMeta, nil
}

// GetMultipleRepoMeta returns a list of all repos that match the given filter function.
func (rc *RedisDB) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool) (
	[]mTypes.RepoMeta, error,
) {
	foundRepos := []mTypes.RepoMeta{}

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return foundRepos, fmt.Errorf("failed to get all repometa records: %w", err)
	}

	for repo, repoMetaBlob := range repoMetaEntries {
		if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
			continue
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, []byte(repoMetaBlob))
		if err != nil {
			// similarly with other metadb implementations, return a partial result on error
			return foundRepos, err
		}

		delete(protoRepoMeta.Tags, "")

		repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

		if filter(repoMeta) {
			foundRepos = append(foundRepos, repoMeta)
		}
	}

	return foundRepos, nil
}

// AddManifestSignature adds signature metadata to a given manifest in the database.
func (rc *RedisDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			var err error
			// create a new object
			repoMeta := proto_go.RepoMeta{
				Name: repo,
				Tags: map[string]*proto_go.TagDescriptor{"": {}},
				Signatures: map[string]*proto_go.ManifestSignatures{
					signedManifestDigest.String(): {
						Map: map[string]*proto_go.SignaturesInfo{
							sigMeta.SignatureType: {
								List: []*proto_go.SignatureInfo{
									{
										SignatureManifestDigest: sigMeta.SignatureDigest,
										LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
									},
								},
							},
						},
					},
				},
				Referrers:  map[string]*proto_go.ReferrersInfo{"": {}},
				Statistics: map[string]*proto_go.DescriptorStatistics{"": {}},
			}

			repoMetaBlob, err := proto.Marshal(&repoMeta)
			if err != nil {
				return err
			}

			if err := rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to put repo meta record")

				return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
			}

			return nil
		}

		var (
			manifestSignatures *proto_go.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = protoRepoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = &proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{"": {}}}
		}

		signatureSlice := &proto_go.SignaturesInfo{List: []*proto_go.SignatureInfo{}}
		if sigSlice, found := manifestSignatures.Map[sigMeta.SignatureType]; found {
			signatureSlice = sigSlice
		}

		if !common.ProtoSignatureAlreadyExists(signatureSlice.List, sigMeta) {
			switch sigMeta.SignatureType {
			case zcommon.NotationSignature:
				signatureSlice.List = append(signatureSlice.List, &proto_go.SignatureInfo{
					SignatureManifestDigest: sigMeta.SignatureDigest,
					LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
				})
			case zcommon.CosignSignature:
				newCosignSig := &proto_go.SignatureInfo{
					SignatureManifestDigest: sigMeta.SignatureDigest,
					LayersInfo:              mConvert.GetProtoLayersInfo(sigMeta.LayersInfo),
				}

				if zcommon.IsCosignTag(sigMeta.SignatureTag) {
					// the entry for "sha256-{digest}.sig" signatures should be overwritten if
					// it exists or added on the first position if it doesn't exist
					if len(signatureSlice.GetList()) == 0 {
						signatureSlice.List = []*proto_go.SignatureInfo{newCosignSig}
					} else {
						signatureSlice.List[0] = newCosignSig
					}
				} else {
					// the first position should be reserved for "sha256-{digest}.sig" signatures
					if len(signatureSlice.GetList()) == 0 {
						signatureSlice.List = []*proto_go.SignatureInfo{{
							SignatureManifestDigest: "",
							LayersInfo:              []*proto_go.LayersInfo{},
						}}
					}

					signatureSlice.List = append(signatureSlice.List, newCosignSig)
				}
			}
		}

		manifestSignatures.Map[sigMeta.SignatureType] = signatureSlice
		protoRepoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// DeleteSignature deletes signature metadata to a given manifest from the database.
func (rc *RedisDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			return err
		}

		manifestSignatures, found := protoRepoMeta.Signatures[signedManifestDigest.String()]
		if !found {
			return zerr.ErrImageMetaNotFound
		}

		signatureSlice := manifestSignatures.Map[sigMeta.SignatureType]

		newSignatureSlice := make([]*proto_go.SignatureInfo, 0, len(signatureSlice.List))

		for _, sigInfo := range signatureSlice.List {
			if sigInfo.SignatureManifestDigest != sigMeta.SignatureDigest {
				newSignatureSlice = append(newSignatureSlice, sigInfo)
			}
		}

		manifestSignatures.Map[sigMeta.SignatureType] = &proto_go.SignaturesInfo{List: newSignatureSlice}
		protoRepoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// UpdateSignaturesValidity checks and updates signatures validity of a given manifest.
func (rc *RedisDB) UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error {
	imgTrustStore := rc.ImageTrustStore()

	if imgTrustStore == nil {
		return nil
	}

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		// get ManifestData of signed manifest
		protoImageMeta, err := rc.getProtoImageMeta(ctx, manifestDigest.String())
		if err != nil {
			if errors.Is(err, zerr.ErrImageMetaNotFound) {
				// manifest meta not found, updating signatures with details about validity and author will not be performed
				return nil
			}

			return err
		}

		// update signatures with details about validity and author
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			return err
		}

		manifestSignatures := proto_go.ManifestSignatures{Map: map[string]*proto_go.SignaturesInfo{"": {}}}

		for sigType, sigs := range protoRepoMeta.Signatures[manifestDigest.String()].Map {
			if zcommon.IsContextDone(ctx) {
				return ctx.Err()
			}

			signaturesInfo := []*proto_go.SignatureInfo{}

			for _, sigInfo := range sigs.List {
				layersInfo := []*proto_go.LayersInfo{}

				for _, layerInfo := range sigInfo.LayersInfo {
					author, date, isTrusted, _ := imgTrustStore.VerifySignature(sigType, layerInfo.LayerContent,
						layerInfo.SignatureKey, manifestDigest, mConvert.GetImageMeta(protoImageMeta), repo)

					if isTrusted {
						layerInfo.Signer = author
					}

					if !date.IsZero() {
						layerInfo.Signer = author
						layerInfo.Date = timestamppb.New(date)
					}

					layersInfo = append(layersInfo, layerInfo)
				}

				signaturesInfo = append(signaturesInfo, &proto_go.SignatureInfo{
					SignatureManifestDigest: sigInfo.SignatureManifestDigest,
					LayersInfo:              layersInfo,
				})
			}

			manifestSignatures.Map[sigType] = &proto_go.SignaturesInfo{List: signaturesInfo}
		}

		protoRepoMeta.Signatures[manifestDigest.String()] = &manifestSignatures

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// IncrementRepoStars adds 1 to the star count of an image.
func (rc *RedisDB) IncrementRepoStars(repo string) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			return err
		}

		protoRepoMeta.Stars++

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// DecrementRepoStars subtracts 1 from the star count of an image.
func (rc *RedisDB) DecrementRepoStars(repo string) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			return err
		}

		if protoRepoMeta.Stars == 0 {
			return nil
		}

		protoRepoMeta.Stars--

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// SetRepoMeta should NEVER be used in production as both GetRepoMeta and SetRepoMeta
// should be locked for the duration of the entire transaction at a higher level in the app.
func (rc *RedisDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMeta) error {
	repoMeta.Name = repo

	repoMetaBlob, err := proto.Marshal(mConvert.GetProtoRepoMeta(repoMeta))
	if err != nil {
		return err
	}

	// The last update time is set to 0 in order to force an update in case of a next storage parsing
	protoTime := timestamppb.New(time.Time{})

	protoTimeBlob, err := proto.Marshal(protoTime)
	if err != nil {
		return err
	}

	ctx := context.Background()

	err = rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		_, err := rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err := txrp.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to put repo meta record")

				return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
			}

			if err := txrp.HSet(ctx, rc.RepoLastUpdatedKey, repo, protoTimeBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoLastUpdatedKey).Str("repo", repo).
					Msg("failed to put repo last updated timestamp")

				return fmt.Errorf("failed to put repo last updated record for repo %s: %w", repo, err)
			}

			return nil
		})

		return err
	})

	return err
}

func (rc *RedisDB) DeleteRepoMeta(repo string) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		_, err := rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err := txrp.HDel(ctx, rc.RepoMetaKey, repo).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hdel", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to delete repo meta record")

				return fmt.Errorf("failed to delete repometa record for repo %s: %w", repo, err)
			}

			if err := txrp.HDel(ctx, rc.RepoBlobsKey, repo).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hdel", rc.RepoBlobsKey).Str("repo", repo).
					Msg("failed to put repo blobs record")

				return fmt.Errorf("failed to delete repo blobs record for repo %s: %w", repo, err)
			}

			if err := txrp.HDel(ctx, rc.RepoLastUpdatedKey, repo).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hdel", rc.RepoLastUpdatedKey).Str("repo", repo).
					Msg("failed to put repo last updated timestamp")

				return fmt.Errorf("failed to delete repo last updated record for repo %s: %w", repo, err)
			}

			return nil
		})

		return err
	})

	return err
}

// GetReferrersInfo returns a list of  for all referrers of the given digest that match one of the
// artifact types.
func (rc *RedisDB) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	referrersInfoResult := []mTypes.ReferrerInfo{}
	ctx := context.Background()

	protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
	if err != nil {
		return referrersInfoResult, err
	}

	referrersInfo := protoRepoMeta.Referrers[referredDigest.String()].List
	seenDigests := make(map[string]struct{})

	for i := range referrersInfo {
		if !common.MatchesArtifactTypes(referrersInfo[i].ArtifactType, artifactTypes) {
			continue
		}

		if _, seen := seenDigests[referrersInfo[i].Digest]; seen {
			continue
		}

		seenDigests[referrersInfo[i].Digest] = struct{}{}

		referrersInfoResult = append(referrersInfoResult, mTypes.ReferrerInfo{
			Digest:       referrersInfo[i].Digest,
			MediaType:    referrersInfo[i].MediaType,
			ArtifactType: referrersInfo[i].ArtifactType,
			Size:         int(referrersInfo[i].Size),
			Annotations:  referrersInfo[i].Annotations,
		})
	}

	return referrersInfoResult, nil
}

// UpdateStatsOnDownload adds 1 to the download count of an image and sets the timestamp of download.
func (rc *RedisDB) UpdateStatsOnDownload(repo string, reference string) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			return err
		}

		manifestDigest := reference

		if common.ReferenceIsTag(reference) {
			descriptor, found := protoRepoMeta.Tags[reference]

			if !found {
				return zerr.ErrImageMetaNotFound
			}

			manifestDigest = descriptor.Digest
		}

		manifestStatistics, ok := protoRepoMeta.Statistics[manifestDigest]
		if !ok {
			// Statistics entry doesn't exist - validate digest exists in this repository before creating it
			// Check if digest is referenced in any tag for this repository
			digestExists := false

			for _, tagDescriptor := range protoRepoMeta.Tags {
				if tagDescriptor.Digest == manifestDigest {
					digestExists = true

					break
				}
			}

			if !digestExists {
				return zerr.ErrImageMetaNotFound
			}

			// Statistics entry doesn't exist - create it
			// This can happen if SetRepoReference failed or wasn't called
			manifestStatistics = &proto_go.DescriptorStatistics{
				DownloadCount:     0,
				LastPullTimestamp: &timestamppb.Timestamp{},
				PushTimestamp:     &timestamppb.Timestamp{}, // Unknown push time
				PushedBy:          "",                       // Unknown pusher
			}
		}

		manifestStatistics.DownloadCount++
		manifestStatistics.LastPullTimestamp = timestamppb.Now()
		protoRepoMeta.Statistics[manifestDigest] = manifestStatistics

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		err = rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err()
		if err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

// FilterImageMeta returns the image data for the given digests.
func (rc *RedisDB) FilterImageMeta(ctx context.Context,
	digests []string,
) (map[mTypes.ImageDigest]mTypes.ImageMeta, error) {
	imageMetaMap := map[string]mTypes.ImageMeta{}

	for _, digest := range digests {
		protoImageMeta, err := rc.getProtoImageMeta(ctx, digest)
		if err != nil {
			return imageMetaMap, err
		}

		if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
			_, manifestDataList, err := rc.getAllContainedMeta(ctx, protoImageMeta)
			if err != nil {
				return imageMetaMap, err
			}

			protoImageMeta.Manifests = manifestDataList
		}

		imageMetaMap[digest] = mConvert.GetImageMeta(protoImageMeta)
	}

	return imageMetaMap, nil
}

// RemoveRepoReference removes the tag from RepoMetadata if the reference is a tag.
// It also removes its corresponding digest from Statistics, Signatures and Referrers if there are no tags
// pointing to it.
// If the reference is a digest then it will remove the digest from Statistics, Signatures and Referrers only
// if there are no tags pointing to the digest, otherwise it's noop.
func (rc *RedisDB) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoMetaNotFound) {
				return nil
			}

			return err
		}

		protoImageMeta, err := rc.getProtoImageMeta(ctx, manifestDigest.String())
		if err != nil {
			if errors.Is(err, zerr.ErrImageMetaNotFound) {
				return nil
			}

			return err
		}

		// Remove Referrers
		if subject := mConvert.GetImageSubject(protoImageMeta); subject != nil {
			referredDigest := subject.Digest.String()
			refInfo := &proto_go.ReferrersInfo{}

			if protoRepoMeta.Referrers[referredDigest] != nil {
				refInfo = protoRepoMeta.Referrers[referredDigest]
			}

			referrers := refInfo.List

			for i := range referrers {
				if referrers[i].Digest == manifestDigest.String() {
					referrers[i].Count -= 1

					if referrers[i].Count == 0 || common.ReferenceIsDigest(reference) {
						referrers = append(referrers[:i], referrers[i+1:]...)
					}

					break
				}
			}

			refInfo.List = referrers

			protoRepoMeta.Referrers[referredDigest] = refInfo
		}

		if !common.ReferenceIsDigest(reference) {
			delete(protoRepoMeta.Tags, reference)
		} else {
			// remove all tags pointing to this digest
			for tag, desc := range protoRepoMeta.Tags {
				if desc.Digest == reference {
					delete(protoRepoMeta.Tags, tag)
				}
			}
		}

		/* try to find at least one tag pointing to manifestDigest
		if not found then we can also remove everything related to this digest */
		var foundTag bool

		for _, desc := range protoRepoMeta.Tags {
			if desc.Digest == manifestDigest.String() {
				foundTag = true
			}
		}

		if !foundTag {
			delete(protoRepoMeta.Statistics, manifestDigest.String())
			delete(protoRepoMeta.Signatures, manifestDigest.String())
			delete(protoRepoMeta.Referrers, manifestDigest.String())
		}

		repoBlobsBytes, err := rc.Client.HGet(ctx, rc.RepoBlobsKey, repo).Bytes()
		if err != nil && !errors.Is(err, redis.Nil) {
			rc.Log.Error().Err(err).Str("hget", rc.RepoBlobsKey).Str("repo", repo).
				Msg("failed to get repo blobs record")

			return fmt.Errorf("failed to get repo blobs record for repo %s: %w", repo, err)
		}

		repoBlobs, err := unmarshalProtoRepoBlobs(repo, repoBlobsBytes)
		if err != nil {
			return err
		}

		protoRepoMeta, repoBlobs = common.RemoveImageFromRepoMeta(protoRepoMeta, repoBlobs, reference)
		protoTime := timestamppb.New(time.Now())

		protoTimeBlob, err := proto.Marshal(protoTime)
		if err != nil {
			return err
		}

		repoBlobsBytes, err = proto.Marshal(repoBlobs)
		if err != nil {
			return err
		}

		repoMetaBlob, err := proto.Marshal(protoRepoMeta)
		if err != nil {
			return err
		}

		_, err = rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
			if err := txrp.HSet(ctx, rc.RepoLastUpdatedKey, repo, protoTimeBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoLastUpdatedKey).Str("repo", repo).
					Msg("failed to put repo last updated timestamp")

				return fmt.Errorf("failed to put repo last updated record for repo %s: %w", repo, err)
			}

			if err := txrp.HSet(ctx, rc.RepoBlobsKey, repo, repoBlobsBytes).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoBlobsKey).Str("repo", repo).
					Msg("failed to put repo blobs record")

				return fmt.Errorf("failed to set repo blobs record for repo %s: %w", repo, err)
			}

			if err := txrp.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
				rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
					Msg("failed to put repo meta record")

				return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
			}

			return nil
		})

		return err
	})

	return err
}

// ResetRepoReferences resets layout specific data (tags, signatures, referrers, etc.) but keep user and image
// specific metadata such as star count, downloads other statistics.
// tagsToKeep is a set of tag names that should be preserved (tags that exist in storage).
// Tags not in tagsToKeep will be removed.
func (rc *RedisDB) ResetRepoReferences(repo string, tagsToKeep map[string]bool) error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getRepoLockKey(repo)}, func() error {
		protoRepoMeta, err := rc.getProtoRepoMeta(ctx, repo)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoMetaNotFound) {
				// Repo doesn't exist, nothing to reset
				return nil
			}

			return err
		}

		// Preserve tags that are in tagsToKeep, remove others
		preservedTags := make(map[string]*proto_go.TagDescriptor)
		if tagsToKeep != nil {
			for tag, descriptor := range protoRepoMeta.Tags {
				// Keep the tag if it's in tagsToKeep, or if it's the empty key (internal use)
				if tag == "" || tagsToKeep[tag] {
					preservedTags[tag] = descriptor
				}
			}
		}

		// Ensure empty key exists for internal use
		if _, exists := preservedTags[""]; !exists {
			preservedTags[""] = &proto_go.TagDescriptor{}
		}

		repoMetaBlob, err := proto.Marshal(&proto_go.RepoMeta{
			Name:       repo,
			Statistics: protoRepoMeta.Statistics,
			Stars:      protoRepoMeta.Stars,
			Tags:       preservedTags,
			Signatures: map[string]*proto_go.ManifestSignatures{"": {Map: map[string]*proto_go.SignaturesInfo{"": {}}}},
			Referrers:  map[string]*proto_go.ReferrersInfo{"": {}},
		})
		if err != nil {
			return err
		}

		if err := rc.Client.HSet(ctx, rc.RepoMetaKey, repo, repoMetaBlob).Err(); err != nil {
			rc.Log.Error().Err(err).Str("hset", rc.RepoMetaKey).Str("repo", repo).
				Msg("failed to put repo meta record")

			return fmt.Errorf("failed to put repometa record for repo %s: %w", repo, err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) GetRepoLastUpdated(repo string) time.Time {
	ctx := context.Background()

	lastUpdatedBlob, err := rc.Client.HGet(ctx, rc.RepoLastUpdatedKey, repo).Bytes()
	if err != nil {
		// redis.Nil is a normal condition when the key doesn't exist (new repo)
		if !errors.Is(err, redis.Nil) {
			rc.Log.Error().Err(err).Str("hget", rc.RepoLastUpdatedKey).Str("repo", repo).
				Msg("failed to get repo last updated timestamp")
		}

		return time.Time{}
	}

	if len(lastUpdatedBlob) == 0 {
		return time.Time{}
	}

	protoTime := &timestamppb.Timestamp{}

	err = proto.Unmarshal(lastUpdatedBlob, protoTime)
	if err != nil {
		return time.Time{}
	}

	lastUpdated := *mConvert.GetTime(protoTime)

	return lastUpdated
}

func (rc *RedisDB) GetAllRepoNames() ([]string, error) {
	foundRepos := []string{}
	ctx := context.Background()

	repoMetaEntries, err := rc.Client.HGetAll(ctx, rc.RepoMetaKey).Result()
	if err != nil {
		rc.Log.Error().Err(err).Str("hgetall", rc.RepoMetaKey).Msg("failed to get all repo meta records")

		return foundRepos, fmt.Errorf("failed to get all repometa records %w", err)
	}

	for repo := range repoMetaEntries {
		foundRepos = append(foundRepos, repo)
	}

	return foundRepos, nil
}

// ResetDB will delete all data in the DB.
// Ideally we would use locks here, but it would require a more complex logic to lock/unlock
// everything, and this function is only used in testing, so let's not add that complexity.
func (rc *RedisDB) ResetDB() error {
	ctx := context.Background()

	_, err := rc.Client.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		if err := txrp.Del(ctx, rc.RepoMetaKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.RepoMetaKey).Msg("failed to delete repo meta bucket")

			return fmt.Errorf("failed to delete repo meta bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.ImageMetaKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.ImageMetaKey).Msg("failed to delete image meta bucket")

			return fmt.Errorf("failed to delete image meta bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.RepoBlobsKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.RepoBlobsKey).Msg("failed to delete repo blobs bucket")

			return fmt.Errorf("failed to delete repo blobs bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.RepoLastUpdatedKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.RepoLastUpdatedKey).Msg("failed to delete repo last updated bucket")

			return fmt.Errorf("failed to delete repo last updated bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.UserDataKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.UserDataKey).Msg("failed to delete user data bucket")

			return fmt.Errorf("failed to delete user data bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.UserAPIKeysKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.UserAPIKeysKey).Msg("failed to delete user api key bucket")

			return fmt.Errorf("failed to delete user api key bucket: %w", err)
		}

		if err := txrp.Del(ctx, rc.VersionKey).Err(); err != nil {
			rc.Log.Error().Err(err).Str("del", rc.VersionKey).Msg("failed to delete version bucket")

			return fmt.Errorf("failed to delete version bucket: %w", err)
		}

		return nil
	})

	return err
}

func (rc *RedisDB) PatchDB() error {
	ctx := context.Background()

	err := rc.withRSLocks(ctx, []string{rc.getVersionLockKey()}, func() error {
		var DBVersion string

		DBVersion, err := rc.Client.Get(ctx, rc.VersionKey).Result()
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				rc.Log.Error().Err(err).Str("get", rc.VersionKey).Msg("failed to get db version")

				return fmt.Errorf("patching the database failed, can't read db version: %w", err)
			}

			// this is a new DB, we need to initialize the version
			if err := rc.Client.Set(ctx, rc.VersionKey, rc.Version, 0).Err(); err != nil {
				rc.Log.Error().Err(err).Str("set", rc.VersionKey).
					Str("value", version.CurrentVersion).Msg("failed to set db version")

				return fmt.Errorf("patching the database failed, can't set db version: %w", err)
			}

			// No need to apply patches on a new DB
			return nil
		}

		if version.GetVersionIndex(DBVersion) == -1 {
			return fmt.Errorf("%w: %s could not identify patches", zerr.ErrInvalidMetaDBVersion, DBVersion)
		}

		for patchIndex, patch := range rc.Patches {
			if patchIndex < version.GetVersionIndex(DBVersion) {
				continue
			}

			err := patch(rc.Client)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (rc *RedisDB) ImageTrustStore() mTypes.ImageTrustStore {
	return rc.imgTrustStore
}

func (rc *RedisDB) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	rc.imgTrustStore = imgTrustStore
}

// getUserBookmarksAndStarsNoError is used in several calls where we don't want
// to fail if the user data is unavailable, such as the case of getting all repos for
// anonymous users, or using metaDB internaly for CVE scanning repos.
func (rc *RedisDB) getUserBookmarksAndStarsNoError(ctx context.Context) ([]string, []string) {
	userData, err := rc.GetUserData(ctx)
	if err != nil {
		return []string{}, []string{}
	}

	return userData.BookmarkedRepos, userData.StarredRepos
}

func (rc *RedisDB) getProtoImageMeta(ctx context.Context, digest string) (*proto_go.ImageMeta, error) {
	imageMetaBlob, err := rc.Client.HGet(ctx, rc.ImageMetaKey, digest).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		rc.Log.Error().Err(err).Str("hget", rc.ImageMetaKey).Str("digest", digest).
			Msg("failed to get image meta record")

		return nil, fmt.Errorf("failed to get image meta record for digest %s: %w", digest, err)
	}

	if len(imageMetaBlob) == 0 || errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w for digest %s", zerr.ErrImageMetaNotFound, digest)
	}

	imageMeta := proto_go.ImageMeta{}

	err = proto.Unmarshal(imageMetaBlob, &imageMeta)
	if err != nil {
		return nil, err
	}

	return &imageMeta, nil
}

func (rc *RedisDB) getAllContainedMeta(ctx context.Context, imageIndexData *proto_go.ImageMeta,
) ([]*proto_go.ImageMeta, []*proto_go.ManifestMeta, error) {
	manifestDataList := make([]*proto_go.ManifestMeta, 0, len(imageIndexData.Index.Index.Manifests))
	imageMetaList := make([]*proto_go.ImageMeta, 0, len(imageIndexData.Index.Index.Manifests))

	for _, manifest := range imageIndexData.Index.Index.Manifests {
		if manifest.MediaType != ispec.MediaTypeImageManifest &&
			manifest.MediaType != ispec.MediaTypeImageIndex &&
			!compat.IsCompatibleManifestMediaType(manifest.MediaType) &&
			!compat.IsCompatibleManifestListMediaType(manifest.MediaType) {
			// filter out unexpected media types from the manifest lists,
			// this could be the case of buildkit cache entries for example
			continue
		}

		imageManifestData, err := rc.getProtoImageMeta(ctx, manifest.Digest)
		if err != nil {
			// Skip manifests that don't have MetaDB entries (missing from storage)
			if errors.Is(err, zerr.ErrImageMetaNotFound) {
				continue
			}

			return imageMetaList, manifestDataList, err
		}

		if imageManifestData.MediaType == ispec.MediaTypeImageManifest ||
			compat.IsCompatibleManifestMediaType(imageManifestData.MediaType) {
			imageMetaList = append(imageMetaList, imageManifestData)
			manifestDataList = append(manifestDataList, imageManifestData.Manifests[0])
		} else if imageManifestData.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(imageManifestData.MediaType) {
			partialImageDataList, partialManifestDataList, err := rc.getAllContainedMeta(ctx, imageManifestData)
			if err != nil {
				// getAllContainedMeta skips missing items internally, so any error returned
				// is a real error that should be propagated
				return imageMetaList, manifestDataList, err
			}

			imageMetaList = append(imageMetaList, partialImageDataList...)
			manifestDataList = append(manifestDataList, partialManifestDataList...)
		}
	}

	return imageMetaList, manifestDataList, nil
}

func (rc *RedisDB) getProtoRepoMeta(ctx context.Context, repo string) (*proto_go.RepoMeta, error) {
	repoMetaBlob, err := rc.Client.HGet(ctx, rc.RepoMetaKey, repo).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		rc.Log.Error().Err(err).Str("hget", rc.RepoMetaKey).Str("repo", repo).
			Msg("failed to get repo meta record")

		return nil, fmt.Errorf("failed to get repo meta record for repo %s: %w", repo, err)
	}

	return unmarshalProtoRepoMeta(repo, repoMetaBlob)
}

func (rc *RedisDB) withRSLocks(ctx context.Context, lockNames []string, wrappedFunc func() error) error {
	for _, lockName := range lockNames {
		lock := rc.RS.NewMutex(lockName)

		if err := lock.LockContext(ctx); err != nil {
			rc.Log.Error().Err(err).Str("lockName", lockName).Msg("failed to acquire redis lock")

			return err
		}

		defer func() {
			if _, err := lock.UnlockContext(ctx); err != nil {
				rc.Log.Error().Err(err).Str("lockName", lockName).Msg("failed to release redis lock")
			}
		}()
	}

	return wrappedFunc()
}

func (rc *RedisDB) getRepoLockKey(name string) string {
	return strings.Join([]string{rc.LocksKey, "Repo", name}, ":")
}

func (rc *RedisDB) getImageLockKey(name string) string {
	return strings.Join([]string{rc.LocksKey, "Image", name}, ":")
}

func (rc *RedisDB) getUserLockKey(name string) string {
	return strings.Join([]string{rc.LocksKey, "User", name}, ":")
}

func (rc *RedisDB) getVersionLockKey() string {
	return strings.Join([]string{rc.LocksKey, "Version"}, ":")
}

// unmarshalProtoRepoMeta will unmarshal the repoMeta blob and initialize nil maps. If the blob is empty
// an empty initialized object is returned.
func unmarshalProtoRepoMeta(repo string, repoMetaBlob []byte) (*proto_go.RepoMeta, error) {
	protoRepoMeta := &proto_go.RepoMeta{
		Name: repo,
	}

	if len(repoMetaBlob) > 0 {
		err := proto.Unmarshal(repoMetaBlob, protoRepoMeta)
		if err != nil {
			return protoRepoMeta, err
		}
	}

	if protoRepoMeta.Tags == nil {
		protoRepoMeta.Tags = map[string]*proto_go.TagDescriptor{"": {}}
	}

	if protoRepoMeta.Statistics == nil {
		protoRepoMeta.Statistics = map[string]*proto_go.DescriptorStatistics{"": {}}
	}

	if protoRepoMeta.Signatures == nil {
		protoRepoMeta.Signatures = map[string]*proto_go.ManifestSignatures{"": {}}
	}

	if protoRepoMeta.Referrers == nil {
		protoRepoMeta.Referrers = map[string]*proto_go.ReferrersInfo{"": {}}
	}

	if len(repoMetaBlob) == 0 {
		return protoRepoMeta, zerr.ErrRepoMetaNotFound
	}

	return protoRepoMeta, nil
}

// unmarshalProtoRepoBlobs will unmarshal the repoBlobs blob and initialize nil maps. If the blob is empty
// an empty initialized object is returned.
func unmarshalProtoRepoBlobs(repo string, repoBlobsBytes []byte) (*proto_go.RepoBlobs, error) {
	repoBlobs := &proto_go.RepoBlobs{
		Name: repo,
	}

	if len(repoBlobsBytes) > 0 {
		err := proto.Unmarshal(repoBlobsBytes, repoBlobs)
		if err != nil {
			return nil, err
		}
	}

	if repoBlobs.Blobs == nil {
		repoBlobs.Blobs = map[string]*proto_go.BlobInfo{"": {}}
	}

	return repoBlobs, nil
}

func join(xs ...string) string {
	return strings.Join(xs, ":")
}

func (rc *RedisDB) Close() error {
	err := rc.Client.Close()
	rc.Client = nil

	return err
}
