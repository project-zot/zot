package boltdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.etcd.io/bbolt"
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

type BoltDB struct {
	DB            *bbolt.DB
	Patches       []func(DB *bbolt.DB) error
	imgTrustStore mTypes.ImageTrustStore
	Log           log.Logger
}

func New(boltDB *bbolt.DB, log log.Logger) (*BoltDB, error) {
	err := boltDB.Update(func(transaction *bbolt.Tx) error {
		versionBuck, err := transaction.CreateBucketIfNotExists([]byte(VersionBucket))
		if err != nil {
			return err
		}

		err = versionBuck.Put([]byte(version.DBVersionKey), []byte(version.CurrentVersion))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(UserDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(UserAPIKeysBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(ImageMetaBuck))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(RepoMetaBuck))
		if err != nil {
			return err
		}

		repoBlobsBuck, err := transaction.CreateBucketIfNotExists([]byte(RepoBlobsBuck))
		if err != nil {
			return err
		}

		_, err = repoBlobsBuck.CreateBucketIfNotExists([]byte(RepoLastUpdatedBuck))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltDB{
		DB:            boltDB,
		Patches:       version.GetBoltDBPatches(),
		imgTrustStore: nil,
		Log:           log,
	}, nil
}

func (bdw *BoltDB) GetAllRepoNames() ([]string, error) {
	repoNames := []string{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		return repoMetaBuck.ForEach(func(repo, _ []byte) error {
			repoNames = append(repoNames, string(repo))

			return nil
		})
	})

	return repoNames, err
}

func (bdw *BoltDB) GetRepoLastUpdated(repo string) time.Time {
	lastUpdated := time.Time{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		repoBlobsBuck := tx.Bucket([]byte(RepoBlobsBuck))

		lastUpdatedBuck := repoBlobsBuck.Bucket([]byte(RepoLastUpdatedBuck))

		lastUpdatedBlob := lastUpdatedBuck.Get([]byte(repo))
		if len(lastUpdatedBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoTime := &timestamppb.Timestamp{}

		err := proto.Unmarshal(lastUpdatedBlob, protoTime)
		if err != nil {
			return err
		}

		lastUpdated = *mConvert.GetTime(protoTime)

		return nil
	})
	if err != nil {
		return time.Time{}
	}

	return lastUpdated
}

func (bdw *BoltDB) SetImageMeta(digest godigest.Digest, imageMeta mTypes.ImageMeta) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(ImageMetaBuck))

		protoImageMeta := &proto_go.ImageMeta{}

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

		err = buck.Put([]byte(digest), pImageMetaBlob)
		if err != nil {
			return fmt.Errorf("failed to set manifest data with for digest %s %w", digest, err)
		}

		return nil
	})

	return err
}

func (bdw *BoltDB) SetRepoReference(ctx context.Context, repo string, reference string, imageMeta mTypes.ImageMeta,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, imageMeta.Digest); err != nil {
		return err
	}

	var userid string

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err == nil {
		userid = userAc.GetUsername()
	}

	err = bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoBuck := tx.Bucket([]byte(RepoMetaBuck))
		repoBlobsBuck := tx.Bucket([]byte(RepoBlobsBuck))
		repoLastUpdatedBuck := repoBlobsBuck.Bucket([]byte(RepoLastUpdatedBuck))
		imageBuck := tx.Bucket([]byte(ImageMetaBuck))

		// 1. Add image data to db if needed

		protoImageMeta := mConvert.GetProtoImageMeta(imageMeta)

		imageMetaBlob, err := proto.Marshal(protoImageMeta)
		if err != nil {
			return err
		}

		err = imageBuck.Put([]byte(imageMeta.Digest), imageMetaBlob)
		if err != nil {
			return err
		}

		protoRepoMeta, err := getProtoRepoMeta(repo, repoBuck)
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
		repoBlobsBytes := repoBlobsBuck.Get([]byte(repo))

		repoBlobs, err := unmarshalProtoRepoBlobs(repo, repoBlobsBytes)
		if err != nil {
			return err
		}

		protoRepoMeta, repoBlobs = common.AddImageMetaToRepoMeta(protoRepoMeta, repoBlobs, reference, imageMeta)

		err = setRepoLastUpdated(repo, time.Now(), repoLastUpdatedBuck)
		if err != nil {
			return err
		}

		err = setProtoRepoBlobs(repoBlobs, repoBlobsBuck)
		if err != nil {
			return err
		}

		return setProtoRepoMeta(protoRepoMeta, repoBuck)
	})

	return err
}

func setRepoLastUpdated(repo string, lastUpdated time.Time, repoLastUpdatedBuck *bbolt.Bucket) error {
	protoTime := timestamppb.New(lastUpdated)

	protoTimeBlob, err := proto.Marshal(protoTime)
	if err != nil {
		return err
	}

	return repoLastUpdatedBuck.Put([]byte(repo), protoTimeBlob)
}

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

func setProtoRepoBlobs(repoBlobs *proto_go.RepoBlobs, repoBlobsBuck *bbolt.Bucket) error {
	repoBlobsBytes, err := proto.Marshal(repoBlobs)
	if err != nil {
		return err
	}

	return repoBlobsBuck.Put([]byte(repoBlobs.Name), repoBlobsBytes)
}

func getProtoRepoMeta(repo string, repoMetaBuck *bbolt.Bucket) (*proto_go.RepoMeta, error) {
	repoMetaBlob := repoMetaBuck.Get([]byte(repo))

	return unmarshalProtoRepoMeta(repo, repoMetaBlob)
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

func setProtoRepoMeta(repoMeta *proto_go.RepoMeta, repoBuck *bbolt.Bucket) error {
	repoMetaBlob, err := proto.Marshal(repoMeta)
	if err != nil {
		return err
	}

	return repoBuck.Put([]byte(repoMeta.Name), repoMetaBlob)
}

func (bdw *BoltDB) FilterImageMeta(ctx context.Context, digests []string,
) (map[string]mTypes.ImageMeta, error) {
	imageMetaMap := map[string]mTypes.ImageMeta{}

	err := bdw.DB.View(func(transaction *bbolt.Tx) error {
		imageBuck := transaction.Bucket([]byte(ImageMetaBuck))

		for _, digest := range digests {
			protoImageMeta, err := getProtoImageMeta(imageBuck, digest)
			if err != nil {
				return err
			}

			if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
				compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
				_, manifestDataList, err := getAllContainedMeta(imageBuck, protoImageMeta)
				if err != nil {
					return err
				}

				protoImageMeta.Manifests = manifestDataList
			}

			imageMetaMap[digest] = mConvert.GetImageMeta(protoImageMeta)
		}

		return nil
	})

	return imageMetaMap, err
}

func (bdw *BoltDB) SearchRepos(ctx context.Context, searchText string,
) ([]mTypes.RepoMeta, error) {
	repos := []mTypes.RepoMeta{}

	err := bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetaBuck))
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := reqCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			rank := common.RankRepoName(searchText, string(repoName))
			if rank == -1 {
				continue
			}

			protoRepoMeta, err := unmarshalProtoRepoMeta(string(repoName), repoMetaBlob)
			if err != nil {
				return err
			}

			delete(protoRepoMeta.Tags, "")

			if len(protoRepoMeta.Tags) == 0 {
				continue
			}

			protoRepoMeta.Rank = int32(rank) //nolint:gosec // ignore overflow
			protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)
			protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)

			repos = append(repos, mConvert.GetRepoMeta(protoRepoMeta))
		}

		return nil
	})

	return repos, err
}

func getProtoImageMeta(imageBuck *bbolt.Bucket, digest string) (*proto_go.ImageMeta, error) {
	imageMetaBlob := imageBuck.Get([]byte(digest))

	if len(imageMetaBlob) == 0 {
		return nil, fmt.Errorf("%w for digest %s", zerr.ErrImageMetaNotFound, digest)
	}

	imageMeta := proto_go.ImageMeta{}

	err := proto.Unmarshal(imageMetaBlob, &imageMeta)
	if err != nil {
		return nil, err
	}

	return &imageMeta, nil
}

func getAllContainedMeta(imageBuck *bbolt.Bucket, imageIndexData *proto_go.ImageMeta,
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

		imageManifestData, err := getProtoImageMeta(imageBuck, manifest.Digest)
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
			partialImageDataList, partialManifestDataList, err := getAllContainedMeta(imageBuck, imageManifestData)
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

func (bdw *BoltDB) SearchTags(ctx context.Context, searchText string,
) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []mTypes.FullImageMeta{},
			fmt.Errorf("failed to parse search text, invalid format %w", err)
	}

	err = bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetaBuck))
			imageBuck     = transaction.Bucket([]byte(ImageMetaBuck))
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		repoName, repoMetaBlob := repoBuck.Cursor().Seek([]byte(searchedRepo))

		if string(repoName) != searchedRepo {
			return nil
		}

		if ok, err := reqCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
			return err
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(string(repoName), repoMetaBlob)
		if err != nil {
			return err
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

				imageManifestData, err := getProtoImageMeta(imageBuck, manifestDigest)
				if err != nil {
					return fmt.Errorf("failed to fetch manifest meta for manifest with digest %s %w",
						manifestDigest, err)
				}

				protoImageMeta = imageManifestData
			} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
				compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
				indexDigest := descriptor.Digest

				imageIndexData, err := getProtoImageMeta(imageBuck, indexDigest)
				if err != nil {
					return fmt.Errorf("failed to fetch manifest meta for manifest with digest %s %w",
						indexDigest, err)
				}

				_, manifestDataList, err := getAllContainedMeta(imageBuck, imageIndexData)
				if err != nil {
					return err
				}

				imageIndexData.Manifests = manifestDataList

				protoImageMeta = imageIndexData
			} else {
				bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

				continue
			}

			images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta))
		}

		return nil
	})

	return images, err
}

func (bdw *BoltDB) FilterTags(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
	filterFunc mTypes.FilterFunc,
) ([]mTypes.FullImageMeta, error) {
	images := []mTypes.FullImageMeta{}

	err := bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetaBuck))
			imageMetaBuck = transaction.Bucket([]byte(ImageMetaBuck))
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
			viewError     error
		)

		cursor := repoBuck.Cursor()
		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := reqCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			protoRepoMeta, err := unmarshalProtoRepoMeta(string(repoName), repoMetaBlob)
			if err != nil {
				viewError = errors.Join(viewError, err)

				continue
			}

			delete(protoRepoMeta.Tags, "")
			protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, protoRepoMeta.Name)
			protoRepoMeta.IsStarred = slices.Contains(userStars, protoRepoMeta.Name)
			repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

			for tag, descriptor := range protoRepoMeta.Tags {
				if !filterRepoTag(string(repoName), tag) {
					continue
				}

				if descriptor.MediaType == ispec.MediaTypeImageManifest || //nolint:gocritic
					compat.IsCompatibleManifestMediaType(descriptor.MediaType) {
					manifestDigest := descriptor.Digest

					imageManifestData, err := getProtoImageMeta(imageMetaBuck, manifestDigest)
					if err != nil {
						viewError = errors.Join(viewError, err)

						continue
					}

					imageMeta := mConvert.GetImageMeta(imageManifestData)

					if filterFunc(repoMeta, imageMeta) {
						images = append(images, mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, imageManifestData))
					}
				} else if descriptor.MediaType == ispec.MediaTypeImageIndex ||
					compat.IsCompatibleManifestListMediaType(descriptor.MediaType) {
					indexDigest := descriptor.Digest

					protoImageIndexMeta, err := getProtoImageMeta(imageMetaBuck, indexDigest)
					if err != nil {
						viewError = errors.Join(viewError, err)

						continue
					}

					imageIndexMeta := mConvert.GetImageMeta(protoImageIndexMeta)
					matchedManifests := []*proto_go.ManifestMeta{}

					imageManifestDataList, _, err := getAllContainedMeta(imageMetaBuck, protoImageIndexMeta)
					if err != nil {
						viewError = errors.Join(viewError, err)

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
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("unsupported media type")

					continue
				}
			}
		}

		return viewError
	})

	return images, err
}

func (bdw *BoltDB) FilterRepos(ctx context.Context, acceptName mTypes.FilterRepoNameFunc,
	filter mTypes.FilterFullRepoFunc,
) ([]mTypes.RepoMeta, error) {
	repos := []mTypes.RepoMeta{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		var (
			buck          = tx.Bucket([]byte(RepoMetaBuck))
			cursor        = buck.Cursor()
			userBookmarks = getUserBookmarks(ctx, tx)
			userStars     = getUserStars(ctx, tx)
		)

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := reqCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			if !acceptName(string(repoName)) {
				continue
			}

			repoMeta, err := unmarshalProtoRepoMeta(string(repoName), repoMetaBlob)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = slices.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = slices.Contains(userStars, repoMeta.Name)

			fullRepoMeta := mConvert.GetRepoMeta(repoMeta)

			if filter(fullRepoMeta) {
				repos = append(repos, fullRepoMeta)
			}
		}

		return nil
	})
	if err != nil {
		return []mTypes.RepoMeta{}, err
	}

	return repos, err
}

func (bdw *BoltDB) GetRepoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	var protoRepoMeta *proto_go.RepoMeta

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))
		userBookmarks := getUserBookmarks(ctx, tx)
		userStars := getUserStars(ctx, tx)

		repoMetaBlob := buck.Get([]byte(repo))

		var err error

		protoRepoMeta, err = unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
		}

		delete(protoRepoMeta.Tags, "")
		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, repo)
		protoRepoMeta.IsStarred = slices.Contains(userStars, repo)

		return nil
	})

	return mConvert.GetRepoMeta(protoRepoMeta), err
}

func (bdw *BoltDB) GetFullImageMeta(ctx context.Context, repo string, tag string) (mTypes.FullImageMeta, error) {
	protoRepoMeta := &proto_go.RepoMeta{}
	protoImageMeta := &proto_go.ImageMeta{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))
		imageBuck := tx.Bucket([]byte(ImageMetaBuck))
		userBookmarks := getUserBookmarks(ctx, tx)
		userStars := getUserStars(ctx, tx)

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var err error

		protoRepoMeta, err = unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
		}

		delete(protoRepoMeta.Tags, "")
		protoRepoMeta.IsBookmarked = slices.Contains(userBookmarks, repo)
		protoRepoMeta.IsStarred = slices.Contains(userStars, repo)

		descriptor, ok := protoRepoMeta.Tags[tag]
		if !ok {
			return zerr.ErrImageMetaNotFound
		}

		protoImageMeta, err = getProtoImageMeta(imageBuck, descriptor.Digest)
		if err != nil {
			return err
		}

		if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
			_, manifestDataList, err := getAllContainedMeta(imageBuck, protoImageMeta)
			if err != nil {
				return err
			}

			protoImageMeta.Manifests = manifestDataList
		}

		return nil
	})

	return mConvert.GetFullImageMetaFromProto(tag, protoRepoMeta, protoImageMeta), err
}

func (bdw *BoltDB) GetImageMeta(digest godigest.Digest) (mTypes.ImageMeta, error) {
	imageMeta := mTypes.ImageMeta{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		imageBuck := tx.Bucket([]byte(ImageMetaBuck))

		protoImageMeta, err := getProtoImageMeta(imageBuck, digest.String())
		if err != nil {
			return err
		}

		if protoImageMeta.MediaType == ispec.MediaTypeImageIndex ||
			compat.IsCompatibleManifestListMediaType(protoImageMeta.MediaType) {
			_, manifestDataList, err := getAllContainedMeta(imageBuck, protoImageMeta)
			if err != nil {
				return err
			}

			protoImageMeta.Manifests = manifestDataList
		}

		imageMeta = mConvert.GetImageMeta(protoImageMeta)

		return nil
	})

	return imageMeta, err
}

func (bdw *BoltDB) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool,
) ([]mTypes.RepoMeta, error) {
	foundRepos := []mTypes.RepoMeta{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := reqCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			protoRepoMeta, err := unmarshalProtoRepoMeta(string(repoName), repoMetaBlob)
			if err != nil {
				return err
			}

			delete(protoRepoMeta.Tags, "")

			repoMeta := mConvert.GetRepoMeta(protoRepoMeta)

			if filter(repoMeta) {
				foundRepos = append(foundRepos, repoMeta)
			}
		}

		return nil
	})

	return foundRepos, err
}

func (bdw *BoltDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoMetaBuck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
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

			repoMetaBlob, err = proto.Marshal(&repoMeta)
			if err != nil {
				return err
			}

			return repoMetaBuck.Put([]byte(repo), repoMetaBlob)
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
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

				if zcommon.IsCosignSignature(sigMeta.SignatureTag) {
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

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoMetaBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrImageMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
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

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) IncrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoMetaBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
		}

		protoRepoMeta.Stars++

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) DecrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoMetaBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
		}

		if protoRepoMeta.Stars == 0 {
			return nil
		}

		protoRepoMeta.Stars--

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMeta) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))
		repoLastUpdatedBuck := tx.Bucket([]byte(RepoBlobsBuck)).Bucket([]byte(RepoLastUpdatedBuck))

		repoMeta.Name = repo

		repoMetaBlob, err := proto.Marshal(mConvert.GetProtoRepoMeta(repoMeta))
		if err != nil {
			return err
		}

		err = buck.Put([]byte(repo), repoMetaBlob)
		if err != nil {
			return err
		}

		// The last update time is set to 0 in order to force an update in case of a next storage parsing
		return setRepoLastUpdated(repo, time.Time{}, repoLastUpdatedBuck)
	})

	return err
}

func (bdw *BoltDB) DeleteRepoMeta(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoBuck := tx.Bucket([]byte(RepoMetaBuck))
		repoBlobsBuck := tx.Bucket([]byte(RepoBlobsBuck))
		repoLastUpdatedBuck := repoBlobsBuck.Bucket([]byte(RepoLastUpdatedBuck))

		err := repoBuck.Delete([]byte(repo))
		if err != nil {
			return err
		}

		err = repoBlobsBuck.Delete([]byte(repo))
		if err != nil {
			return err
		}

		return repoLastUpdatedBuck.Delete([]byte(repo))
	})

	return err
}

func (bdw *BoltDB) ResetRepoReferences(repo string, tagsToKeep map[string]bool) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := buck.Get([]byte(repo))

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
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

		repoMetaBlob, err = proto.Marshal(&proto_go.RepoMeta{
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

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	referrersInfoResult := []mTypes.ReferrerInfo{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := buck.Get([]byte(repo))

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
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

		return nil
	})

	return referrersInfoResult, err
}

func (bdw *BoltDB) UpdateStatsOnDownload(repo string, reference string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoMetaBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
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

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error {
	err := bdw.DB.Update(func(transaction *bbolt.Tx) error {
		imgTrustStore := bdw.ImageTrustStore()

		if imgTrustStore == nil {
			return nil
		}

		// get ManifestData of signed manifest
		imageMetaBuck := transaction.Bucket([]byte(ImageMetaBuck))
		idBlob := imageMetaBuck.Get([]byte(manifestDigest))

		if len(idBlob) == 0 {
			// manifest meta not found, updating signatures with details about validity and author will not be performed
			return nil
		}

		protoImageMeta := proto_go.ImageMeta{}

		err := proto.Unmarshal(idBlob, &protoImageMeta)
		if err != nil {
			return err
		}

		// update signatures with details about validity and author
		repoBuck := transaction.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
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
						layerInfo.SignatureKey, manifestDigest, mConvert.GetImageMeta(&protoImageMeta), repo)

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

		return setProtoRepoMeta(protoRepoMeta, repoBuck)
	})

	return err
}

func (bdw *BoltDB) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		repoMetaBuck := tx.Bucket([]byte(RepoMetaBuck))
		imageMetaBuck := tx.Bucket([]byte(ImageMetaBuck))
		repoBlobsBuck := tx.Bucket([]byte(RepoBlobsBuck))
		repoLastUpdatedBuck := repoBlobsBuck.Bucket([]byte(RepoLastUpdatedBuck))

		protoRepoMeta, err := getProtoRepoMeta(repo, repoMetaBuck)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoMetaNotFound) {
				return nil
			}

			return err
		}

		protoImageMeta, err := getProtoImageMeta(imageMetaBuck, manifestDigest.String())
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

		repoBlobsBytes := repoBlobsBuck.Get([]byte(protoRepoMeta.Name))

		repoBlobs, err := unmarshalProtoRepoBlobs(repo, repoBlobsBytes)
		if err != nil {
			return err
		}

		err = setRepoLastUpdated(repo, time.Now(), repoLastUpdatedBuck)
		if err != nil {
			return err
		}

		protoRepoMeta, repoBlobs = common.RemoveImageFromRepoMeta(protoRepoMeta, repoBlobs, reference)

		repoBlobsBytes, err = proto.Marshal(repoBlobs)
		if err != nil {
			return err
		}

		err = repoBlobsBuck.Put([]byte(protoRepoMeta.Name), repoBlobsBytes)
		if err != nil {
			return err
		}

		return setProtoRepoMeta(protoRepoMeta, repoMetaBuck)
	})

	return err
}

func (bdw *BoltDB) ImageTrustStore() mTypes.ImageTrustStore {
	return bdw.imgTrustStore
}

func (bdw *BoltDB) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	bdw.imgTrustStore = imgTrustStore
}

func (bdw *BoltDB) ToggleStarRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var res mTypes.ToggleState

	if err := bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
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

		err = bdw.setUserData(userid, tx, userData)
		if err != nil {
			return err
		}

		repoBuck := tx.Bucket([]byte(RepoMetaBuck))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		protoRepoMeta, err := unmarshalProtoRepoMeta(repo, repoMetaBlob)
		if err != nil {
			return err
		}

		switch res {
		case mTypes.Added:
			protoRepoMeta.Stars++
		case mTypes.Removed:
			protoRepoMeta.Stars--
		}

		return setProtoRepoMeta(protoRepoMeta, repoBuck)
	}); err != nil {
		return mTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *BoltDB) GetStarredRepos(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.StarredRepos, err
}

func (bdw *BoltDB) ToggleBookmarkRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	if userAc.IsAnonymous() || !userAc.Can(constants.ReadPermission, repo) {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var res mTypes.ToggleState

	if err := bdw.DB.Update(func(transaction *bbolt.Tx) error { //nolint:dupl
		var userData mTypes.UserData

		err := bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
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

		return bdw.setUserData(userid, transaction, userData)
	}); err != nil {
		return mTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *BoltDB) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.BookmarkedRepos, err
}

func (bdw *BoltDB) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		versionBuck := tx.Bucket([]byte(VersionBucket))
		DBVersion = string(versionBuck.Get([]byte(version.DBVersionKey)))

		return nil
	})
	if err != nil {
		return fmt.Errorf("patching the database failed, can't read db version %w", err)
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return fmt.Errorf("%w: %s could not identify patches", zerr.ErrInvalidMetaDBVersion, DBVersion)
	}

	for patchIndex, patch := range bdw.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		err := patch(bdw.DB)
		if err != nil {
			return err
		}
	}

	return nil
}

func getUserStars(ctx context.Context, transaction *bbolt.Tx) []string {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return []string{}
	}

	var (
		userData mTypes.UserData
		userid   = userAc.GetUsername()
		userdb   = transaction.Bucket([]byte(UserDataBucket))
	)

	if userid == "" || userdb == nil {
		return []string{}
	}

	mdata := userdb.Get([]byte(userid))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &userData); err != nil {
		return []string{}
	}

	return userData.StarredRepos
}

func getUserBookmarks(ctx context.Context, transaction *bbolt.Tx) []string {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return []string{}
	}

	var (
		userData mTypes.UserData
		userid   = userAc.GetUsername()
		userdb   = transaction.Bucket([]byte(UserDataBucket))
	)

	if userid == "" || userdb == nil {
		return []string{}
	}

	mdata := userdb.Get([]byte(userid))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &userData); err != nil {
		return []string{}
	}

	return userData.BookmarkedRepos
}

func (bdw *BoltDB) SetUserGroups(ctx context.Context, groups []string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		userData.Groups = groups

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) GetUserGroups(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)

	return userData.Groups, err
}

func (bdw *BoltDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil {
			return err
		}

		apiKeyDetails := userData.APIKeys[hashedKey]
		apiKeyDetails.LastUsed = time.Now()

		userData.APIKeys[hashedKey] = apiKeyDetails

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return false, err
	}

	if userAc.IsAnonymous() {
		return false, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	var isExpired bool

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil {
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

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return isExpired, err
}

func (bdw *BoltDB) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	apiKeys := make([]mTypes.APIKeyDetails, 0)

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if userAc.IsAnonymous() {
		return nil, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		err = bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		for hashedKey, apiKeyDetails := range userData.APIKeys {
			// if expiresAt is not nil value
			if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
				apiKeyDetails.IsExpired = true
			}

			userData.APIKeys[hashedKey] = apiKeyDetails

			err = bdw.setUserData(userid, transaction, userData)
			if err != nil {
				return err
			}

			apiKeys = append(apiKeys, apiKeyDetails)
		}

		return nil
	})

	return apiKeys, err
}

func (bdw *BoltDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		apiKeysbuck := transaction.Bucket([]byte(UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := apiKeysbuck.Put([]byte(hashedKey), []byte(userid))
		if err != nil {
			return fmt.Errorf("failed to set userData for identity %s %w", userid, err)
		}

		err = bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		if userData.APIKeys == nil {
			userData.APIKeys = make(map[string]mTypes.APIKeyDetails)
		}

		userData.APIKeys[hashedKey] = *apiKeyDetails

		err = bdw.setUserData(userid, transaction, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) DeleteUserAPIKey(ctx context.Context, keyID string) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		apiKeysbuck := transaction.Bucket([]byte(UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := bdw.getUserData(userid, transaction, &userData)
		if err != nil {
			return err
		}

		for hash, apiKeyDetails := range userData.APIKeys {
			if apiKeyDetails.UUID == keyID {
				delete(userData.APIKeys, hash)

				err := apiKeysbuck.Delete([]byte(hash))
				if err != nil {
					return fmt.Errorf("failed to delete userAPIKey entry for hash %s %w", hash, err)
				}
			}
		}

		return bdw.setUserData(userid, transaction, userData)
	})

	return err
}

func (bdw *BoltDB) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	var userid string

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(UserAPIKeysBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		uiBlob := buck.Get([]byte(hashedKey))
		if len(uiBlob) == 0 {
			return zerr.ErrUserAPIKeyNotFound
		}

		userid = string(uiBlob)

		return nil
	})

	return userid, err
}

func (bdw *BoltDB) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	var userData mTypes.UserData

	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return userData, err
	}

	if userAc.IsAnonymous() {
		return userData, zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.View(func(tx *bbolt.Tx) error {
		return bdw.getUserData(userid, tx, &userData)
	})

	return userData, err
}

func (bdw *BoltDB) getUserData(userid string, transaction *bbolt.Tx, res *mTypes.UserData) error {
	buck := transaction.Bucket([]byte(UserDataBucket))
	if buck == nil {
		return zerr.ErrBucketDoesNotExist
	}

	upBlob := buck.Get([]byte(userid))

	if len(upBlob) == 0 {
		return zerr.ErrUserDataNotFound
	}

	err := json.Unmarshal(upBlob, res)
	if err != nil {
		return err
	}

	return nil
}

func (bdw *BoltDB) SetUserData(ctx context.Context, userData mTypes.UserData) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(tx *bbolt.Tx) error {
		return bdw.setUserData(userid, tx, userData)
	})

	return err
}

func (bdw *BoltDB) setUserData(userid string, transaction *bbolt.Tx, userData mTypes.UserData) error {
	buck := transaction.Bucket([]byte(UserDataBucket))
	if buck == nil {
		return zerr.ErrBucketDoesNotExist
	}

	upBlob, err := json.Marshal(userData)
	if err != nil {
		return err
	}

	err = buck.Put([]byte(userid), upBlob)
	if err != nil {
		return fmt.Errorf("failed to set userData for identity %s %w", userid, err)
	}

	return nil
}

func (bdw *BoltDB) DeleteUserData(ctx context.Context) error {
	userAc, err := reqCtx.UserAcFromContext(ctx)
	if err != nil {
		return err
	}

	if userAc.IsAnonymous() {
		return zerr.ErrUserDataNotAllowed
	}

	userid := userAc.GetUsername()

	err = bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(UserDataBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := buck.Delete([]byte(userid))
		if err != nil {
			return fmt.Errorf("failed to delete userData for identity %s %w", userid, err)
		}

		return nil
	})

	return err
}

func (bdw *BoltDB) ResetDB() error {
	err := bdw.DB.Update(func(transaction *bbolt.Tx) error {
		err := resetBucket(transaction, RepoMetaBuck)
		if err != nil {
			return err
		}

		err = resetBucket(transaction, ImageMetaBuck)
		if err != nil {
			return err
		}

		err = resetBucket(transaction, RepoBlobsBuck)
		if err != nil {
			return err
		}

		err = resetBucket(transaction, UserAPIKeysBucket)
		if err != nil {
			return err
		}

		err = resetBucket(transaction, UserDataBucket)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func resetBucket(transaction *bbolt.Tx, bucketName string) error {
	bucket := transaction.Bucket([]byte(bucketName))
	if bucket == nil {
		return nil
	}

	// we need to create the sub buckets if they exits, we'll presume the sub-buckets are not nested more than 1 layer
	subBuckets := [][]byte{}

	err := bucket.ForEachBucket(func(bucketName []byte) error {
		subBuckets = append(subBuckets, bucketName)

		return nil
	})
	if err != nil {
		return err
	}

	err = transaction.DeleteBucket([]byte(bucketName))
	if err != nil {
		return err
	}

	bucket, err = transaction.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}

	for _, subBucket := range subBuckets {
		_, err := bucket.CreateBucketIfNotExists(subBucket)
		if err != nil {
			return err
		}
	}

	return err
}

func (bdw *BoltDB) Close() error {
	err := bdw.DB.Close()
	bdw.DB = nil

	return err
}
