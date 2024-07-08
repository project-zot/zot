package redisdb

import (
	"context"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"

	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

type RedisDB struct {
	Client        *redis.Client
	imgTrustStore mTypes.ImageTrustStore
	Log           log.Logger
}

func New(client *redis.Client, log log.Logger) (*RedisDB, error) {
	redisWrapper := RedisDB{
		Client:        client,
		imgTrustStore: nil,
		Log:           log,
	}

	// Using the Config value, create the DynamoDB client
	return &redisWrapper, nil
}

func GetRedisClient(url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	return redis.NewClient(opts), nil
}

// GetStarredRepos returns starred repos and takes current user in consideration.
func (rc *RedisDB) GetStarredRepos(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

// GetBookmarkedRepos returns bookmarked repos and takes current user in consideration.
func (rc *RedisDB) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

// ToggleStarRepo adds/removes stars on repos.
func (rc *RedisDB) ToggleStarRepo(ctx context.Context, reponame string) (mTypes.ToggleState, error) {
	return 0, nil
}

// ToggleBookmarkRepo adds/removes bookmarks on repos.
func (rc *RedisDB) ToggleBookmarkRepo(ctx context.Context, reponame string) (mTypes.ToggleState, error) {
	return 0, nil
}

// UserDB profile/api key CRUD.
func (rc *RedisDB) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	return mTypes.UserData{}, nil
}

func (rc *RedisDB) SetUserData(ctx context.Context, userData mTypes.UserData) error {
	return nil
}

func (rc *RedisDB) SetUserGroups(ctx context.Context, groups []string) error {
	return nil
}

func (rc *RedisDB) GetUserGroups(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func (rc *RedisDB) DeleteUserData(ctx context.Context) error {
	return nil
}

func (rc *RedisDB) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	return "", nil
}

func (rc *RedisDB) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	return []mTypes.APIKeyDetails{}, nil
}

func (rc *RedisDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	return nil
}

func (rc *RedisDB) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	return false, nil
}

func (rc *RedisDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	return nil
}

func (rc *RedisDB) DeleteUserAPIKey(ctx context.Context, id string) error {
	return nil
}

func (rc *RedisDB) SetImageMeta(digest godigest.Digest, imageMeta mTypes.ImageMeta) error {
	return nil
}

// SetRepoReference sets the given image data to the repo metadata.
func (rc *RedisDB) SetRepoReference(ctx context.Context, repo string,
	reference string, imageMeta mTypes.ImageMeta,
) error {
	return nil
}

// SearchRepos searches for repos given a search string.
func (rc *RedisDB) SearchRepos(ctx context.Context, searchText string) ([]mTypes.RepoMeta, error) {
	return []mTypes.RepoMeta{}, nil
}

// SearchTags searches for images(repo:tag) given a search string.
func (rc *RedisDB) SearchTags(ctx context.Context, searchText string) ([]mTypes.FullImageMeta, error) {
	return []mTypes.FullImageMeta{}, nil
}

// FilterTags filters for images given a filter function.
func (rc *RedisDB) FilterTags(ctx context.Context, filterRepoTag mTypes.FilterRepoTagFunc,
	filterFunc mTypes.FilterFunc,
) ([]mTypes.FullImageMeta, error) {
	return []mTypes.FullImageMeta{}, nil
}

// FilterRepos filters for repos given a filter function.
func (rc *RedisDB) FilterRepos(ctx context.Context, rankName mTypes.FilterRepoNameFunc,
	filterFunc mTypes.FilterFullRepoFunc,
) ([]mTypes.RepoMeta, error) {
	return []mTypes.RepoMeta{}, nil
}

// GetRepoMeta returns the full information about a repo.
func (rc *RedisDB) GetRepoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	return mTypes.RepoMeta{}, nil
}

// GetFullImageMeta returns the full information about an image.
func (rc *RedisDB) GetFullImageMeta(ctx context.Context, repo string, tag string) (mTypes.FullImageMeta, error) {
	return mTypes.FullImageMeta{}, nil
}

// GetImageMeta returns the raw information about an image.
func (rc *RedisDB) GetImageMeta(digest godigest.Digest) (mTypes.ImageMeta, error) {
	return mTypes.ImageMeta{}, nil
}

// GetMultipleRepoMeta returns a list of all repos that match the given filter function.
func (rc *RedisDB) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMeta) bool) (
	[]mTypes.RepoMeta, error,
) {
	return []mTypes.RepoMeta{}, nil
}

// AddManifestSignature adds signature metadata to a given manifest in the database.
func (rc *RedisDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sm mTypes.SignatureMetadata,
) error {
	return nil
}

// DeleteSignature deletes signature metadata to a given manifest from the database.
func (rc *RedisDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	return nil
}

// UpdateSignaturesValidity checks and updates signatures validity of a given manifest.
func (rc *RedisDB) UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error {
	return nil
}

// IncrementRepoStars adds 1 to the star count of an image.
func (rc *RedisDB) IncrementRepoStars(repo string) error {
	return nil
}

// DecrementRepoStars subtracts 1 from the star count of an image.
func (rc *RedisDB) DecrementRepoStars(repo string) error {
	return nil
}

// SetRepoMeta returns RepoMetadata of a repo from the database.
func (rc *RedisDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMeta) error {
	return nil
}

// DeleteRepoMeta.
func (rc *RedisDB) DeleteRepoMeta(repo string) error {
	return nil
}

// GetReferrersInfo returns a list of  for all referrers of the given digest that match one of the
// artifact types.
func (rc *RedisDB) GetReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	return []mTypes.ReferrerInfo{}, nil
}

// UpdateStatsOnDownload adds 1 to the download count of an image and sets the timestamp of download.
func (rc *RedisDB) UpdateStatsOnDownload(repo string, reference string) error {
	return nil
}

// FilterImageMeta returns the image data for the given digests.
func (rc *RedisDB) FilterImageMeta(ctx context.Context,
	digests []string,
) (map[mTypes.ImageDigest]mTypes.ImageMeta, error) {
	return map[mTypes.ImageDigest]mTypes.ImageMeta{}, nil
}

/*
	RemoveRepoReference removes the tag from RepoMetadata if the reference is a tag,

it also removes its corresponding digest from Statistics, Signatures and Referrers if there are no tags
pointing to it.
If the reference is a digest then it will remove the digest from Statistics, Signatures and Referrers only
if there are no tags pointing to the digest, otherwise it's noop.
*/
func (rc *RedisDB) RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest) error {
	return nil
}

// ResetRepoReferences resets all layout specific data (tags, signatures, referrers, etc.) but keep user and image
// specific metadata such as star count, downloads other statistics.
func (rc *RedisDB) ResetRepoReferences(repo string) error {
	return nil
}

func (rc *RedisDB) GetRepoLastUpdated(repo string) time.Time {
	return time.Now()
}

func (rc *RedisDB) GetAllRepoNames() ([]string, error) {
	return []string{}, nil
}

// ResetDB will delete all data in the DB.
func (rc *RedisDB) ResetDB() error {
	return nil
}

func (rc *RedisDB) PatchDB() error {
	return nil
}

func (rc *RedisDB) ImageTrustStore() mTypes.ImageTrustStore {
	return rc.imgTrustStore
}

func (rc *RedisDB) SetImageTrustStore(imgTrustStore mTypes.ImageTrustStore) {
	rc.imgTrustStore = imgTrustStore
}
