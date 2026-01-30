package types

import (
	"context"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ToggleState is used to model changes to an object after a call to the DB.
type ToggleState int

const (
	NotChanged ToggleState = iota
	Added
	Removed
)

type (
	// FilterFunc is a filter function.
	// Currently imageMeta applied for indexes is applied for each manifest individually so imageMeta.manifests
	// contains just 1 manifest.
	FilterFunc         func(repoMeta RepoMeta, imageMeta ImageMeta) bool
	FilterRepoNameFunc func(repo string) bool
	FilterFullRepoFunc func(repoMeta RepoMeta) bool
	FilterRepoTagFunc  func(repo, tag string) bool
)

func AcceptAllRepoNames(repo string) bool {
	return true
}

func AcceptAllRepoMeta(repoMeta RepoMeta) bool {
	return true
}

func AcceptAllRepoTag(repo, tag string) bool {
	return true
}

func AcceptOnlyRepo(repo string) func(repo, tag string) bool {
	return func(r, t string) bool { return repo == r }
}

func AcceptAllImageMeta(repoMeta RepoMeta, imageMeta ImageMeta) bool {
	return true
}

func GetLatestImageDigests(repoMetaList []RepoMeta) []string {
	digests := make([]string, 0, len(repoMetaList))

	for i := range repoMetaList {
		if repoMetaList[i].LastUpdatedImage != nil {
			digests = append(digests, repoMetaList[i].LastUpdatedImage.Digest)
		}
	}

	return digests
}

type MetaDB interface { //nolint:interfacebloat
	UserDB

	// SetImageMeta sets ImageMeta for a given image in the database
	// should NEVER be used in production as both GetImageMeta and SetImageMeta
	// should be locked for the duration of the entire transaction at a higher level in the app
	SetImageMeta(digest godigest.Digest, imageMeta ImageMeta) error

	// SetRepoReference sets the given image data to the repo metadata.
	SetRepoReference(ctx context.Context, repo string, reference string, imageMeta ImageMeta) error

	// SearchRepos searches for repos given a search string
	SearchRepos(ctx context.Context, searchText string) ([]RepoMeta, error)

	// SearchTags searches for images(repo:tag) given a search string
	SearchTags(ctx context.Context, searchText string) ([]FullImageMeta, error)

	// FilterTags filters for images given a filter function
	FilterTags(ctx context.Context, filterRepoTag FilterRepoTagFunc, filterFunc FilterFunc,
	) ([]FullImageMeta, error)

	// FilterRepos filters for repos given a filter function
	FilterRepos(ctx context.Context, rankName FilterRepoNameFunc, filterFunc FilterFullRepoFunc,
	) ([]RepoMeta, error)

	// GetRepoMeta returns the full information about a repo
	GetRepoMeta(ctx context.Context, repo string) (RepoMeta, error)

	// GetFullImageMeta returns the full information about an image
	GetFullImageMeta(ctx context.Context, repo string, tag string) (FullImageMeta, error)

	// GetImageMeta returns the raw information about an image
	GetImageMeta(digest godigest.Digest) (ImageMeta, error)

	// GetMultipleRepoMeta returns a list of all repos that match the given filter.
	// function
	GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMeta) bool) (
		[]RepoMeta, error)

	// AddManifestSignature adds signature metadata to a given manifest in the database
	AddManifestSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// DeleteSignature deletes signature metadata to a given manifest from the database
	DeleteSignature(repo string, signedManifestDigest godigest.Digest, sigMeta SignatureMetadata) error

	// UpdateSignaturesValidity checks and updates signatures validity of a given manifest
	UpdateSignaturesValidity(ctx context.Context, repo string, manifestDigest godigest.Digest) error

	// IncrementRepoStars adds 1 to the star count of an image
	IncrementRepoStars(repo string) error

	// DecrementRepoStars subtracts 1 from the star count of an image
	DecrementRepoStars(repo string) error

	// SetRepoMeta sets RepoMetadata for a given repo in the database
	// should NEVER be used in production as both GetRepoMeta and SetRepoMeta
	// should be locked for the duration of the entire transaction at a higher level in the app
	SetRepoMeta(repo string, repoMeta RepoMeta) error

	// DeleteRepoMeta
	DeleteRepoMeta(repo string) error

	// GetReferrersInfo returns a list of  for all referrers of the given digest that match one of the
	// artifact types.
	GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string) ([]ReferrerInfo, error)

	// UpdateStatsOnDownload adds 1 to the download count of an image and sets the timestamp of download
	UpdateStatsOnDownload(repo string, reference string) error

	// FilterImageMeta returns the image data for the given digests
	FilterImageMeta(ctx context.Context, digests []string) (map[ImageDigest]ImageMeta, error)

	/*
	   	RemoveRepoReference removes the tag from RepoMetadata if the reference is a tag,

	   it also removes its corresponding digest from Statistics, Signatures and Referrers if there are no tags
	   pointing to it.
	   If the reference is a digest then it will remove the digest from Statistics, Signatures and Referrers only
	   if there are no tags pointing to the digest, otherwise it's noop
	*/
	RemoveRepoReference(repo, reference string, manifestDigest godigest.Digest) error

	// ResetRepoReferences resets layout specific data (tags, signatures, referrers, etc.) but keep user and image
	// specific metadata such as star count, downloads other statistics.
	// tagsToKeep is a set of tag names that should be preserved (tags that exist in storage).
	// Tags not in tagsToKeep will be removed.
	ResetRepoReferences(repo string, tagsToKeep map[string]bool) error

	GetRepoLastUpdated(repo string) time.Time

	GetAllRepoNames() ([]string, error)

	// ResetDB will delete all data in the DB
	ResetDB() error

	PatchDB() error

	ImageTrustStore() ImageTrustStore

	SetImageTrustStore(imgTrustStore ImageTrustStore)

	// Close will close the db
	Close() error
}

type UserDB interface { //nolint:interfacebloat
	// GetStarredRepos returns starred repos and takes current user in consideration
	GetStarredRepos(ctx context.Context) ([]string, error)

	// GetBookmarkedRepos returns bookmarked repos and takes current user in consideration
	GetBookmarkedRepos(ctx context.Context) ([]string, error)

	// ToggleStarRepo adds/removes stars on repos
	ToggleStarRepo(ctx context.Context, reponame string) (ToggleState, error)

	// ToggleBookmarkRepo adds/removes bookmarks on repos
	ToggleBookmarkRepo(ctx context.Context, reponame string) (ToggleState, error)

	// UserDB profile/api key CRUD
	GetUserData(ctx context.Context) (UserData, error)

	// SetUserData sets UserData for a given user in the database
	// SetUserData should NEVER be used in production as both GetUserData and SetUserData
	// should be locked for the duration of the entire transaction at a higher level in the app
	SetUserData(ctx context.Context, userData UserData) error

	SetUserGroups(ctx context.Context, groups []string) error

	GetUserGroups(ctx context.Context) ([]string, error)

	DeleteUserData(ctx context.Context) error

	GetUserAPIKeyInfo(hashedKey string) (identity string, err error)

	GetUserAPIKeys(ctx context.Context) ([]APIKeyDetails, error)

	AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *APIKeyDetails) error

	IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error)

	UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error

	DeleteUserAPIKey(ctx context.Context, id string) error
}

type (
	Author     = string
	ExpiryDate = time.Time
	Validity   = bool
)

type ImageTrustStore interface {
	VerifySignature(
		signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, imageMeta ImageMeta,
		repo string,
	) (Author, ExpiryDate, Validity, error)
}

// ImageMeta can store all data related to a image, multiarch or simple. Used for writing imaged to MetaDB.
type ImageMeta struct {
	MediaType string          // MediaType refers to the image descriptor, a manifest or a index (if multiarch)
	Digest    godigest.Digest // Digest refers to the image descriptor, a manifest or a index (if multiarch)
	Size      int64           // Size refers to the image descriptor, a manifest or a index (if multiarch)
	Index     *ispec.Index    // If the image is multiarch the Index will be non-nil
	Manifests []ManifestMeta  // All manifests under the image, 1 for simple images and many for multiarch
}

// ManifestMeta represents all data related to an image manifests (found from the image contents itself).
type ManifestMeta struct {
	Size     int64
	Digest   godigest.Digest
	Manifest ispec.Manifest
	Config   ispec.Image
}

type (
	Tag         = string
	ImageDigest = string
)

type RepoMeta struct {
	Name string
	Tags map[Tag]Descriptor

	Statistics map[ImageDigest]DescriptorStatistics
	Signatures map[ImageDigest]ManifestSignatures
	Referrers  map[ImageDigest][]ReferrerInfo

	LastUpdatedImage *LastUpdatedImage
	Platforms        []ispec.Platform
	Vendors          []string
	Size             int64

	IsStarred    bool
	IsBookmarked bool
	Rank         int

	StarCount     int
	DownloadCount int
}

// FullImageMeta is a condensed structure of all information needed about an image when searching MetaDB.
type FullImageMeta struct {
	Repo         string
	Tag          string
	MediaType    string
	Digest       godigest.Digest
	Size         int64
	Index        *ispec.Index
	Manifests    []FullManifestMeta
	IsStarred    bool
	IsBookmarked bool

	Referrers       []ReferrerInfo
	Statistics      DescriptorStatistics
	Signatures      ManifestSignatures
	TaggedTimestamp time.Time
}

type FullManifestMeta struct {
	ManifestMeta

	Referrers  []ReferrerInfo
	Statistics DescriptorStatistics
	Signatures ManifestSignatures
}

type LastUpdatedImage struct {
	Descriptor

	Tag         string
	LastUpdated *time.Time
}

type ReferrerInfo struct {
	Digest       string
	MediaType    string
	ArtifactType string
	Size         int
	Annotations  map[string]string
}

// Descriptor represents an image. Multiple images might have the same digests but different tags.
type Descriptor struct {
	Digest          string
	MediaType       string
	TaggedTimestamp time.Time
}

type DescriptorStatistics struct {
	DownloadCount     int
	LastPullTimestamp time.Time
	PushTimestamp     time.Time
	PushedBy          string
}

type (
	SignatureType = string
)

type ManifestSignatures map[SignatureType][]SignatureInfo

type LayerInfo struct {
	LayerDigest  string
	LayerContent []byte
	SignatureKey string
	Signer       string
	Date         time.Time
}

type SignatureInfo struct {
	SignatureManifestDigest string
	LayersInfo              []LayerInfo
}

type SignatureMetadata struct {
	SignatureType   string
	SignatureDigest string
	SignatureTag    string
	LayersInfo      []LayerInfo
}

type (
	HashedAPIKey = string
)

type UserData struct {
	StarredRepos    []string
	BookmarkedRepos []string
	Groups          []string
	APIKeys         map[HashedAPIKey]APIKeyDetails
}

type Filter struct {
	Os            []*string
	Arch          []*string
	HasToBeSigned *bool
	IsBookmarked  *bool
	IsStarred     *bool
}

type FilterData struct {
	DownloadCount int
	LastUpdated   time.Time
	OsList        []string
	ArchList      []string
	IsSigned      bool
	IsStarred     bool
	IsBookmarked  bool
}

type APIKeyDetails struct {
	CreatedAt      time.Time `json:"createdAt"`
	ExpirationDate time.Time `json:"expirationDate"`
	IsExpired      bool      `json:"isExpired"`
	CreatorUA      string    `json:"creatorUa"`
	GeneratedBy    string    `json:"generatedBy"`
	LastUsed       time.Time `json:"lastUsed"`
	Label          string    `json:"label"`
	Scopes         []string  `json:"scopes"`
	UUID           string    `json:"uuid"`
}
