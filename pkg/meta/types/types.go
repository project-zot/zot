package types

import (
	"context"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/common"
)

// DetailedRepoMeta is a auxiliary structure used for sorting RepoMeta arrays by information
// that's not directly available in the RepoMetadata structure (ex. that needs to be calculated
// by iterating the manifests, etc.)
type DetailedRepoMeta struct {
	RepoMetadata
	Rank       int
	Downloads  int
	UpdateTime time.Time
}

// Used to model changes to an object after a call to the DB.
type ToggleState int

const (
	NotChanged ToggleState = iota
	Added
	Removed
)

type (
	FilterFunc     func(repoMeta RepoMetadata, manifestMeta ManifestMetadata) bool
	FilterRepoFunc func(repoMeta RepoMetadata) bool
)

type MetaDB interface { //nolint:interfacebloat
	UserDB
	// IncrementRepoStars adds 1 to the star count of an image
	IncrementRepoStars(repo string) error

	// IncrementRepoStars subtracts 1 from the star count of an image
	DecrementRepoStars(repo string) error

	// GetRepoStars returns the total number of stars a repo has
	GetRepoStars(repo string) (int, error)

	// SetRepoReference sets the reference of a manifest in the tag list of a repo
	SetRepoReference(repo string, reference string, manifestDigest godigest.Digest, mediaType string) error

	// DeleteRepoTag delets the tag from the tag list of a repo
	DeleteRepoTag(repo string, tag string) error

	// GetRepoMeta returns RepoMetadata of a repo from the database
	GetRepoMeta(repo string) (RepoMetadata, error)

	// GetUserRepometa return RepoMetadata of a repo from the database along side specific information about the
	// user
	GetUserRepoMeta(ctx context.Context, repo string) (RepoMetadata, error)

	// GetRepoMeta returns RepoMetadata of a repo from the database
	SetRepoMeta(repo string, repoMeta RepoMetadata) error

	// GetMultipleRepoMeta returns information about all repositories as map[string]RepoMetadata filtered by the filter
	// function
	GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMetadata) bool, requestedPage PageInput) (
		[]RepoMetadata, error)

	// SetManifestData sets ManifestData for a given manifest in the database
	SetManifestData(manifestDigest godigest.Digest, md ManifestData) error

	// GetManifestData return the manifest and it's related config
	GetManifestData(manifestDigest godigest.Digest) (ManifestData, error)

	// GetManifestMeta returns ManifestMetadata for a given manifest from the database
	GetManifestMeta(repo string, manifestDigest godigest.Digest) (ManifestMetadata, error)

	// GetManifestMeta sets ManifestMetadata for a given manifest in the database
	SetManifestMeta(repo string, manifestDigest godigest.Digest, mm ManifestMetadata) error

	// SetIndexData sets indexData for a given index in the database
	SetIndexData(digest godigest.Digest, indexData IndexData) error

	// GetIndexData returns indexData for a given Index from the database
	GetIndexData(indexDigest godigest.Digest) (IndexData, error)

	// SetReferrer adds a referrer to the referrers list of a manifest inside a repo
	SetReferrer(repo string, referredDigest godigest.Digest, referrer ReferrerInfo) error

	// SetReferrer delets a referrer to the referrers list of a manifest inside a repo
	DeleteReferrer(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	// GetReferrersInfo returnes a list of  for all referrers of the given digest that match one of the
	// artifact types.
	GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string) (
		[]ReferrerInfo, error)

	// IncrementManifestDownloads adds 1 to the download count of a manifest
	IncrementImageDownloads(repo string, reference string) error

	// AddManifestSignature adds signature metadata to a given manifest in the database
	AddManifestSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// DeleteSignature delets signature metadata to a given manifest from the database
	DeleteSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// UpdateSignaturesValidity checks and updates signatures validity of a given manifest
	UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error

	// SearchRepos searches for repos given a search string
	SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, common.PageInfo, error)

	// SearchTags searches for images(repo:tag) given a search string
	SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, common.PageInfo, error)

	// FilterRepos filters for repos given a filter function
	FilterRepos(ctx context.Context, filter FilterRepoFunc, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, common.PageInfo, error)

	// FilterTags filters for images given a filter function
	FilterTags(ctx context.Context, filterFunc FilterFunc, filter Filter,
		requestedPage PageInput) ([]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, common.PageInfo, error)

	PatchDB() error
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

	SetUserData(ctx context.Context, userData UserData) error

	SetUserGroups(ctx context.Context, groups []string) error

	GetUserGroups(ctx context.Context) ([]string, error)

	DeleteUserData(ctx context.Context) error

	GetUserAPIKeyInfo(hashedKey string) (identity string, err error)

	AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *APIKeyDetails) error

	UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error

	DeleteUserAPIKey(ctx context.Context, id string) error
}

type ManifestMetadata struct {
	ManifestBlob  []byte
	ConfigBlob    []byte
	DownloadCount int
	Signatures    ManifestSignatures
}

type IndexData struct {
	IndexBlob []byte
}

type ManifestData struct {
	ManifestBlob []byte
	ConfigBlob   []byte
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
	Digest    string
	MediaType string
}

type DescriptorStatistics struct {
	DownloadCount int
}

type ManifestSignatures map[string][]SignatureInfo

type RepoMetadata struct {
	Name string
	Tags map[string]Descriptor

	Statistics map[string]DescriptorStatistics
	Signatures map[string]ManifestSignatures
	Referrers  map[string][]ReferrerInfo

	IsStarred    bool
	IsBookmarked bool

	Stars int
}

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
	LayersInfo      []LayerInfo
}

type UserData struct {
	StarredRepos    []string
	BookmarkedRepos []string
	Groups          []string
	APIKeys         map[string]APIKeyDetails
}

type PageInput struct {
	Limit  int
	Offset int
	SortBy SortCriteria
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
	CreatedAt   time.Time `json:"createdAt"`
	CreatorUA   string    `json:"creatorUa"`
	GeneratedBy string    `json:"generatedBy"`
	LastUsed    time.Time `json:"lastUsed"`
	Label       string    `json:"label"`
	Scopes      []string  `json:"scopes"`
	UUID        string    `json:"uuid"`
}
