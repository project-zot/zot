package repodb

import (
	"context"

	godigest "github.com/opencontainers/go-digest"
)

// MetadataDB.
const (
	ManifestDataBucket = "ManifestData"
	UserMetadataBucket = "UserMeta"
	RepoMetadataBucket = "RepoMetadata"
	VersionBucket      = "Version"
)

const (
	SignaturesDirPath = "/tmp/zot/signatures"
	SigKey            = "dev.cosignproject.cosign/signature"
	NotationType      = "notation"
	CosignType        = "cosign"
)

type (
	FilterFunc     func(repoMeta RepoMetadata, manifestMeta ManifestMetadata) bool
	FilterRepoFunc func(repoMeta RepoMetadata) bool
)

type RepoDB interface { //nolint:interfacebloat
	// IncrementRepoStars adds 1 to the star count of an image
	IncrementRepoStars(repo string) error

	// IncrementRepoStars subtracts 1 from the star count of an image
	DecrementRepoStars(repo string) error

	// GetRepoStars returns the total number of stars a repo has
	GetRepoStars(repo string) (int, error)

	// SetRepoTag sets the tag of a manifest in the tag list of a repo
	SetRepoTag(repo string, tag string, manifestDigest godigest.Digest, mediaType string) error

	// DeleteRepoTag delets the tag from the tag list of a repo
	DeleteRepoTag(repo string, tag string) error

	// GetRepoMeta returns RepoMetadata of a repo from the database
	GetRepoMeta(repo string) (RepoMetadata, error)

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

	// IncrementManifestDownloads adds 1 to the download count of a manifest
	IncrementImageDownloads(repo string, reference string) error

	// AddManifestSignature adds signature metadata to a given manifest in the database
	AddManifestSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// DeleteSignature delets signature metadata to a given manifest from the database
	DeleteSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// SearchRepos searches for repos given a search string
	SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, PageInfo, error)

	// SearchTags searches for images(repo:tag) given a search string
	SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, PageInfo, error)

	// FilterTags filters for repos given a filter function
	FilterRepos(ctx context.Context,
		filter FilterRepoFunc,
		requestedPage PageInput,
	) (
		[]RepoMetadata, map[string]ManifestMetadata, PageInfo, error,
	)

	// FilterTags filters for images given a filter function
	FilterTags(ctx context.Context, filter FilterFunc,
		requestedPage PageInput) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error)

	PatchDB() error
}

type ManifestMetadata struct {
	ManifestBlob  []byte
	ConfigBlob    []byte
	DownloadCount int
	Signatures    ManifestSignatures
}

type ManifestData struct {
	ManifestBlob []byte
	ConfigBlob   []byte
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
	Stars      int
}

type LayerInfo struct {
	LayerDigest  string
	LayerContent []byte
	SignatureKey string
	Signer       string
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

type SortCriteria string

const (
	Relevance     = SortCriteria("RELEVANCE")
	UpdateTime    = SortCriteria("UPDATE_TIME")
	AlphabeticAsc = SortCriteria("ALPHABETIC_ASC")
	AlphabeticDsc = SortCriteria("ALPHABETIC_DSC")
	Stars         = SortCriteria("STARS")
	Downloads     = SortCriteria("DOWNLOADS")
)

type PageInput struct {
	Limit  int
	Offset int
	SortBy SortCriteria
}

type PageInfo struct {
	TotalCount int
	ItemCount  int
}

type Filter struct {
	Os            []*string
	Arch          []*string
	HasToBeSigned *bool
}

type FilterData struct {
	OsList   []string
	ArchList []string
	IsSigned bool
}
