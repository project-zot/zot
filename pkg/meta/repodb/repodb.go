package repodb

import (
	"context"
	"time"

	godigest "github.com/opencontainers/go-digest"
)

// MetadataDB.
const (
	ManifestDataBucket = "ManifestData"
	IndexDataBucket    = "IndexData"
	ArtifactDataBucket = "ArtifactData"
	UserMetadataBucket = "UserMeta"
	RepoMetadataBucket = "RepoMetadata"
	VersionBucket      = "Version"
	SignaturesDirPath  = "/tmp/zot/signatures"
	SigKey             = "dev.cosignproject.cosign/signature"
	NotationType       = "notation"
	CosignType         = "cosign"
)

type FilterFunc func(repoMeta RepoMetadata, manifestMeta ManifestMetadata) bool

type RepoDB interface { //nolint:interfacebloat
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

	// SetArtifactData sets artifactData for a given artifact in the database
	SetArtifactData(artifactDigest godigest.Digest, artifactData ArtifactData) error

	// GetArtifactData returns artifactData for a given artifact from the database
	GetArtifactData(artifactDigest godigest.Digest) (ArtifactData, error)

	// SetReferrer adds a referrer to the referrers list of a manifest inside a repo
	SetReferrer(repo string, referredDigest godigest.Digest, referrer Descriptor) error

	// SetReferrer delets a referrer to the referrers list of a manifest inside a repo
	DeleteReferrer(repo string, referredDigest godigest.Digest, referrerDigest godigest.Digest) error

	// GetReferrers returns the list of referrers for a referred manifest
	GetReferrers(repo string, referredDigest godigest.Digest) ([]Descriptor, error)

	// GetFilteredReferrersInfo returnes a list of  for all referrers of the given digest that match one of the
	// artifact types.
	GetFilteredReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string) (
		[]ReferrerInfo, error)

	// IncrementManifestDownloads adds 1 to the download count of a manifest
	IncrementImageDownloads(repo string, reference string) error

	// AddManifestSignature adds signature metadata to a given manifest in the database
	AddManifestSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// DeleteSignature delets signature metadata to a given manifest from the database
	DeleteSignature(repo string, signedManifestDigest godigest.Digest, sm SignatureMetadata) error

	// SearchRepos searches for repos given a search string
	SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, PageInfo, error)

	// SearchTags searches for images(repo:tag) given a search string
	SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, PageInfo, error)

	// FilterTags filters for images given a filter function
	FilterTags(ctx context.Context, filter FilterFunc,
		requestedPage PageInput) ([]RepoMetadata, map[string]ManifestMetadata, map[string]IndexData, PageInfo, error)

	PatchDB() error
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

type ArtifactData struct {
	ManifestBlob []byte
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
	Referrers  map[string][]Descriptor

	Stars int
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
	DownloadCount int
	LastUpdated   time.Time
	OsList        []string
	ArchList      []string
	IsSigned      bool
}
