package repodb

import "context"

// MetadataDB.
const (
	ManifestMetadataBucket = "ManifestMetadata"
	UserMetadataBucket     = "UserMeta"
	RepoMetadataBucket     = "RepoMetadata"
)

type RepoDB interface { //nolint:interfacebloat
	// SetRepoDescription sets the repo description
	SetRepoDescription(repo, description string) error

	// IncrementRepoStars adds 1 to the star count of an image
	IncrementRepoStars(repo string) error

	// IncrementRepoStars subtracts 1 from the star count of an image
	DecrementRepoStars(repo string) error

	// GetRepoStars returns the total number of stars a repo has
	GetRepoStars(repo string) (int, error)

	// SetRepoLogo sets the path of the repo logo image
	SetRepoLogo(repo string, logoPath string) error

	// SetRepoTag sets the tag of a manifest in the tag list of a repo
	SetRepoTag(repo string, tag string, manifestDigest string) error

	// DeleteRepoTag delets the tag from the tag list of a repo
	DeleteRepoTag(repo string, tag string) error

	// GetRepoMeta returns RepoMetadata of a repo from the database
	GetRepoMeta(repo string) (RepoMetadata, error)

	// GetMultipleRepoMeta returns information about all repositories as map[string]RepoMetadata filtered by the filter
	// function
	GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMetadata) bool, requestedPage PageInput) (
		[]RepoMetadata, error)

	// GetManifestMeta returns ManifestMetadata for a given manifest from the database
	GetManifestMeta(manifestDigest string) (ManifestMetadata, error)

	// GetManifestMeta sets ManifestMetadata for a given manifest in the database
	SetManifestMeta(manifestDigest string, mm ManifestMetadata) error

	// IncrementManifestDownloads adds 1 to the download count of a manifest
	IncrementManifestDownloads(manifestDigest string) error

	// AddManifestSignature adds signature metadata to a given manifest in the database
	AddManifestSignature(manifestDigest string, sm SignatureMetadata) error

	// DeleteSignature delets signature metadata to a given manifest from the database
	DeleteSignature(manifestDigest string, sm SignatureMetadata) error

	// SearchRepos searches for repos given a search string
	SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)

	// SearchTags searches for images(repo:tag) given a search string
	SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)

	// SearchDigests searches for digests given a search string
	SearchDigests(ctx context.Context, searchText string, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)

	// SearchLayers searches for layers given a search string
	SearchLayers(ctx context.Context, searchText string, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)

	// SearchForAscendantImages searches for ascendant images given a search string
	SearchForAscendantImages(ctx context.Context, searchText string, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)

	// SearchForDescendantImages searches for descendant images given a search string
	SearchForDescendantImages(ctx context.Context, searchText string, requestedPage PageInput) (
		[]RepoMetadata, map[string]ManifestMetadata, error)
}

type ManifestMetadata struct {
	ManifestBlob  []byte
	ConfigBlob    []byte
	DownloadCount int
	Signatures    map[string][]string
	Dependencies  []string
	Dependants    []string
	BlobsSize     int
	BlobCount     int
}

type RepoMetadata struct {
	Name        string
	Tags        map[string]string
	Signatures  []string
	Stars       int
	Description string
	LogoPath    string
}

type SignatureMetadata struct {
	SignatureType   string
	SignatureDigest string
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

type Filter struct {
	Os            []*string
	Arch          []*string
	HasToBeSigned *bool
}

type filterData struct {
	OsList   []string
	ArchList []string
	IsSigned bool
}
