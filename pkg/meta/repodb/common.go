package repodb

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
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

func SortFunctions() map[SortCriteria]func(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return map[SortCriteria]func(pageBuffer []DetailedRepoMeta) func(i, j int) bool{
		AlphabeticAsc: SortByAlphabeticAsc,
		AlphabeticDsc: SortByAlphabeticDsc,
		Relevance:     SortByRelevance,
		UpdateTime:    SortByUpdateTime,
		Downloads:     SortByDownloads,
	}
}

func SortByAlphabeticAsc(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Name < pageBuffer[j].Name
	}
}

func SortByAlphabeticDsc(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Name > pageBuffer[j].Name
	}
}

func SortByRelevance(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Rank < pageBuffer[j].Rank
	}
}

// SortByUpdateTime sorting descending by time.
func SortByUpdateTime(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].UpdateTime.After(pageBuffer[j].UpdateTime)
	}
}

// SortByDownloads returns a comparison function for descendant sorting by downloads.
func SortByDownloads(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Downloads > pageBuffer[j].Downloads
	}
}

// FindMediaTypeForDigest will look into the buckets for a certain digest. Depending on which bucket that
// digest is found the corresponding mediatype is returned.
func FindMediaTypeForDigest(repoDB RepoDB, digest godigest.Digest) (bool, string) {
	_, err := repoDB.GetManifestData(digest)
	if err == nil {
		return true, ispec.MediaTypeImageManifest
	}

	_, err = repoDB.GetIndexData(digest)
	if err == nil {
		return true, ispec.MediaTypeImageIndex
	}

	return false, ""
}

func GetImageDescriptor(repoDB RepoDB, repo, tag string) (Descriptor, error) {
	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil {
		return Descriptor{}, err
	}

	imageDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return Descriptor{}, zerr.ErrTagMetaNotFound
	}

	return imageDescriptor, nil
}
