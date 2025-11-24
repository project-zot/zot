package pagination

import (
	"fmt"
	"slices"
	"sync"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	gql_gen "zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
)

var (
	//nolint:gochecknoglobals // lazy initialization with sync.Once to avoid reallocation
	imgSortFunctionsOnce sync.Once
	//nolint:gochecknoglobals // cached map of static sort functions, effectively immutable
	imgSortFunctions map[SortCriteria]func(a, b *gql_gen.ImageSummary) int
)

type ImageSummariesPageFinder struct {
	limit      int
	offset     int
	sortBy     SortCriteria
	pageBuffer []*gql_gen.ImageSummary
}

func NewImgSumPageFinder(limit, offset int, sortBy SortCriteria) (*ImageSummariesPageFinder, error) {
	if sortBy == "" {
		sortBy = AlphabeticAsc
	}

	if limit < 0 {
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	// Validate sortBy
	if _, found := getImgSortFunctions()[sortBy]; !found {
		return nil, fmt.Errorf("sorting repos by '%s' is not supported %w",
			sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &ImageSummariesPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]*gql_gen.ImageSummary, 0),
	}, nil
}

func (pf *ImageSummariesPageFinder) Add(imgSum *gql_gen.ImageSummary) {
	pf.pageBuffer = append(pf.pageBuffer, imgSum)
}

func (pf *ImageSummariesPageFinder) Page() ([]*gql_gen.ImageSummary, zcommon.PageInfo) {
	if len(pf.pageBuffer) == 0 {
		return []*gql_gen.ImageSummary{}, zcommon.PageInfo{}
	}

	pageInfo := zcommon.PageInfo{}

	slices.SortFunc(pf.pageBuffer, getImgSortFunctions()[pf.sortBy])

	// the offset and limit are calculated in terms of repos counted
	start := pf.offset
	end := pf.offset + pf.limit

	// we'll return an empty array when the offset is greater than the number of elements
	if start >= len(pf.pageBuffer) {
		start = len(pf.pageBuffer)
		end = start
	}

	if end >= len(pf.pageBuffer) {
		end = len(pf.pageBuffer)
	}

	page := pf.pageBuffer[start:end]

	pageInfo.ItemCount = len(page)

	if start == 0 && end == 0 {
		page = pf.pageBuffer
		pageInfo.ItemCount = len(page)
	}

	pageInfo.TotalCount = len(pf.pageBuffer)

	return page, pageInfo
}

// getImgSortFunctions returns a cached map of sort functions.
func getImgSortFunctions() map[SortCriteria]func(a, b *gql_gen.ImageSummary) int {
	imgSortFunctionsOnce.Do(func() {
		imgSortFunctions = map[SortCriteria]func(a, b *gql_gen.ImageSummary) int{
			AlphabeticAsc: ImgSortByAlphabeticAsc,
			AlphabeticDsc: ImgSortByAlphabeticDsc,
			Relevance:     ImgSortByRelevance,
			UpdateTime:    ImgSortByUpdateTime,
			Downloads:     ImgSortByDownloads,
		}
	})

	return imgSortFunctions
}

// ImgSortByAlphabeticAsc sorts alphabetically ascending.
func ImgSortByAlphabeticAsc(a, b *gql_gen.ImageSummary) int { //nolint:varnamelen // standard comparison func signature
	if *a.RepoName < *b.RepoName {
		return -1
	}

	if *a.RepoName == *b.RepoName {
		if *a.Tag < *b.Tag {
			return -1
		}
		if *a.Tag == *b.Tag {
			return 0
		}
	}

	return 1
}

// ImgSortByAlphabeticDsc sorts alphabetically descending.
func ImgSortByAlphabeticDsc(a, b *gql_gen.ImageSummary) int { //nolint:varnamelen // standard comparison func signature
	if *a.RepoName > *b.RepoName {
		return -1
	}

	if *a.RepoName == *b.RepoName {
		if *a.Tag > *b.Tag {
			return -1
		}
		if *a.Tag == *b.Tag {
			return 0
		}
	}

	return 1
}

// ImgSortByRelevance sorts by relevance.
func ImgSortByRelevance(a, b *gql_gen.ImageSummary) int { //nolint:varnamelen // standard comparison func signature
	if *a.RepoName < *b.RepoName {
		return -1
	}

	if *a.RepoName == *b.RepoName {
		if *a.Tag < *b.Tag {
			return -1
		}
		if *a.Tag == *b.Tag {
			return 0
		}
	}

	return 1
}

// ImgSortByUpdateTime sorts descending by image update time.
func ImgSortByUpdateTime(a, b *gql_gen.ImageSummary) int { //nolint:varnamelen // standard comparison func signature
	// Handle nil and zero time cases: both are treated as oldest (come last in descending sort)
	aIsZero := a.LastUpdated == nil || (a.LastUpdated != nil && a.LastUpdated.IsZero())
	bIsZero := b.LastUpdated == nil || (b.LastUpdated != nil && b.LastUpdated.IsZero())

	if aIsZero && bIsZero {
		return 0
	}

	if aIsZero {
		return 1 // a is zero/nil, b is not - a comes after b
	}

	if bIsZero {
		return -1 // b is zero/nil, a is not - a comes before b
	}

	if a.LastUpdated.After(*b.LastUpdated) {
		return -1
	}

	if a.LastUpdated.Equal(*b.LastUpdated) {
		return 0
	}

	return 1
}

// ImgSortByDownloads returns a comparison function for descendant sorting by downloads.
func ImgSortByDownloads(a, b *gql_gen.ImageSummary) int {
	if *a.DownloadCount > *b.DownloadCount {
		return -1
	}
	if *a.DownloadCount == *b.DownloadCount {
		return 0
	}

	return 1
}
