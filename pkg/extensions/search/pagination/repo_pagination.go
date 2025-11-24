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
	repoSortFunctionsOnce sync.Once
	//nolint:gochecknoglobals // cached map initialized once, effectively immutable
	repoSortFunctions map[SortCriteria]func(a, b *gql_gen.RepoSummary) int
)

type RepoSummariesPageFinder struct {
	limit      int
	offset     int
	sortBy     SortCriteria
	pageBuffer []*gql_gen.RepoSummary
}

func NewRepoSumPageFinder(limit, offset int, sortBy SortCriteria) (*RepoSummariesPageFinder, error) {
	if sortBy == "" {
		sortBy = AlphabeticAsc
	}

	if limit < 0 {
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	sortFuncs := getRepoSortFunctions()
	if _, found := sortFuncs[sortBy]; !found {
		return nil, fmt.Errorf("sorting repos by '%s' is not supported %w",
			sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &RepoSummariesPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]*gql_gen.RepoSummary, 0),
	}, nil
}

func (pf *RepoSummariesPageFinder) Add(imgSum *gql_gen.RepoSummary) {
	pf.pageBuffer = append(pf.pageBuffer, imgSum)
}

func (pf *RepoSummariesPageFinder) Page() ([]*gql_gen.RepoSummary, zcommon.PageInfo) {
	if len(pf.pageBuffer) == 0 {
		return []*gql_gen.RepoSummary{}, zcommon.PageInfo{}
	}

	pageInfo := zcommon.PageInfo{}

	sortFuncs := getRepoSortFunctions()
	sortFn, ok := sortFuncs[pf.sortBy]
	if !ok {
		// Fallback to default (should not happen due to validation in NewRepoSumPageFinder)
		sortFn = sortFuncs[AlphabeticAsc]
	}
	slices.SortFunc(pf.pageBuffer, sortFn)

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

// getRepoSortFunctions returns a cached map of sort functions.
// The map is initialized once using sync.Once to avoid reallocation.
func getRepoSortFunctions() map[SortCriteria]func(a, b *gql_gen.RepoSummary) int {
	repoSortFunctionsOnce.Do(func() {
		repoSortFunctions = map[SortCriteria]func(a, b *gql_gen.RepoSummary) int{
			AlphabeticAsc: RepoSortByAlphabeticAsc,
			AlphabeticDsc: RepoSortByAlphabeticDsc,
			Relevance:     RepoSortByRelevance,
			UpdateTime:    RepoSortByUpdateTime,
			Downloads:     RepoSortByDownloads,
		}
	})

	return repoSortFunctions
}

// RepoSortByAlphabeticAsc sorts alphabetically ascending.
func RepoSortByAlphabeticAsc(a, b *gql_gen.RepoSummary) int {
	if *a.Name < *b.Name {
		return -1
	}
	if *a.Name == *b.Name {
		return 0
	}

	return 1
}

// RepoSortByAlphabeticDsc sorts alphabetically descending.
func RepoSortByAlphabeticDsc(a, b *gql_gen.RepoSummary) int {
	if *a.Name > *b.Name {
		return -1
	}
	if *a.Name == *b.Name {
		return 0
	}

	return 1
}

// RepoSortByRelevance sorts by relevance.
func RepoSortByRelevance(a, b *gql_gen.RepoSummary) int {
	if *a.Rank < *b.Rank {
		return -1
	}
	if *a.Rank == *b.Rank {
		return 0
	}

	return 1
}

// RepoSortByUpdateTime sorts descending by time.
func RepoSortByUpdateTime(a, b *gql_gen.RepoSummary) int { //nolint:varnamelen // standard comparison func signature
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

// RepoSortByDownloads returns a comparison function for descendant sorting by downloads.
func RepoSortByDownloads(a, b *gql_gen.RepoSummary) int {
	if *a.DownloadCount > *b.DownloadCount {
		return -1
	}
	if *a.DownloadCount == *b.DownloadCount {
		return 0
	}

	return 1
}
