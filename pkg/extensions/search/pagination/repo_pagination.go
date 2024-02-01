package pagination

import (
	"fmt"
	"sort"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	gql_gen "zotregistry.dev/zot/pkg/extensions/search/gql_generated"
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

	if _, found := RepoSumSortFuncs()[sortBy]; !found {
		return nil, fmt.Errorf("sorting repos by '%s' is not supported %w",
			sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &RepoSummariesPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: []*gql_gen.RepoSummary{},
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

	sort.Slice(pf.pageBuffer, RepoSumSortFuncs()[pf.sortBy](pf.pageBuffer))

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

func RepoSumSortFuncs() map[SortCriteria]func(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return map[SortCriteria]func(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool{
		AlphabeticAsc: RepoSortByAlphabeticAsc,
		AlphabeticDsc: RepoSortByAlphabeticDsc,
		Relevance:     RepoSortByRelevance,
		UpdateTime:    RepoSortByUpdateTime,
		Downloads:     RepoSortByDownloads,
	}
}

func RepoSortByAlphabeticAsc(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return *pageBuffer[i].Name < *pageBuffer[j].Name
	}
}

func RepoSortByAlphabeticDsc(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return *pageBuffer[i].Name > *pageBuffer[j].Name
	}
}

func RepoSortByRelevance(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return *pageBuffer[i].Rank < *pageBuffer[j].Rank
	}
}

// SortByUpdateTime sorting descending by time.
func RepoSortByUpdateTime(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].LastUpdated.After(*pageBuffer[j].LastUpdated)
	}
}

// SortByDownloads returns a comparison function for descendant sorting by downloads.
func RepoSortByDownloads(pageBuffer []*gql_gen.RepoSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return *pageBuffer[i].DownloadCount > *pageBuffer[j].DownloadCount
	}
}
