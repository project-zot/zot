package pagination

import (
	"fmt"
	"sort"
	"time"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	gql_gen "zotregistry.dev/zot/pkg/extensions/search/gql_generated"
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

	if _, found := ImgSumSortFuncs()[sortBy]; !found {
		return nil, fmt.Errorf("sorting repos by '%s' is not supported %w",
			sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &ImageSummariesPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: []*gql_gen.ImageSummary{},
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

	sort.Slice(pf.pageBuffer, ImgSumSortFuncs()[pf.sortBy](pf.pageBuffer))

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

func ImgSumSortFuncs() map[SortCriteria]func(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	return map[SortCriteria]func(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool{
		AlphabeticAsc: ImgSortByAlphabeticAsc,
		AlphabeticDsc: ImgSortByAlphabeticDsc,
		UpdateTime:    ImgSortByUpdateTime,
		Relevance:     ImgSortByRelevance,
		Downloads:     ImgSortByDownloads,
	}
}

func ImgSortByAlphabeticAsc(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	return func(i, j int) bool { //nolint: varnamelen
		if *pageBuffer[i].RepoName < *pageBuffer[j].RepoName {
			return true
		}

		if *pageBuffer[i].RepoName == *pageBuffer[j].RepoName {
			return *pageBuffer[i].Tag < *pageBuffer[j].Tag
		}

		return false
	}
}

func ImgSortByAlphabeticDsc(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	return func(i, j int) bool { //nolint: varnamelen
		if *pageBuffer[i].RepoName > *pageBuffer[j].RepoName {
			return true
		}

		if *pageBuffer[i].RepoName == *pageBuffer[j].RepoName {
			return *pageBuffer[i].Tag > *pageBuffer[j].Tag
		}

		return false
	}
}

func ImgSortByRelevance(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	return func(i, j int) bool { //nolint: varnamelen
		if *pageBuffer[i].RepoName < *pageBuffer[j].RepoName {
			return true
		}

		if *pageBuffer[i].RepoName == *pageBuffer[j].RepoName {
			return *pageBuffer[i].Tag < *pageBuffer[j].Tag
		}

		return false
	}
}

// SortByUpdateTime sorting descending by time.
func ImgSortByUpdateTime(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	repos2LastUpdated := map[string]time.Time{}

	for _, img := range pageBuffer {
		lastUpdated, ok := repos2LastUpdated[*img.RepoName]

		if !ok || lastUpdated.Before(*img.LastUpdated) {
			repos2LastUpdated[*img.RepoName] = *img.LastUpdated
		}
	}

	return func(i, j int) bool {
		iRepoTime, jRepoTime := repos2LastUpdated[*pageBuffer[i].RepoName], repos2LastUpdated[*pageBuffer[j].RepoName]

		return (iRepoTime.After(jRepoTime) || iRepoTime.Equal(jRepoTime)) &&
			pageBuffer[i].LastUpdated.After(*pageBuffer[j].LastUpdated)
	}
}

// SortByDownloads returns a comparison function for descendant sorting by downloads.
func ImgSortByDownloads(pageBuffer []*gql_gen.ImageSummary) func(i, j int) bool {
	return func(i, j int) bool {
		return *pageBuffer[i].DownloadCount > *pageBuffer[j].DownloadCount
	}
}
