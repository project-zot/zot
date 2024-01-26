package cveinfo

import (
	"fmt"
	"sort"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
)

const (
	AlphabeticAsc = cvemodel.SortCriteria("ALPHABETIC_ASC")
	AlphabeticDsc = cvemodel.SortCriteria("ALPHABETIC_DSC")
	SeverityDsc   = cvemodel.SortCriteria("SEVERITY")
)

func SortFunctions() map[cvemodel.SortCriteria]func(pageBuffer []cvemodel.CVE) func(i, j int) bool {
	return map[cvemodel.SortCriteria]func(pageBuffer []cvemodel.CVE) func(i, j int) bool{
		AlphabeticAsc: SortByAlphabeticAsc,
		AlphabeticDsc: SortByAlphabeticDsc,
		SeverityDsc:   SortBySeverity,
	}
}

func SortByAlphabeticAsc(pageBuffer []cvemodel.CVE) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].ID < pageBuffer[j].ID
	}
}

func SortByAlphabeticDsc(pageBuffer []cvemodel.CVE) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].ID > pageBuffer[j].ID
	}
}

func SortBySeverity(pageBuffer []cvemodel.CVE) func(i, j int) bool {
	return func(i, j int) bool {
		if cvemodel.CompareSeverities(pageBuffer[i].Severity, pageBuffer[j].Severity) == 0 {
			return pageBuffer[i].ID < pageBuffer[j].ID
		}

		return cvemodel.CompareSeverities(pageBuffer[i].Severity, pageBuffer[j].Severity) < 0
	}
}

// PageFinder permits keeping a pool of objects using Add
// and returning a specific page.
type PageFinder interface {
	Add(cve cvemodel.CVE)
	Page() ([]cvemodel.CVE, common.PageInfo)
	Reset()
}

// CvePageFinder implements PageFinder. It manages Cve objects and calculates the page
// using the given limit, offset and sortBy option.
type CvePageFinder struct {
	limit      int
	offset     int
	sortBy     cvemodel.SortCriteria
	pageBuffer []cvemodel.CVE
}

func NewCvePageFinder(limit, offset int, sortBy cvemodel.SortCriteria) (*CvePageFinder, error) {
	if sortBy == "" {
		sortBy = SeverityDsc
	}

	if limit < 0 {
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	if _, found := SortFunctions()[sortBy]; !found {
		return nil, fmt.Errorf("sorting CVEs by '%s' is not supported %w", sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &CvePageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]cvemodel.CVE, 0, limit),
	}, nil
}

func (bpt *CvePageFinder) Reset() {
	bpt.pageBuffer = []cvemodel.CVE{}
}

func (bpt *CvePageFinder) Add(cve cvemodel.CVE) {
	bpt.pageBuffer = append(bpt.pageBuffer, cve)
}

func (bpt *CvePageFinder) Page() ([]cvemodel.CVE, common.PageInfo) {
	if len(bpt.pageBuffer) == 0 {
		return []cvemodel.CVE{}, common.PageInfo{}
	}

	pageInfo := &common.PageInfo{}

	sort.Slice(bpt.pageBuffer, SortFunctions()[bpt.sortBy](bpt.pageBuffer))

	// the offset and limit are calculated in terms of CVEs counted
	start := bpt.offset
	end := bpt.offset + bpt.limit

	// we'll return an empty array when the offset is greater than the number of elements
	if start >= len(bpt.pageBuffer) {
		start = len(bpt.pageBuffer)
		end = start
	}

	if end >= len(bpt.pageBuffer) {
		end = len(bpt.pageBuffer)
	}

	cves := bpt.pageBuffer[start:end]

	pageInfo.ItemCount = len(cves)

	if start == 0 && end == 0 {
		cves = bpt.pageBuffer
		pageInfo.ItemCount = len(cves)
	}

	pageInfo.TotalCount = len(bpt.pageBuffer)

	return cves, *pageInfo
}
