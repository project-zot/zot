package cveinfo

import (
	"sort"

	"github.com/pkg/errors"

	zerr "zotregistry.io/zot/errors"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
)

type SortCriteria string

const (
	AlphabeticAsc = SortCriteria("ALPHABETIC_ASC")
	AlphabeticDsc = SortCriteria("ALPHABETIC_DSC")
	SeverityDsc   = SortCriteria("SEVERITY")
)

func SortFunctions() map[SortCriteria]func(pageBuffer []cvemodel.CVE, cveInfo CveInfo) func(i, j int) bool {
	return map[SortCriteria]func(pageBuffer []cvemodel.CVE, cveInfo CveInfo) func(i, j int) bool{
		AlphabeticAsc: SortByAlphabeticAsc,
		AlphabeticDsc: SortByAlphabeticDsc,
		SeverityDsc:   SortBySeverity,
	}
}

func SortByAlphabeticAsc(pageBuffer []cvemodel.CVE, cveInfo CveInfo) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].ID < pageBuffer[j].ID
	}
}

func SortByAlphabeticDsc(pageBuffer []cvemodel.CVE, cveInfo CveInfo) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].ID > pageBuffer[j].ID
	}
}

func SortBySeverity(pageBuffer []cvemodel.CVE, cveInfo CveInfo) func(i, j int) bool {
	return func(i, j int) bool {
		return cveInfo.CompareSeverities(pageBuffer[i].Severity, pageBuffer[j].Severity) < 0
	}
}

// PageFinder permits keeping a pool of objects using Add
// and returning a specific page.
type PageFinder interface {
	Add(cve cvemodel.CVE)
	Page() ([]cvemodel.CVE, PageInfo)
	Reset()
}

// CvePageFinder implements PageFinder. It manages Cve objects and calculates the page
// using the given limit, offset and sortBy option.
type CvePageFinder struct {
	limit      int
	offset     int
	sortBy     SortCriteria
	pageBuffer []cvemodel.CVE
	cveInfo    CveInfo
}

func NewCvePageFinder(limit, offset int, sortBy SortCriteria, cveInfo CveInfo) (*CvePageFinder, error) {
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
		return nil, errors.Wrapf(zerr.ErrSortCriteriaNotSupported, "sorting CVEs by '%s' is not supported", sortBy)
	}

	return &CvePageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]cvemodel.CVE, 0, limit),
		cveInfo:    cveInfo,
	}, nil
}

func (bpt *CvePageFinder) Reset() {
	bpt.pageBuffer = []cvemodel.CVE{}
}

func (bpt *CvePageFinder) Add(cve cvemodel.CVE) {
	bpt.pageBuffer = append(bpt.pageBuffer, cve)
}

func (bpt *CvePageFinder) Page() ([]cvemodel.CVE, PageInfo) {
	if len(bpt.pageBuffer) == 0 {
		return []cvemodel.CVE{}, PageInfo{}
	}

	pageInfo := &PageInfo{}

	sort.Slice(bpt.pageBuffer, SortFunctions()[bpt.sortBy](bpt.pageBuffer, bpt.cveInfo))

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

type PageInfo struct {
	TotalCount int
	ItemCount  int
}

type PageInput struct {
	Limit  int
	Offset int
	SortBy SortCriteria
}
