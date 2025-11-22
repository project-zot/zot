package cveinfo

import (
	"fmt"
	"slices"
	"sync"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
)

const (
	AlphabeticAsc = cvemodel.SortCriteria("ALPHABETIC_ASC")
	AlphabeticDsc = cvemodel.SortCriteria("ALPHABETIC_DSC")
	SeverityDsc   = cvemodel.SortCriteria("SEVERITY")
)

var (
	//nolint:gochecknoglobals // lazy initialization with sync.Once to avoid reallocation
	sortFunctionsOnce sync.Once
	//nolint:gochecknoglobals // cached map initialized once, effectively immutable
	sortFunctions map[cvemodel.SortCriteria]func(a, b cvemodel.CVE) int
)

// getSortFunctions returns a cached map of sort criteria to comparison functions.
// Using slices.SortFunc which expects func(a, b cvemodel.CVE) int.
// The map is initialized once using sync.Once to avoid reallocation.
func getSortFunctions() map[cvemodel.SortCriteria]func(a, b cvemodel.CVE) int {
	sortFunctionsOnce.Do(func() {
		sortFunctions = map[cvemodel.SortCriteria]func(a, b cvemodel.CVE) int{
			AlphabeticAsc: sortCVEByAlphabeticAsc,
			AlphabeticDsc: sortCVEByAlphabeticDsc,
			SeverityDsc:   sortCVEBySeverityDsc,
		}
	})

	return sortFunctions
}

//nolint:varnamelen // standard comparison function signature
func sortCVEByAlphabeticAsc(a, b cvemodel.CVE) int {
	if a.ID < b.ID {
		return -1
	}
	if a.ID > b.ID {
		return 1
	}

	return 0
}

//nolint:varnamelen // standard comparison function signature
func sortCVEByAlphabeticDsc(a, b cvemodel.CVE) int {
	if a.ID > b.ID {
		return -1
	}
	if a.ID < b.ID {
		return 1
	}

	return 0
}

//nolint:varnamelen // standard comparison function signature
func sortCVEBySeverityDsc(a, b cvemodel.CVE) int {
	severityCmp := cvemodel.CompareSeverities(a.Severity, b.Severity)
	if severityCmp != 0 {
		return severityCmp
	}

	// If severities are equal, sort by ID ascending
	if a.ID < b.ID {
		return -1
	}
	if a.ID > b.ID {
		return 1
	}

	return 0
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

const maxCvePageLimit = 4 * 1024

func NewCvePageFinder(limit, offset int, sortBy cvemodel.SortCriteria) (*CvePageFinder, error) {
	if sortBy == "" {
		sortBy = SeverityDsc
	}

	if limit < 0 {
		return nil, zerr.ErrLimitIsNegative
	}

	if limit > maxCvePageLimit {
		return nil, zerr.ErrLimitIsExcessive
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	sortFuncs := getSortFunctions()
	if _, found := sortFuncs[sortBy]; !found {
		return nil, fmt.Errorf("sorting CVEs by '%s' is not supported %w", sortBy, zerr.ErrSortCriteriaNotSupported)
	}

	return &CvePageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]cvemodel.CVE, 0),
	}, nil
}

func (bpt *CvePageFinder) Reset() {
	// Preserve capacity to avoid reallocation
	bpt.pageBuffer = bpt.pageBuffer[:0]
}

func (bpt *CvePageFinder) Add(cve cvemodel.CVE) {
	bpt.pageBuffer = append(bpt.pageBuffer, cve)
}

func (bpt *CvePageFinder) Page() ([]cvemodel.CVE, common.PageInfo) {
	if len(bpt.pageBuffer) == 0 {
		return []cvemodel.CVE{}, common.PageInfo{}
	}

	pageInfo := &common.PageInfo{}

	// Use slices.SortFunc with cached comparison function
	sortFuncs := getSortFunctions()
	sortFn, ok := sortFuncs[bpt.sortBy]
	if !ok {
		// Fallback to default (should not happen due to validation in NewCvePageFinder)
		sortFn = sortFuncs[SeverityDsc]
	}
	slices.SortFunc(bpt.pageBuffer, sortFn)

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
