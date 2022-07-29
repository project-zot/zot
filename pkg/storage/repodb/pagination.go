package repodb

import (
	"sort"

	"github.com/pkg/errors"
)

var (
	ErrLimitIsNegative          = errors.New("pageturner: limit has negative value")
	ErrOffsetIsNegative         = errors.New("pageturner: offset has negative value")
	ErrSortCriteriaNotSupported = errors.New("pageturner: the sort criteria is not supported")
)

// PageFinder permits keeping a pool of objects using Add
// and returning a specific page.
type PageFinder interface {
	// Add
	Add(detailedRepoMeta DetailedRepoMeta)
	Page() []RepoMetadata
	Reset()
}

// RepoPageFinder implements PageFinder. It manages RepoMeta objects and calculates the page
// using the given limit, offset and sortBy option.
type RepoPageFinder struct {
	limit      int
	offset     int
	sortBy     SortCriteria
	pageBuffer []DetailedRepoMeta
}

func NewBaseRepoPageFinder(limit, offset int, sortBy SortCriteria) (*RepoPageFinder, error) {
	if sortBy == "" {
		sortBy = AlphabeticAsc
	}

	if limit < 0 {
		return nil, ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, ErrLimitIsNegative
	}

	if _, found := SortFunctions()[sortBy]; !found {
		return nil, errors.Wrapf(ErrSortCriteriaNotSupported, "sorting repos by '%s' is not supported", sortBy)
	}

	return &RepoPageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]DetailedRepoMeta, 0, limit),
	}, nil
}

func (bpt *RepoPageFinder) Reset() {
	bpt.pageBuffer = []DetailedRepoMeta{}
}

func (bpt *RepoPageFinder) Add(namedRepoMeta DetailedRepoMeta) {
	bpt.pageBuffer = append(bpt.pageBuffer, namedRepoMeta)
}

func (bpt *RepoPageFinder) Page() []RepoMetadata {
	if len(bpt.pageBuffer) == 0 {
		return []RepoMetadata{}
	}

	sort.Slice(bpt.pageBuffer, SortFunctions()[bpt.sortBy](bpt.pageBuffer))

	start := bpt.offset
	end := bpt.offset + bpt.limit

	// we'll return an empty array when the offset is greater than the number of elements
	if start >= len(bpt.pageBuffer) {
		start = len(bpt.pageBuffer)
		end = start
	}

	detailedReposPage := bpt.pageBuffer[start:end]

	if start == 0 && end == 0 {
		detailedReposPage = bpt.pageBuffer
	}

	repos := make([]RepoMetadata, 0, len(detailedReposPage))

	for _, drm := range detailedReposPage {
		repos = append(repos, drm.RepoMeta)
	}

	return repos
}

type ImagePageFinder struct {
	limit      int
	offset     int
	sortBy     SortCriteria
	pageBuffer []DetailedRepoMeta
}

func NewBaseImagePageFinder(limit, offset int, sortBy SortCriteria) (*ImagePageFinder, error) {
	if sortBy == "" {
		sortBy = AlphabeticAsc
	}

	if limit < 0 {
		return nil, ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, ErrLimitIsNegative
	}

	if _, found := SortFunctions()[sortBy]; !found {
		return nil, errors.Wrapf(ErrSortCriteriaNotSupported, "sorting repos by '%s' is not supported", sortBy)
	}

	return &ImagePageFinder{
		limit:      limit,
		offset:     offset,
		sortBy:     sortBy,
		pageBuffer: make([]DetailedRepoMeta, 0, limit),
	}, nil
}

func (bpt *ImagePageFinder) Reset() {
	bpt.pageBuffer = []DetailedRepoMeta{}
}

func (bpt *ImagePageFinder) Add(namedRepoMeta DetailedRepoMeta) {
	bpt.pageBuffer = append(bpt.pageBuffer, namedRepoMeta)
}

func (bpt *ImagePageFinder) Page() []RepoMetadata {
	if len(bpt.pageBuffer) == 0 {
		return []RepoMetadata{}
	}

	sort.Slice(bpt.pageBuffer, SortFunctions()[bpt.sortBy](bpt.pageBuffer))

	repoStartIndex := 0
	tagStartIndex := 0
	remainingOffset := bpt.offset
	remainingLimit := bpt.limit

	// bring cursor to position
	for _, drm := range bpt.pageBuffer {
		if remainingOffset < len(drm.RepoMeta.Tags) {
			tagStartIndex = remainingOffset

			break
		}

		remainingOffset -= len(drm.RepoMeta.Tags)
		repoStartIndex++
	}

	// offset is larger than the number of tags
	if repoStartIndex >= len(bpt.pageBuffer) {
		return []RepoMetadata{}
	}

	repos := make([]RepoMetadata, 0)

	// finish any partial repo tags (when tagStartIndex is not 0)

	partialTags := map[string]string{}
	repoMeta := bpt.pageBuffer[repoStartIndex].RepoMeta

	keys := make([]string, 0, len(repoMeta.Tags))
	for k := range repoMeta.Tags {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for i := tagStartIndex; i < len(keys); i++ {
		tag := keys[i]

		partialTags[tag] = repoMeta.Tags[tag]
		remainingLimit--

		if remainingLimit == 0 {
			repoMeta.Tags = partialTags
			repos = append(repos, repoMeta)

			return repos
		}
	}

	repoMeta.Tags = partialTags
	repos = append(repos, repoMeta)
	repoStartIndex++

	// continue with the remaining repos
	for i := repoStartIndex; i < len(bpt.pageBuffer); i++ {
		repoMeta := bpt.pageBuffer[i].RepoMeta

		if len(repoMeta.Tags) > remainingLimit {
			partialTags := map[string]string{}

			keys := make([]string, 0, len(repoMeta.Tags))
			for k := range repoMeta.Tags {
				keys = append(keys, k)
			}

			sort.Strings(keys)

			for _, tag := range keys {
				partialTags[tag] = repoMeta.Tags[tag]
				remainingLimit--

				if remainingLimit == 0 {
					repoMeta.Tags = partialTags
					repos = append(repos, repoMeta)

					break
				}
			}

			return repos
		}

		// add the whole repo
		repos = append(repos, repoMeta)
		remainingLimit -= len(repoMeta.Tags)

		if remainingLimit == 0 {
			return repos
		}
	}

	// we arrive here when the limit is bigger than the number of tags

	return repos
}
