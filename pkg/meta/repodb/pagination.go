package repodb

import (
	"sort"

	"github.com/pkg/errors"

	zerr "zotregistry.io/zot/errors"
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
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	if _, found := SortFunctions()[sortBy]; !found {
		return nil, errors.Wrapf(zerr.ErrSortCriteriaNotSupported, "sorting repos by '%s' is not supported", sortBy)
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

	// the offset and limit are calculatd in terms of repos counted
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
		return nil, zerr.ErrLimitIsNegative
	}

	if offset < 0 {
		return nil, zerr.ErrOffsetIsNegative
	}

	if _, found := SortFunctions()[sortBy]; !found {
		return nil, errors.Wrapf(zerr.ErrSortCriteriaNotSupported, "sorting repos by '%s' is not supported", sortBy)
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

	// the offset and limit are calculatd in terms of tags counted
	remainingOffset := bpt.offset
	remainingLimit := bpt.limit

	// bring cursor to position in RepoMeta array
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

	// finish counting remaining tags inside the first repo meta
	partialTags := map[string]string{}
	firstRepoMeta := bpt.pageBuffer[repoStartIndex].RepoMeta

	tags := make([]string, 0, len(firstRepoMeta.Tags))
	for k := range firstRepoMeta.Tags {
		tags = append(tags, k)
	}

	sort.Strings(tags)

	for i := tagStartIndex; i < len(tags); i++ {
		tag := tags[i]

		partialTags[tag] = firstRepoMeta.Tags[tag]
		remainingLimit--

		if remainingLimit == 0 {
			firstRepoMeta.Tags = partialTags
			repos = append(repos, firstRepoMeta)

			return repos
		}
	}

	firstRepoMeta.Tags = partialTags
	repos = append(repos, firstRepoMeta)
	repoStartIndex++

	// continue with the remaining repos
	for i := repoStartIndex; i < len(bpt.pageBuffer); i++ {
		repoMeta := bpt.pageBuffer[i].RepoMeta

		if len(repoMeta.Tags) > remainingLimit {
			partialTags := map[string]string{}

			tags := make([]string, 0, len(repoMeta.Tags))
			for k := range repoMeta.Tags {
				tags = append(tags, k)
			}

			sort.Strings(tags)

			for _, tag := range tags {
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
