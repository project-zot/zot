package repodb

import (
	"time"
)

// DetailedRepoMeta is a auxiliary structure used for sorting RepoMeta arrays by information
// that's not directly available in the RepoMetadata structure (ex. that needs to be calculated
// by iterating the manifests, etc.)
type DetailedRepoMeta struct {
	RepoMeta   RepoMetadata
	Score      int
	Downloads  int
	UpdateTime time.Time
}

func SortFunctions() map[SortCriteria]func(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return map[SortCriteria]func(pageBuffer []DetailedRepoMeta) func(i, j int) bool{
		AlphabeticAsc: SortByAlphabeticAsc,
		AlphabeticDsc: SortByAlphabeticDsc,
		Relevance:     SortByRelevance,
		UpdateTime:    SortByUpdateTime,
		Stars:         SortByStars,
		Downloads:     SortByDownloads,
	}
}

func SortByAlphabeticAsc(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].RepoMeta.Name < pageBuffer[j].RepoMeta.Name
	}
}

func SortByAlphabeticDsc(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].RepoMeta.Name > pageBuffer[j].RepoMeta.Name
	}
}

func SortByRelevance(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Score < pageBuffer[j].Score
	}
}

// SortByUpdateTime sorting descending by time.
func SortByUpdateTime(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].UpdateTime.After(pageBuffer[j].UpdateTime)
	}
}

func SortByStars(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].RepoMeta.Stars > pageBuffer[j].RepoMeta.Stars
	}
}

// SortByDownloads returns a comparison function for descendant sorting by downloads.
func SortByDownloads(pageBuffer []DetailedRepoMeta) func(i, j int) bool {
	return func(i, j int) bool {
		return pageBuffer[i].Downloads > pageBuffer[j].Downloads
	}
}
