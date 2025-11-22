package convert

import (
	"slices"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	gql_gen "zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

func ImgSumAcceptedByFilter(imageSummary *gql_gen.ImageSummary, filter mTypes.Filter) bool {
	// Early return if image is not signed and signing is required
	if filter.HasToBeSigned != nil && *filter.HasToBeSigned && !*imageSummary.IsSigned {
		return false
	}

	platforms := getImagePlatforms(imageSummary)

	// Early return if no platforms and no filters means platform match passes
	if len(platforms) == 0 && filter.Os == nil && filter.Arch == nil {
		return true
	}

	osFilters := strSliceFromRef(filter.Os)
	archFilters := strSliceFromRef(filter.Arch)

	return slices.ContainsFunc(platforms, func(platform *gql_gen.Platform) bool {
		osCheck := true

		if len(osFilters) > 0 {
			osCheck = platform.Os != nil && zcommon.ContainsStringIgnoreCase(osFilters, *platform.Os)
		}

		archCheck := true

		if len(archFilters) > 0 {
			archCheck = platform.Arch != nil && zcommon.ContainsStringIgnoreCase(archFilters, *platform.Arch)
		}

		return osCheck && archCheck
	})
}

func getImagePlatforms(imageSummary *gql_gen.ImageSummary) []*gql_gen.Platform {
	platforms := make([]*gql_gen.Platform, 0, len(imageSummary.Manifests))

	for _, manifest := range imageSummary.Manifests {
		if manifest.Platform != nil {
			platforms = append(platforms, manifest.Platform)
		}
	}

	return platforms
}

func RepoSumAcceptedByFilter(repoSummary *gql_gen.RepoSummary, filter mTypes.Filter) bool {
	if filter.HasToBeSigned != nil && *filter.HasToBeSigned && !*repoSummary.NewestImage.IsSigned {
		return false
	}

	if filter.IsBookmarked != nil && *filter.IsBookmarked != *repoSummary.IsBookmarked {
		return false
	}

	if filter.IsStarred != nil && *filter.IsStarred != *repoSummary.IsStarred {
		return false
	}

	// Early return if no platforms and no filters means platform match passes
	if len(repoSummary.Platforms) == 0 && filter.Os == nil && filter.Arch == nil {
		return true
	}

	osFilters := strSliceFromRef(filter.Os)
	archFilters := strSliceFromRef(filter.Arch)

	return slices.ContainsFunc(repoSummary.Platforms, func(platform *gql_gen.Platform) bool {
		osCheck := true

		if len(osFilters) > 0 {
			osCheck = platform.Os != nil && zcommon.ContainsStringIgnoreCase(osFilters, *platform.Os)
		}

		archCheck := true

		if len(archFilters) > 0 {
			archCheck = platform.Arch != nil && zcommon.ContainsStringIgnoreCase(archFilters, *platform.Arch)
		}

		return osCheck && archCheck
	})
}

func strSliceFromRef(slice []*string) []string {
	resultSlice := make([]string, len(slice))

	for i := range slice {
		if slice[i] != nil {
			resultSlice[i] = *slice[i]
		}
	}

	return resultSlice
}
