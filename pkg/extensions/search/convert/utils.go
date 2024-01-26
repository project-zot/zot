package convert

import (
	zcommon "zotregistry.dev/zot/pkg/common"
	gql_gen "zotregistry.dev/zot/pkg/extensions/search/gql_generated"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

func ImgSumAcceptedByFilter(imageSummary *gql_gen.ImageSummary, filter mTypes.Filter) bool {
	osFilters := strSliceFromRef(filter.Os)
	archFilters := strSliceFromRef(filter.Arch)
	platforms := getImagePlatforms(imageSummary)

	platformMatchFound := len(platforms) == 0 && filter.Os == nil && filter.Arch == nil

	for _, platform := range platforms {
		osCheck := true

		if len(osFilters) > 0 {
			osCheck = platform.Os != nil && zcommon.ContainsStringIgnoreCase(osFilters, *platform.Os)
		}

		archCheck := true

		if len(archFilters) > 0 {
			archCheck = platform.Arch != nil && zcommon.ContainsStringIgnoreCase(archFilters, *platform.Arch)
		}

		if osCheck && archCheck {
			platformMatchFound = true

			break
		}
	}

	if !platformMatchFound {
		return false
	}

	if filter.HasToBeSigned != nil && *filter.HasToBeSigned && !*imageSummary.IsSigned {
		return false
	}

	return true
}

func getImagePlatforms(imageSummary *gql_gen.ImageSummary) []*gql_gen.Platform {
	platforms := []*gql_gen.Platform{}

	for _, manifest := range imageSummary.Manifests {
		if manifest.Platform != nil {
			platforms = append(platforms, manifest.Platform)
		}
	}

	return platforms
}

func RepoSumAcceptedByFilter(repoSummary *gql_gen.RepoSummary, filter mTypes.Filter) bool {
	osFilters := strSliceFromRef(filter.Os)
	archFilters := strSliceFromRef(filter.Arch)

	platformMatchFound := len(repoSummary.Platforms) == 0 && filter.Os == nil && filter.Arch == nil

	for _, platform := range repoSummary.Platforms {
		osCheck := true

		if len(osFilters) > 0 {
			osCheck = platform.Os != nil && zcommon.ContainsStringIgnoreCase(osFilters, *platform.Os)
		}

		archCheck := true

		if len(archFilters) > 0 {
			archCheck = platform.Arch != nil && zcommon.ContainsStringIgnoreCase(archFilters, *platform.Arch)
		}

		if osCheck && archCheck {
			platformMatchFound = true

			break
		}
	}

	if !platformMatchFound {
		return false
	}

	if filter.HasToBeSigned != nil && *filter.HasToBeSigned && !*repoSummary.NewestImage.IsSigned {
		return false
	}

	if filter.IsBookmarked != nil && *filter.IsBookmarked != *repoSummary.IsBookmarked {
		return false
	}

	if filter.IsStarred != nil && *filter.IsStarred != *repoSummary.IsStarred {
		return false
	}

	return true
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
