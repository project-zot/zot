package convert

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/meta/repodb"
)

type SkipQGLField struct {
	Vulnerabilities bool
}

func RepoMeta2RepoSummary(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata,
	skip SkipQGLField, cveInfo cveinfo.CveInfo, isBookmarked bool, isStarred bool,
) *gql_generated.RepoSummary {
	var (
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.OsArch{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoStarCount            = repoMeta.Stars
		// isBookmarked             = false
		// isStarred                = false
		repoDownloadCount = 0
		repoName          = repoMeta.Name

		// map used to keep track of all blobs of a repo without dublicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)
	)

	for tag, manifestDigest := range repoMeta.Tags {
		var manifestContent ispec.Manifest

		err := json.Unmarshal(manifestMetaMap[manifestDigest].ManifestBlob, &manifestContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
				"error: %s", repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		var configContent ispec.Image

		err = json.Unmarshal(manifestMetaMap[manifestDigest].ConfigBlob, &configContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal config blob for image: %s:%s, manifest digest: %s, error: %s",
				repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		var (
			tag              = tag
			isSigned         = len(manifestMetaMap[manifestDigest].Signatures) > 0
			configDigest     = manifestContent.Config.Digest.String()
			configSize       = manifestContent.Config.Size
			opSys            = configContent.OS
			arch             = configContent.Architecture
			osArch           = gql_generated.OsArch{Os: &opSys, Arch: &arch}
			imageLastUpdated = common.GetImageLastUpdated(configContent)
			downloadCount    = manifestMetaMap[manifestDigest].DownloadCount
			manifestDigest   = manifestDigest

			size = updateRepoBlobsMap(
				manifestDigest, int64(len(manifestMetaMap[manifestDigest].ManifestBlob)),
				configDigest, configSize,
				manifestContent.Layers,
				repoBlob2Size)
			imageSize = strconv.FormatInt(size, 10)
		)

		annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

		authors := annotations.Authors
		if authors == "" {
			authors = configContent.Author
		}

		historyEntries, err := getAllHistory(manifestContent, configContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
				"manifest digest: %s, error: %s", tag, repoMeta.Name, manifestDigest, err.Error()))
		}

		imageCveSummary := cveinfo.ImageCVESummary{}

		imageSummary := gql_generated.ImageSummary{
			RepoName:      &repoName,
			Tag:           &tag,
			Digest:        &manifestDigest,
			ConfigDigest:  &configDigest,
			LastUpdated:   &imageLastUpdated,
			IsSigned:      &isSigned,
			Size:          &imageSize,
			Platform:      &osArch,
			Vendor:        &annotations.Vendor,
			DownloadCount: &downloadCount,
			Layers:        getLayersSummaries(manifestContent),
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			Logo:          &annotations.Logo,
			Authors:       &authors,
			History:       historyEntries,
			Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
				MaxSeverity: &imageCveSummary.MaxSeverity,
				Count:       &imageCveSummary.Count,
			},
		}

		if annotations.Vendor != "" {
			repoVendorsSet[annotations.Vendor] = true
		}

		if opSys != "" || arch != "" {
			osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
			repoPlatformsSet[osArchString] = &gql_generated.OsArch{Os: &opSys, Arch: &arch}
		}

		if repoLastUpdatedTimestamp.Equal(time.Time{}) {
			// initialize with first time value
			repoLastUpdatedTimestamp = imageLastUpdated
			lastUpdatedImageSummary = &imageSummary
		} else if repoLastUpdatedTimestamp.Before(imageLastUpdated) {
			repoLastUpdatedTimestamp = imageLastUpdated
			lastUpdatedImageSummary = &imageSummary
		}

		repoDownloadCount += manifestMetaMap[manifestDigest].DownloadCount
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)
	score := 0

	repoPlatforms := make([]*gql_generated.OsArch, 0, len(repoPlatformsSet))
	for _, osArch := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, osArch)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	// We only scan the latest image on the repo for performance reasons
	// Check if vulnerability scanning is disabled
	if cveInfo != nil && lastUpdatedImageSummary != nil && !skip.Vulnerabilities {
		imageName := fmt.Sprintf("%s:%s", repoMeta.Name, *lastUpdatedImageSummary.Tag)

		imageCveSummary, err := cveInfo.GetCVESummaryForImage(imageName)
		if err != nil {
			// Log the error, but we should still include the image in results
			graphql.AddError(
				ctx,
				gqlerror.Errorf(
					"unable to run vulnerability scan on tag %s in repo %s: error: %s",
					*lastUpdatedImageSummary.Tag, repoMeta.Name, err.Error(),
				),
			)
		}

		lastUpdatedImageSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		}
	}

	return &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		Score:         &score,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &isBookmarked,
		IsStarred:     &isStarred,
	}
}

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, skip SkipQGLField, cveInfo cveinfo.CveInfo,
) []*gql_generated.ImageSummary {
	imageSummaries := make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))

	for tag, manifestDigest := range repoMeta.Tags {
		var manifestContent ispec.Manifest

		err := json.Unmarshal(manifestMetaMap[manifestDigest].ManifestBlob, &manifestContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, "+
				"manifest digest: %s, error: %s", repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		var configContent ispec.Image

		err = json.Unmarshal(manifestMetaMap[manifestDigest].ConfigBlob, &configContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal config blob for image: %s:%s, "+
				"manifest digest: %s, error: %s", repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		imageCveSummary := cveinfo.ImageCVESummary{}
		// Check if vulnerability scanning is disabled
		if cveInfo != nil && !skip.Vulnerabilities {
			imageName := fmt.Sprintf("%s:%s", repoMeta.Name, tag)
			imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

			if err != nil {
				// Log the error, but we should still include the manifest in results
				graphql.AddError(ctx, gqlerror.Errorf("unable to run vulnerability scan on tag %s in repo %s: "+
					"manifest digest: %s, error: %s", tag, repoMeta.Name, manifestDigest, err.Error()))
			}
		}

		imgSize := int64(0)
		imgSize += manifestContent.Config.Size
		imgSize += int64(len(manifestMetaMap[manifestDigest].ManifestBlob))

		for _, layer := range manifestContent.Layers {
			imgSize += layer.Size
		}

		var (
			repoName         = repoMeta.Name
			tag              = tag
			manifestDigest   = manifestDigest
			configDigest     = manifestContent.Config.Digest.String()
			imageLastUpdated = common.GetImageLastUpdated(configContent)
			isSigned         = imageHasSignatures(manifestMetaMap[manifestDigest].Signatures)
			imageSize        = strconv.FormatInt(imgSize, 10)
			os               = configContent.OS
			arch             = configContent.Architecture
			osArch           = gql_generated.OsArch{Os: &os, Arch: &arch}
			downloadCount    = manifestMetaMap[manifestDigest].DownloadCount
		)

		annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

		authors := annotations.Authors
		if authors == "" {
			authors = configContent.Author
		}

		historyEntries, err := getAllHistory(manifestContent, configContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
				"manifest digest: %s, error: %s", tag, repoMeta.Name, manifestDigest, err.Error()))
		}

		imageSummary := gql_generated.ImageSummary{
			RepoName:      &repoName,
			Tag:           &tag,
			Digest:        &manifestDigest,
			ConfigDigest:  &configDigest,
			LastUpdated:   &imageLastUpdated,
			IsSigned:      &isSigned,
			Size:          &imageSize,
			Platform:      &osArch,
			Vendor:        &annotations.Vendor,
			DownloadCount: &downloadCount,
			Layers:        getLayersSummaries(manifestContent),
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			Logo:          &annotations.Logo,
			Authors:       &authors,
			History:       historyEntries,
			Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
				MaxSeverity: &imageCveSummary.MaxSeverity,
				Count:       &imageCveSummary.Count,
			},
		}

		imageSummaries = append(imageSummaries, &imageSummary)
	}

	return imageSummaries
}

func RepoMeta2ExpandedRepoInfo(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, skip SkipQGLField, cveInfo cveinfo.CveInfo,
	isBookmarked bool, isStarred bool,
) (*gql_generated.RepoSummary, []*gql_generated.ImageSummary) {
	var (
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.OsArch{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoStarCount            = repoMeta.Stars
		// isBookmarked             = false
		// isStarred                = false
		repoDownloadCount = 0
		repoName          = repoMeta.Name

		// map used to keep track of all blobs of a repo without dublicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)

		imageSummaries = make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))
	)

	for tag, manifestDigest := range repoMeta.Tags {
		var manifestContent ispec.Manifest

		err := json.Unmarshal(manifestMetaMap[manifestDigest].ManifestBlob, &manifestContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
				"error: %s", repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		var configContent ispec.Image

		err = json.Unmarshal(manifestMetaMap[manifestDigest].ConfigBlob, &configContent)
		if err != nil {
			graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal config blob for image: %s:%s, manifest digest: %s, error: %s",
				repoMeta.Name, tag, manifestDigest, err.Error()))

			continue
		}

		var (
			tag              = tag
			isSigned         = len(manifestMetaMap[manifestDigest].Signatures) > 0
			configDigest     = manifestContent.Config.Digest.String()
			configSize       = manifestContent.Config.Size
			opSys            = configContent.OS
			arch             = configContent.Architecture
			osArch           = gql_generated.OsArch{Os: &opSys, Arch: &arch}
			imageLastUpdated = common.GetImageLastUpdated(configContent)
			downloadCount    = manifestMetaMap[manifestDigest].DownloadCount
			manifestDigest   = manifestDigest

			size = updateRepoBlobsMap(
				manifestDigest, int64(len(manifestMetaMap[manifestDigest].ManifestBlob)),
				configDigest, configSize,
				manifestContent.Layers,
				repoBlob2Size)
			imageSize = strconv.FormatInt(size, 10)
		)

		annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

		authors := annotations.Authors
		if authors == "" {
			authors = configContent.Author
		}

		imageCveSummary := cveinfo.ImageCVESummary{}

		imageSummary := gql_generated.ImageSummary{
			RepoName:      &repoName,
			Tag:           &tag,
			Digest:        &manifestDigest,
			ConfigDigest:  &configDigest,
			LastUpdated:   &imageLastUpdated,
			IsSigned:      &isSigned,
			Size:          &imageSize,
			Platform:      &osArch,
			Vendor:        &annotations.Vendor,
			DownloadCount: &downloadCount,
			Layers:        getLayersSummaries(manifestContent),
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			Logo:          &annotations.Logo,
			Authors:       &authors,
			Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
				MaxSeverity: &imageCveSummary.MaxSeverity,
				Count:       &imageCveSummary.Count,
			},
		}

		imageSummaries = append(imageSummaries, &imageSummary)

		if annotations.Vendor != "" {
			repoVendorsSet[annotations.Vendor] = true
		}

		if opSys != "" || arch != "" {
			osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
			repoPlatformsSet[osArchString] = &gql_generated.OsArch{Os: &opSys, Arch: &arch}
		}

		if repoLastUpdatedTimestamp.Equal(time.Time{}) {
			// initialize with first time value
			repoLastUpdatedTimestamp = imageLastUpdated
			lastUpdatedImageSummary = &imageSummary
		} else if repoLastUpdatedTimestamp.Before(imageLastUpdated) {
			repoLastUpdatedTimestamp = imageLastUpdated
			lastUpdatedImageSummary = &imageSummary
		}

		repoDownloadCount += manifestMetaMap[manifestDigest].DownloadCount
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)
	score := 0

	repoPlatforms := make([]*gql_generated.OsArch, 0, len(repoPlatformsSet))
	for _, osArch := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, osArch)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	// We only scan the latest image on the repo for performance reasons
	// Check if vulnerability scanning is disabled
	if cveInfo != nil && lastUpdatedImageSummary != nil && !skip.Vulnerabilities {
		imageName := fmt.Sprintf("%s:%s", repoMeta.Name, *lastUpdatedImageSummary.Tag)

		imageCveSummary, err := cveInfo.GetCVESummaryForImage(imageName)
		if err != nil {
			// Log the error, but we should still include the image in results
			graphql.AddError(
				ctx,
				gqlerror.Errorf(
					"unable to run vulnerability scan on tag %s in repo %s: error: %s",
					*lastUpdatedImageSummary.Tag, repoMeta.Name, err.Error(),
				),
			)
		}

		lastUpdatedImageSummary.Vulnerabilities = &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity: &imageCveSummary.MaxSeverity,
			Count:       &imageCveSummary.Count,
		}
	}

	summary := &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		Score:         &score,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &isBookmarked,
		IsStarred:     &isStarred,
	}

	return summary, imageSummaries
}

func GetPreloads(ctx context.Context) map[string]bool {
	if !graphql.HasOperationContext(ctx) {
		return map[string]bool{}
	}

	nestedPreloads := GetNestedPreloads(
		graphql.GetOperationContext(ctx),
		graphql.CollectFieldsCtx(ctx, nil),
		"",
	)

	preloads := map[string]bool{}

	for _, str := range nestedPreloads {
		preloads[str] = true
	}

	return preloads
}

func GetNestedPreloads(ctx *graphql.OperationContext, fields []graphql.CollectedField, prefix string,
) []string {
	preloads := []string{}

	for _, column := range fields {
		prefixColumn := GetPreloadString(prefix, column.Name)
		preloads = append(preloads, prefixColumn)
		preloads = append(preloads,
			GetNestedPreloads(ctx, graphql.CollectFields(ctx, column.Selections, nil), prefixColumn)...,
		)
	}

	return preloads
}

func GetPreloadString(prefix, name string) string {
	if len(prefix) > 0 {
		return prefix + "." + name
	}

	return name
}
