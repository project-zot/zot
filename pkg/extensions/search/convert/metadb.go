package convert

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/extensions/search/pagination"
	"zotregistry.io/zot/pkg/log"
	mcommon "zotregistry.io/zot/pkg/meta/common"
	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type SkipQGLField struct {
	Vulnerabilities bool
}

func RepoMeta2RepoSummary(ctx context.Context, repoMeta mTypes.RepoMetadata,
	manifestMetaMap map[string]mTypes.ManifestMetadata, indexDataMap map[string]mTypes.IndexData,
) *gql_generated.RepoSummary {
	var (
		repoName                 = repoMeta.Name
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.Platform{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoDownloadCount        = 0
		repoStarCount            = repoMeta.Stars        // total number of stars
		repoIsUserStarred        = repoMeta.IsStarred    // value specific to the current user
		repoIsUserBookMarked     = repoMeta.IsBookmarked // value specific to the current user

		// map used to keep track of all blobs of a repo without duplicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)
	)

	for tag, descriptor := range repoMeta.Tags {
		imageSummary, imageBlobsMap, err := Descriptor2ImageSummary(ctx, descriptor, repoMeta.Name,
			tag, repoMeta, manifestMetaMap, indexDataMap,
		)
		if err != nil {
			continue
		}

		for blobDigest, blobSize := range imageBlobsMap {
			repoBlob2Size[blobDigest] = blobSize
		}

		for _, manifestSummary := range imageSummary.Manifests {
			if *manifestSummary.Platform.Os != "" || *manifestSummary.Platform.Arch != "" {
				opSys, arch := *manifestSummary.Platform.Os, *manifestSummary.Platform.Arch

				platformString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
				repoPlatformsSet[platformString] = &gql_generated.Platform{Os: &opSys, Arch: &arch}
			}
		}

		repoDownloadCount += *imageSummary.DownloadCount

		if *imageSummary.Vendor != "" {
			repoVendorsSet[*imageSummary.Vendor] = true
		}

		lastUpdatedImageSummary = UpdateLastUpdatedTimestamp(&repoLastUpdatedTimestamp, lastUpdatedImageSummary, imageSummary)
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)

	repoPlatforms := make([]*gql_generated.Platform, 0, len(repoPlatformsSet))

	for _, platform := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, platform)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	return &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &repoIsUserBookMarked,
		IsStarred:     &repoIsUserStarred,
		Rank:          &repoMeta.Rank,
	}
}

func PaginatedRepoMeta2RepoSummaries(ctx context.Context, reposMeta []mTypes.RepoMetadata,
	manifestMetaMap map[string]mTypes.ManifestMetadata, indexDataMap map[string]mTypes.IndexData,
	skip SkipQGLField, cveInfo cveinfo.CveInfo, filter mTypes.Filter, pageInput pagination.PageInput,
) ([]*gql_generated.RepoSummary, zcommon.PageInfo, error) {
	reposPageFinder, err := pagination.NewRepoSumPageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy)
	if err != nil {
		return []*gql_generated.RepoSummary{}, zcommon.PageInfo{}, err
	}

	for _, repoMeta := range reposMeta {
		repoSummary := RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, indexDataMap)

		if RepoSumAcceptedByFilter(repoSummary, filter) {
			reposPageFinder.Add(repoSummary)
		}
	}

	page, pageInfo := reposPageFinder.Page()

	// CVE scanning is expensive, only scan for the current page
	for _, repoSummary := range page {
		updateRepoSummaryVulnerabilities(ctx, repoSummary, skip, cveInfo)
	}

	return page, pageInfo, nil
}

func UpdateLastUpdatedTimestamp(repoLastUpdatedTimestamp *time.Time,
	lastUpdatedImageSummary *gql_generated.ImageSummary, imageSummary *gql_generated.ImageSummary,
) *gql_generated.ImageSummary {
	newLastUpdatedImageSummary := lastUpdatedImageSummary

	if repoLastUpdatedTimestamp.Equal(time.Time{}) {
		// initialize with first time value
		*repoLastUpdatedTimestamp = *imageSummary.LastUpdated
		newLastUpdatedImageSummary = imageSummary
	} else if repoLastUpdatedTimestamp.Before(*imageSummary.LastUpdated) {
		*repoLastUpdatedTimestamp = *imageSummary.LastUpdated
		newLastUpdatedImageSummary = imageSummary
	}

	return newLastUpdatedImageSummary
}

func Descriptor2ImageSummary(ctx context.Context, descriptor mTypes.Descriptor, repo, tag string,
	repoMeta mTypes.RepoMetadata, manifestMetaMap map[string]mTypes.ManifestMetadata,
	indexDataMap map[string]mTypes.IndexData,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	switch descriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		return ImageManifest2ImageSummary(ctx, repo, tag, godigest.Digest(descriptor.Digest),
			repoMeta, manifestMetaMap[descriptor.Digest])
	case ispec.MediaTypeImageIndex:
		return ImageIndex2ImageSummary(ctx, repo, tag, godigest.Digest(descriptor.Digest),
			repoMeta, indexDataMap[descriptor.Digest], manifestMetaMap)
	default:
		return &gql_generated.ImageSummary{}, map[string]int64{}, zerr.ErrMediaTypeNotSupported
	}
}

func ImageIndex2ImageSummary(ctx context.Context, repo, tag string, indexDigest godigest.Digest,
	repoMeta mTypes.RepoMetadata, indexData mTypes.IndexData, manifestMetaMap map[string]mTypes.ManifestMetadata,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return &gql_generated.ImageSummary{}, map[string]int64{}, err
	}

	var (
		indexLastUpdated    time.Time
		isSigned            bool
		totalIndexSize      int64
		indexSize           string
		totalDownloadCount  int
		manifestAnnotations *ImageAnnotations
		manifestSummaries   = make([]*gql_generated.ManifestSummary, 0, len(indexContent.Manifests))
		indexBlobs          = make(map[string]int64, 0)

		indexDigestStr = indexDigest.String()
		indexMediaType = ispec.MediaTypeImageIndex
	)

	for _, descriptor := range indexContent.Manifests {
		manifestSummary, manifestBlobs, annotations, err := ImageManifest2ManifestSummary(ctx, repo, tag, descriptor,
			repoMeta, manifestMetaMap[descriptor.Digest.String()], repoMeta.Referrers[descriptor.Digest.String()])
		if err != nil {
			return &gql_generated.ImageSummary{}, map[string]int64{}, err
		}

		manifestSize := int64(0)

		for digest, size := range manifestBlobs {
			indexBlobs[digest] = size
			manifestSize += size
		}

		if indexLastUpdated.Before(*manifestSummary.LastUpdated) {
			indexLastUpdated = *manifestSummary.LastUpdated
		}

		if manifestAnnotations == nil {
			manifestAnnotations = annotations
		}

		totalIndexSize += manifestSize

		manifestSummaries = append(manifestSummaries, manifestSummary)
	}

	totalDownloadCount += repoMeta.Statistics[indexDigestStr].DownloadCount

	for _, signatures := range repoMeta.Signatures[indexDigest.String()] {
		if len(signatures) > 0 {
			isSigned = true
		}
	}

	indexSize = strconv.FormatInt(totalIndexSize, 10)

	signaturesInfo := GetSignaturesInfo(isSigned, repoMeta, indexDigest)

	if manifestAnnotations == nil {
		// The index doesn't have manifests
		manifestAnnotations = &ImageAnnotations{}
	}

	annotations := GetIndexAnnotations(indexContent.Annotations, manifestAnnotations)

	indexSummary := gql_generated.ImageSummary{
		RepoName:      &repo,
		Tag:           &tag,
		Digest:        &indexDigestStr,
		MediaType:     &indexMediaType,
		Manifests:     manifestSummaries,
		LastUpdated:   &indexLastUpdated,
		IsSigned:      &isSigned,
		SignatureInfo: signaturesInfo,
		Size:          &indexSize,
		DownloadCount: &totalDownloadCount,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		Vendor:        &annotations.Vendor,
		Authors:       &annotations.Authors,
		Referrers:     getReferrers(repoMeta.Referrers[indexDigest.String()]),
	}

	return &indexSummary, indexBlobs, nil
}

func ImageManifest2ImageSummary(ctx context.Context, repo, tag string, digest godigest.Digest,
	repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata,
) (*gql_generated.ImageSummary, map[string]int64, error) {
	var (
		manifestContent ispec.Manifest
		manifestDigest  = digest.String()
		mediaType       = ispec.MediaTypeImageManifest
	)

	err := json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
			"error: %s", repo, tag, manifestDigest, err.Error()))

		return &gql_generated.ImageSummary{}, map[string]int64{}, err
	}

	configContent := mcommon.InitializeImageConfig(manifestMeta.ConfigBlob)

	var (
		repoName         = repo
		configDigest     = manifestContent.Config.Digest.String()
		configSize       = manifestContent.Config.Size
		artifactType     = zcommon.GetManifestArtifactType(manifestContent)
		imageLastUpdated = zcommon.GetImageLastUpdated(configContent)
		downloadCount    = repoMeta.Statistics[digest.String()].DownloadCount
		isSigned         = false
	)

	opSys := configContent.OS
	arch := configContent.Architecture
	variant := configContent.Variant

	if variant != "" {
		arch = arch + "/" + variant
	}

	platform := gql_generated.Platform{Os: &opSys, Arch: &arch}

	for _, signatures := range repoMeta.Signatures[digest.String()] {
		if len(signatures) > 0 {
			isSigned = true
		}
	}

	size, imageBlobsMap := getImageBlobsInfo(
		manifestDigest, int64(len(manifestMeta.ManifestBlob)),
		configDigest, configSize,
		manifestContent.Layers)
	imageSize := strconv.FormatInt(size, 10)

	annotations := GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

	authors := annotations.Authors
	if authors == "" {
		authors = configContent.Author
	}

	historyEntries, err := getAllHistory(manifestContent, configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
			"manifest digest: %s, error: %s", tag, repo, manifestDigest, err.Error()))
	}

	signaturesInfo := GetSignaturesInfo(isSigned, repoMeta, digest)

	manifestSummary := gql_generated.ManifestSummary{
		Digest:        &manifestDigest,
		ConfigDigest:  &configDigest,
		LastUpdated:   &imageLastUpdated,
		Size:          &imageSize,
		IsSigned:      &isSigned,
		SignatureInfo: signaturesInfo,
		Platform:      &platform,
		DownloadCount: &downloadCount,
		Layers:        getLayersSummaries(manifestContent),
		History:       historyEntries,
		Referrers:     getReferrers(repoMeta.Referrers[manifestDigest]),
		ArtifactType:  &artifactType,
	}

	imageSummary := gql_generated.ImageSummary{
		RepoName:      &repoName,
		Tag:           &tag,
		Digest:        &manifestDigest,
		MediaType:     &mediaType,
		Manifests:     []*gql_generated.ManifestSummary{&manifestSummary},
		LastUpdated:   &imageLastUpdated,
		IsSigned:      &isSigned,
		SignatureInfo: signaturesInfo,
		Size:          &imageSize,
		DownloadCount: &downloadCount,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		Vendor:        &annotations.Vendor,
		Authors:       &authors,
		Referrers:     getReferrers(repoMeta.Referrers[manifestDigest]),
	}

	return &imageSummary, imageBlobsMap, nil
}

func getReferrers(referrersInfo []mTypes.ReferrerInfo) []*gql_generated.Referrer {
	referrers := make([]*gql_generated.Referrer, 0, len(referrersInfo))

	for _, referrerInfo := range referrersInfo {
		referrerInfo := referrerInfo

		referrers = append(referrers, &gql_generated.Referrer{
			MediaType:    &referrerInfo.MediaType,
			ArtifactType: &referrerInfo.ArtifactType,
			Size:         &referrerInfo.Size,
			Digest:       &referrerInfo.Digest,
			Annotations:  getAnnotationsFromMap(referrerInfo.Annotations),
		})
	}

	return referrers
}

func getAnnotationsFromMap(annotationsMap map[string]string) []*gql_generated.Annotation {
	annotations := make([]*gql_generated.Annotation, 0, len(annotationsMap))

	for key, value := range annotationsMap {
		key := key
		value := value

		annotations = append(annotations, &gql_generated.Annotation{
			Key:   &key,
			Value: &value,
		})
	}

	return annotations
}

func ImageManifest2ManifestSummary(ctx context.Context, repo, tag string, descriptor ispec.Descriptor,
	repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata,
	referrersInfo []mTypes.ReferrerInfo,
) (*gql_generated.ManifestSummary, map[string]int64, *ImageAnnotations, error) {
	var (
		manifestContent ispec.Manifest
		digest          = descriptor.Digest
	)

	err := json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("can't unmarshal manifest blob for image: %s:%s, manifest digest: %s, "+
			"error: %s", repo, tag, digest, err.Error()))

		return &gql_generated.ManifestSummary{}, map[string]int64{}, &ImageAnnotations{}, err
	}

	configContent := mcommon.InitializeImageConfig(manifestMeta.ConfigBlob)
	annotations := GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

	var (
		manifestDigestStr = digest.String()
		configDigest      = manifestContent.Config.Digest.String()
		configSize        = manifestContent.Config.Size
		artifactType      = zcommon.GetManifestArtifactType(manifestContent)
		imageLastUpdated  = zcommon.GetImageLastUpdated(configContent)
		downloadCount     = repoMeta.Statistics[digest.String()].DownloadCount
		isSigned          = false
	)

	opSys := configContent.OS
	arch := configContent.Architecture
	variant := configContent.Variant

	if variant != "" {
		arch = arch + "/" + variant
	}

	platform := gql_generated.Platform{Os: &opSys, Arch: &arch}

	size, imageBlobsMap := getImageBlobsInfo(
		manifestDigestStr, int64(len(manifestMeta.ManifestBlob)),
		configDigest, configSize,
		manifestContent.Layers)
	imageSize := strconv.FormatInt(size, 10)

	historyEntries, err := getAllHistory(manifestContent, configContent)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
			"manifest digest: %s, error: %s", tag, repo, manifestDigestStr, err.Error()))
	}

	for _, signatures := range repoMeta.Signatures[manifestDigestStr] {
		if len(signatures) > 0 {
			isSigned = true
		}
	}

	signaturesInfo := GetSignaturesInfo(isSigned, repoMeta, digest)

	manifestSummary := gql_generated.ManifestSummary{
		Digest:        &manifestDigestStr,
		ConfigDigest:  &configDigest,
		LastUpdated:   &imageLastUpdated,
		Size:          &imageSize,
		Platform:      &platform,
		DownloadCount: &downloadCount,
		Layers:        getLayersSummaries(manifestContent),
		History:       historyEntries,
		IsSigned:      &isSigned,
		SignatureInfo: signaturesInfo,
		Referrers:     getReferrers(referrersInfo),
		ArtifactType:  &artifactType,
	}

	return &manifestSummary, imageBlobsMap, &annotations, nil
}

func getImageBlobsInfo(manifestDigest string, manifestSize int64, configDigest string, configSize int64,
	layers []ispec.Descriptor,
) (int64, map[string]int64) {
	imageBlobsMap := map[string]int64{}
	imageSize := int64(0)

	// add config size
	imageSize += configSize
	imageBlobsMap[configDigest] = configSize

	// add manifest size
	imageSize += manifestSize
	imageBlobsMap[manifestDigest] = manifestSize

	// add layers size
	for _, layer := range layers {
		imageBlobsMap[layer.Digest.String()] = layer.Size
		imageSize += layer.Size
	}

	return imageSize, imageBlobsMap
}

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta mTypes.RepoMetadata,
	manifestMetaMap map[string]mTypes.ManifestMetadata, indexDataMap map[string]mTypes.IndexData,
	skip SkipQGLField, cveInfo cveinfo.CveInfo,
) []*gql_generated.ImageSummary {
	imageSummaries := make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))

	// Make sure the tags are sorted
	// We need to implement a proper fix for this taking into account
	// the sorting criteria used in the requested page
	tags := make([]string, 0, len(repoMeta.Tags))
	for tag := range repoMeta.Tags {
		tags = append(tags, tag)
	}

	// Sorting ascending by tag name should do for now
	sort.Strings(tags)

	for _, tag := range tags {
		descriptor := repoMeta.Tags[tag]

		imageSummary, _, err := Descriptor2ImageSummary(ctx, descriptor, repoMeta.Name, tag,
			repoMeta, manifestMetaMap, indexDataMap)
		if err != nil {
			continue
		}

		// CVE scanning is expensive, only scan for final slice of results
		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)

		imageSummaries = append(imageSummaries, imageSummary)
	}

	return imageSummaries
}

func PaginatedRepoMeta2ImageSummaries(ctx context.Context, reposMeta []mTypes.RepoMetadata,
	manifestMetaMap map[string]mTypes.ManifestMetadata, indexDataMap map[string]mTypes.IndexData,
	skip SkipQGLField, cveInfo cveinfo.CveInfo, filter mTypes.Filter, pageInput pagination.PageInput,
) ([]*gql_generated.ImageSummary, zcommon.PageInfo, error) {
	imagePageFinder, err := pagination.NewImgSumPageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy)
	if err != nil {
		return []*gql_generated.ImageSummary{}, zcommon.PageInfo{}, err
	}

	for _, repoMeta := range reposMeta {
		for tag := range repoMeta.Tags {
			descriptor := repoMeta.Tags[tag]

			imageSummary, _, err := Descriptor2ImageSummary(ctx, descriptor, repoMeta.Name, tag,
				repoMeta, manifestMetaMap, indexDataMap)
			if err != nil {
				continue
			}

			if ImgSumAcceptedByFilter(imageSummary, filter) {
				imagePageFinder.Add(imageSummary)
			}
		}
	}

	page, pageInfo := imagePageFinder.Page()

	for _, imageSummary := range page {
		// CVE scanning is expensive, only scan for this page
		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)
	}

	return page, pageInfo, nil
}

func RepoMeta2ExpandedRepoInfo(ctx context.Context, repoMeta mTypes.RepoMetadata,
	manifestMetaMap map[string]mTypes.ManifestMetadata, indexDataMap map[string]mTypes.IndexData,
	skip SkipQGLField, cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.RepoSummary, []*gql_generated.ImageSummary) {
	var (
		repoName                 = repoMeta.Name
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.Platform{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoDownloadCount        = 0
		repoStarCount            = repoMeta.Stars        // total number of stars
		isStarred                = repoMeta.IsStarred    // value specific to the current user
		isBookmarked             = repoMeta.IsBookmarked // value specific to the current user

		// map used to keep track of all blobs of a repo without duplicates as
		// some images may have the same layers
		repoBlob2Size = make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		size = int64(0)

		imageSummaries = make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))
	)

	for tag, descriptor := range repoMeta.Tags {
		imageSummary, imageBlobs, err := Descriptor2ImageSummary(ctx, descriptor, repoName, tag,
			repoMeta, manifestMetaMap, indexDataMap)
		if err != nil {
			log.Error().Str("repository", repoName).Str("reference", tag).
				Msg("metadb: error while converting descriptor for image")

			continue
		}

		for _, manifestSummary := range imageSummary.Manifests {
			opSys, arch := *manifestSummary.Platform.Os, *manifestSummary.Platform.Arch
			if opSys != "" || arch != "" {
				platformString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
				repoPlatformsSet[platformString] = &gql_generated.Platform{Os: &opSys, Arch: &arch}
			}

			updateRepoBlobsMap(imageBlobs, repoBlob2Size)
		}

		if *imageSummary.Vendor != "" {
			repoVendorsSet[*imageSummary.Vendor] = true
		}

		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)

		lastUpdatedImageSummary = UpdateLastUpdatedTimestamp(&repoLastUpdatedTimestamp, lastUpdatedImageSummary, imageSummary)

		repoDownloadCount += *imageSummary.DownloadCount

		imageSummaries = append(imageSummaries, imageSummary)
	}

	// calculate repo size = sum all manifest, config and layer blobs sizes
	for _, blobSize := range repoBlob2Size {
		size += blobSize
	}

	repoSize := strconv.FormatInt(size, 10)

	repoPlatforms := make([]*gql_generated.Platform, 0, len(repoPlatformsSet))

	for _, platform := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, platform)
	}

	repoVendors := make([]*string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, &vendor)
	}

	summary := &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   &repoLastUpdatedTimestamp,
		Size:          &repoSize,
		Platforms:     repoPlatforms,
		Vendors:       repoVendors,
		NewestImage:   lastUpdatedImageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &isBookmarked,
		IsStarred:     &isStarred,
	}

	updateRepoSummaryVulnerabilities(ctx, summary, skip, cveInfo)

	return summary, imageSummaries
}

func StringMap2Annotations(strMap map[string]string) []*gql_generated.Annotation {
	annotations := make([]*gql_generated.Annotation, 0, len(strMap))

	for key, value := range strMap {
		key := key
		value := value

		annotations = append(annotations, &gql_generated.Annotation{
			Key:   &key,
			Value: &value,
		})
	}

	return annotations
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

func GetSignaturesInfo(isSigned bool, repoMeta mTypes.RepoMetadata, indexDigest godigest.Digest,
) []*gql_generated.SignatureSummary {
	signaturesInfo := []*gql_generated.SignatureSummary{}

	if !isSigned {
		return signaturesInfo
	}

	for sigType, signatures := range repoMeta.Signatures[indexDigest.String()] {
		for _, sig := range signatures {
			for _, layer := range sig.LayersInfo {
				var (
					isTrusted bool
					author    string
					tool      string
				)

				if layer.Signer != "" {
					author = layer.Signer

					if !layer.Date.IsZero() && time.Now().After(layer.Date) {
						isTrusted = false
					} else {
						isTrusted = true
					}
				} else {
					isTrusted = false
					author = ""
				}

				tool = sigType

				signaturesInfo = append(signaturesInfo,
					&gql_generated.SignatureSummary{Tool: &tool, IsTrusted: &isTrusted, Author: &author})
			}
		}
	}

	return signaturesInfo
}
