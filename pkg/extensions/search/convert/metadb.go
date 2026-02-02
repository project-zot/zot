package convert

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/99designs/gqlgen/graphql"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	cveinfo "zotregistry.dev/zot/v2/pkg/extensions/search/cve"
	"zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/v2/pkg/extensions/search/pagination"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

type SkipQGLField struct {
	Vulnerabilities bool
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

func getReferrers(referrersInfo []mTypes.ReferrerInfo) []*gql_generated.Referrer {
	referrers := make([]*gql_generated.Referrer, 0, len(referrersInfo))

	for _, referrerInfo := range referrersInfo {
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
		annotations = append(annotations, &gql_generated.Annotation{
			Key:   &key,
			Value: &value,
		})
	}

	return annotations
}

func getImageBlobsInfo(manifestDigest string, manifestSize int64, configDigest string, configSize int64,
	layers []ispec.Descriptor,
) (int64, map[string]int64) {
	// Pre-allocate map with known size: config + manifest + layers
	imageBlobsMap := make(map[string]int64, 2+len(layers))
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

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta mTypes.RepoMeta,
	imageMeta map[string]mTypes.ImageMeta, skip SkipQGLField, cveInfo cveinfo.CveInfo,
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

		imageSummary, _, err := FullImageMeta2ImageSummary(ctx, GetFullImageMeta(tag, repoMeta, imageMeta[descriptor.Digest]))
		if err != nil {
			continue
		}

		// CVE scanning is expensive, only scan for final slice of results
		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)

		imageSummaries = append(imageSummaries, imageSummary)
	}

	return imageSummaries
}

func RepoMeta2ExpandedRepoInfo(ctx context.Context, repoMeta mTypes.RepoMeta,
	imageMetaMap map[string]mTypes.ImageMeta, skip SkipQGLField, cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.RepoSummary, []*gql_generated.ImageSummary) {
	repoName := repoMeta.Name
	imageSummaries := make([]*gql_generated.ImageSummary, 0, len(repoMeta.Tags))

	userCanDeleteTag, _ := reqCtx.CanDelete(ctx, repoName)

	for tag, descriptor := range repoMeta.Tags {
		imageMeta := imageMetaMap[descriptor.Digest]

		imageSummary, _, err := FullImageMeta2ImageSummary(ctx, GetFullImageMeta(tag, repoMeta, imageMeta))
		if err != nil {
			log.Error().Str("repository", repoName).Str("reference", tag).Str("component", "metadb").
				Msg("error while converting descriptor for image")

			continue
		}

		imageSummary.IsDeletable = &userCanDeleteTag

		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)

		imageSummaries = append(imageSummaries, imageSummary)
	}

	repoSummary := RepoMeta2RepoSummary(ctx, repoMeta, imageMetaMap)

	updateRepoSummaryVulnerabilities(ctx, repoSummary, skip, cveInfo)

	return repoSummary, imageSummaries
}

func GetFullImageMeta(tag string, repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta,
) mTypes.FullImageMeta {
	taggedTimestamp := time.Time{}
	if descriptor, ok := repoMeta.Tags[tag]; ok {
		taggedTimestamp = descriptor.TaggedTimestamp
	}

	return mTypes.FullImageMeta{
		Repo:            repoMeta.Name,
		Tag:             tag,
		MediaType:       imageMeta.MediaType,
		Digest:          imageMeta.Digest,
		Size:            imageMeta.Size,
		Index:           imageMeta.Index,
		Manifests:       GetFullManifestMeta(repoMeta, imageMeta.Manifests),
		Referrers:       repoMeta.Referrers[imageMeta.Digest.String()],
		Statistics:      repoMeta.Statistics[imageMeta.Digest.String()],
		Signatures:      repoMeta.Signatures[imageMeta.Digest.String()],
		TaggedTimestamp: taggedTimestamp,
	}
}

func GetFullManifestMeta(repoMeta mTypes.RepoMeta, manifests []mTypes.ManifestMeta) []mTypes.FullManifestMeta {
	results := make([]mTypes.FullManifestMeta, 0, len(manifests))

	for i := range manifests {
		results = append(results, mTypes.FullManifestMeta{
			ManifestMeta: manifests[i],
			Referrers:    repoMeta.Referrers[manifests[i].Digest.String()],
			Statistics:   repoMeta.Statistics[manifests[i].Digest.String()],
			Signatures:   repoMeta.Signatures[manifests[i].Digest.String()],
		})
	}

	return results
}

func StringMap2Annotations(strMap map[string]string) []*gql_generated.Annotation {
	annotations := make([]*gql_generated.Annotation, 0, len(strMap))

	for key, value := range strMap {
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

func GetSignaturesInfo(isSigned bool, signatures mTypes.ManifestSignatures) []*gql_generated.SignatureSummary {
	signaturesInfo := []*gql_generated.SignatureSummary{}

	if !isSigned {
		return signaturesInfo
	}

	for sigType, signatures := range signatures {
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

func PaginatedRepoMeta2RepoSummaries(ctx context.Context, repoMetaList []mTypes.RepoMeta,
	imageMetaMap map[string]mTypes.ImageMeta, filter mTypes.Filter, pageInput pagination.PageInput,
	cveInfo cveinfo.CveInfo, skip SkipQGLField,
) ([]*gql_generated.RepoSummary, zcommon.PageInfo, error) {
	reposPageFinder, err := pagination.NewRepoSumPageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy)
	if err != nil {
		return []*gql_generated.RepoSummary{}, zcommon.PageInfo{}, err
	}

	for _, repoMeta := range repoMetaList {
		repoSummary := RepoMeta2RepoSummary(ctx, repoMeta, imageMetaMap)

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

func RepoMeta2RepoSummary(ctx context.Context, repoMeta mTypes.RepoMeta,
	imageMetaMap map[string]mTypes.ImageMeta,
) *gql_generated.RepoSummary {
	var (
		repoName                 = repoMeta.Name
		lastUpdatedImage         = deref(repoMeta.LastUpdatedImage, mTypes.LastUpdatedImage{})
		lastUpdatedImageMeta     = imageMetaMap[lastUpdatedImage.Digest]
		lastUpdatedTag           = lastUpdatedImage.Tag
		repoLastUpdatedTimestamp = lastUpdatedImage.LastUpdated
		repoPlatforms            = repoMeta.Platforms
		repoVendors              = repoMeta.Vendors
		repoDownloadCount        = repoMeta.DownloadCount
		repoStarCount            = repoMeta.StarCount
		repoIsUserStarred        = repoMeta.IsStarred    // value specific to the current user
		repoIsUserBookMarked     = repoMeta.IsBookmarked // value specific to the current user
		repoSize                 = repoMeta.Size
	)

	if repoLastUpdatedTimestamp == nil {
		repoLastUpdatedTimestamp = &time.Time{}
	}

	imageSummary, _, err := FullImageMeta2ImageSummary(ctx, GetFullImageMeta(lastUpdatedTag, repoMeta,
		lastUpdatedImageMeta))
	_ = err

	return &gql_generated.RepoSummary{
		Name:          &repoName,
		LastUpdated:   repoLastUpdatedTimestamp,
		Size:          ref(strconv.FormatInt(repoSize, 10)),
		Platforms:     getGqlPlatforms(repoPlatforms),
		Vendors:       getGqlVendors(repoVendors),
		NewestImage:   imageSummary,
		DownloadCount: &repoDownloadCount,
		StarCount:     &repoStarCount,
		IsBookmarked:  &repoIsUserBookMarked,
		IsStarred:     &repoIsUserStarred,
		Rank:          ref(repoMeta.Rank),
	}
}

func getGqlVendors(repoVendors []string) []*string {
	result := make([]*string, 0, len(repoVendors))

	for i := range repoVendors {
		result = append(result, &repoVendors[i])
	}

	return result
}

func getGqlPlatforms(repoPlatforms []ispec.Platform) []*gql_generated.Platform {
	result := make([]*gql_generated.Platform, 0, len(repoPlatforms))

	for i := range repoPlatforms {
		result = append(result, &gql_generated.Platform{
			Os:   ref(repoPlatforms[i].OS),
			Arch: ref(getArch(repoPlatforms[i].Architecture, repoPlatforms[i].Variant)),
		})
	}

	return result
}

type (
	ManifestDigest = string
	BlobDigest     = string
)

func FullImageMeta2ImageSummary(ctx context.Context, fullImageMeta mTypes.FullImageMeta,
) (*gql_generated.ImageSummary, map[BlobDigest]int64, error) {
	switch fullImageMeta.MediaType {
	case ispec.MediaTypeImageManifest:
		return ImageManifest2ImageSummary(ctx, fullImageMeta)
	case ispec.MediaTypeImageIndex:
		return ImageIndex2ImageSummary(ctx, fullImageMeta)
	default:
		return nil, nil, zerr.ErrMediaTypeNotSupported
	}
}

func ImageIndex2ImageSummary(ctx context.Context, fullImageMeta mTypes.FullImageMeta,
) (*gql_generated.ImageSummary, map[BlobDigest]int64, error) {
	var (
		repo                = fullImageMeta.Repo
		tag                 = fullImageMeta.Tag
		indexLastUpdated    time.Time
		isSigned            = isImageSigned(fullImageMeta.Signatures)
		indexSize           = int64(0)
		manifestAnnotations *ImageAnnotations
		manifestSummaries   = make([]*gql_generated.ManifestSummary, 0, len(fullImageMeta.Manifests))
		indexBlobs          = map[string]int64{}

		indexDigestStr  = fullImageMeta.Digest.String()
		indexMediaType  = ispec.MediaTypeImageIndex
		pushTimestamp   = fullImageMeta.Statistics.PushTimestamp
		taggedTimestamp = fullImageMeta.TaggedTimestamp
	)

	// Fallback to PushTimestamp if TaggedTimestamp is not available
	if taggedTimestamp.IsZero() {
		taggedTimestamp = pushTimestamp
	}

	for _, imageManifest := range fullImageMeta.Manifests {
		imageManifestSummary, manifestBlobs, err := ImageManifest2ImageSummary(ctx, mTypes.FullImageMeta{
			Repo:            fullImageMeta.Repo,
			Tag:             fullImageMeta.Tag,
			MediaType:       ispec.MediaTypeImageManifest,
			Digest:          imageManifest.Digest,
			Size:            imageManifest.Size,
			Manifests:       []mTypes.FullManifestMeta{imageManifest},
			Referrers:       imageManifest.Referrers,
			Statistics:      imageManifest.Statistics,
			Signatures:      imageManifest.Signatures,
			TaggedTimestamp: fullImageMeta.TaggedTimestamp,
		})
		if err != nil {
			return &gql_generated.ImageSummary{}, map[string]int64{}, err
		}

		manifestSize := int64(0)

		for digest, size := range manifestBlobs {
			indexBlobs[digest] = size
			manifestSize += size
		}

		if indexLastUpdated.Before(*imageManifestSummary.LastUpdated) {
			indexLastUpdated = *imageManifestSummary.LastUpdated
		}

		annotations := GetAnnotations(imageManifest.Manifest.Annotations, imageManifest.Config.Config.Labels)
		if manifestAnnotations == nil {
			manifestAnnotations = &annotations
		}

		indexSize += manifestSize

		manifestSummaries = append(manifestSummaries, imageManifestSummary.Manifests[0])
	}

	signaturesInfo := GetSignaturesInfo(isSigned, fullImageMeta.Signatures)

	if manifestAnnotations == nil {
		manifestAnnotations = &ImageAnnotations{}
	}

	annotations := GetIndexAnnotations(fullImageMeta.Index.Annotations, manifestAnnotations)

	imageLastUpdated := annotations.Created
	if imageLastUpdated == nil {
		imageLastUpdated = &indexLastUpdated
	}

	indexSummary := gql_generated.ImageSummary{
		RepoName:        &repo,
		Tag:             &tag,
		Digest:          &indexDigestStr,
		MediaType:       &indexMediaType,
		Manifests:       manifestSummaries,
		LastUpdated:     imageLastUpdated,
		IsSigned:        &isSigned,
		SignatureInfo:   signaturesInfo,
		Size:            ref(strconv.FormatInt(indexSize, 10)),
		DownloadCount:   ref(fullImageMeta.Statistics.DownloadCount),
		PushTimestamp:   &pushTimestamp,
		TaggedTimestamp: &taggedTimestamp,
		Description:     &annotations.Description,
		Title:           &annotations.Title,
		Documentation:   &annotations.Documentation,
		Licenses:        &annotations.Licenses,
		Labels:          &annotations.Labels,
		Source:          &annotations.Source,
		Vendor:          &annotations.Vendor,
		Authors:         &annotations.Authors,
		Referrers:       getReferrers(fullImageMeta.Referrers),
	}

	return &indexSummary, indexBlobs, nil
}

func ImageManifest2ImageSummary(ctx context.Context, fullImageMeta mTypes.FullImageMeta,
) (*gql_generated.ImageSummary, map[BlobDigest]int64, error) {
	manifest := fullImageMeta.Manifests[0]

	var (
		repoName          = fullImageMeta.Repo
		tag               = fullImageMeta.Tag
		configDigest      = manifest.Manifest.Config.Digest.String()
		configSize        = manifest.Manifest.Config.Size
		manifestDigest    = manifest.Digest.String()
		manifestSize      = manifest.Size
		mediaType         = manifest.Manifest.MediaType
		artifactType      = zcommon.GetManifestArtifactType(fullImageMeta.Manifests[0].Manifest)
		platform          = getPlatform(manifest.Config.Platform)
		downloadCount     = fullImageMeta.Statistics.DownloadCount
		isSigned          = isImageSigned(fullImageMeta.Signatures)
		lastPullTimestamp = fullImageMeta.Statistics.LastPullTimestamp
		pushTimestamp     = fullImageMeta.Statistics.PushTimestamp
		taggedTimestamp   = fullImageMeta.TaggedTimestamp
	)

	// Fallback to PushTimestamp if TaggedTimestamp is not available
	if taggedTimestamp.IsZero() {
		taggedTimestamp = pushTimestamp
	}

	imageSize, imageBlobsMap := getImageBlobsInfo(manifestDigest, manifestSize, configDigest, configSize,
		manifest.Manifest.Layers)
	imageSizeStr := strconv.FormatInt(imageSize, 10)
	annotations := GetAnnotations(manifest.Manifest.Annotations, manifest.Config.Config.Labels)

	authors := annotations.Authors
	if authors == "" {
		authors = manifest.Config.Author
	}

	imageLastUpdated := annotations.Created
	if imageLastUpdated == nil {
		configCreated := zcommon.GetImageLastUpdated(manifest.Config)
		imageLastUpdated = &configCreated
	}

	historyEntries, err := getAllHistory(manifest.Manifest, manifest.Config)
	if err != nil {
		graphql.AddError(ctx, gqlerror.Errorf("error generating history on tag %s in repo %s: "+
			"manifest digest: %s, error: %s", tag, repoName, manifest.Digest, err.Error()))
	}

	signaturesInfo := GetSignaturesInfo(isSigned, fullImageMeta.Signatures)

	manifestSummary := gql_generated.ManifestSummary{
		Digest:        &manifestDigest,
		ConfigDigest:  &configDigest,
		LastUpdated:   imageLastUpdated,
		Size:          &imageSizeStr,
		IsSigned:      &isSigned,
		SignatureInfo: signaturesInfo,
		Platform:      &platform,
		DownloadCount: &downloadCount,
		Layers:        getLayersSummaries(manifest.Manifest),
		History:       historyEntries,
		Referrers:     getReferrers(fullImageMeta.Referrers),
		ArtifactType:  &artifactType,
	}

	imageSummary := gql_generated.ImageSummary{
		RepoName:          &repoName,
		Tag:               &tag,
		Digest:            &manifestDigest,
		MediaType:         &mediaType,
		Manifests:         []*gql_generated.ManifestSummary{&manifestSummary},
		LastUpdated:       imageLastUpdated,
		IsSigned:          &isSigned,
		SignatureInfo:     signaturesInfo,
		Size:              &imageSizeStr,
		DownloadCount:     &downloadCount,
		LastPullTimestamp: &lastPullTimestamp,
		PushTimestamp:     &pushTimestamp,
		TaggedTimestamp:   &taggedTimestamp,
		Description:       &annotations.Description,
		Title:             &annotations.Title,
		Documentation:     &annotations.Documentation,
		Licenses:          &annotations.Licenses,
		Labels:            &annotations.Labels,
		Source:            &annotations.Source,
		Vendor:            &annotations.Vendor,
		Authors:           &authors,
		Referrers:         manifestSummary.Referrers,
	}

	return &imageSummary, imageBlobsMap, nil
}

func isImageSigned(manifestSignatures mTypes.ManifestSignatures) bool {
	for _, signatures := range manifestSignatures {
		if len(signatures) > 0 {
			return true
		}
	}

	return false
}

func getPlatform(platform ispec.Platform) gql_generated.Platform {
	return gql_generated.Platform{
		Os:   ref(platform.OS),
		Arch: ref(getArch(platform.Architecture, platform.Variant)),
	}
}

func getArch(arch string, variant string) string {
	if variant != "" {
		arch = arch + "/" + variant
	}

	return arch
}

func ref[T any](val T) *T {
	ref := val

	return &ref
}

func deref[T any](pointer *T, defaultVal T) T {
	if pointer != nil {
		return *pointer
	}

	return defaultVal
}

func PaginatedFullImageMeta2ImageSummaries(ctx context.Context, imageMetaList []mTypes.FullImageMeta, skip SkipQGLField,
	cveInfo cveinfo.CveInfo, filter mTypes.Filter, pageInput pagination.PageInput,
) ([]*gql_generated.ImageSummary, zcommon.PageInfo, error) {
	imagePageFinder, err := pagination.NewImgSumPageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy)
	if err != nil {
		return []*gql_generated.ImageSummary{}, zcommon.PageInfo{}, err
	}

	for _, imageMeta := range imageMetaList {
		imageSummary, _, err := FullImageMeta2ImageSummary(ctx, imageMeta)
		if err != nil {
			continue
		}

		if ImgSumAcceptedByFilter(imageSummary, filter) {
			imagePageFinder.Add(imageSummary)
		}
	}

	page, pageInfo := imagePageFinder.Page()

	for _, imageSummary := range page {
		// CVE scanning is expensive, only scan for this page
		updateImageSummaryVulnerabilities(ctx, imageSummary, skip, cveInfo)
	}

	return page, pageInfo, nil
}
