package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"              // nolint:gci
	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint:gci
	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/storage/repodb"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	digestinfo "zotregistry.io/zot/pkg/extensions/search/digest"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log" // nolint: gci
	"zotregistry.io/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo         cveinfo.CveInfo
	repoDB          repodb.RepoDB
	storeController storage.StoreController
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

var (
	ErrBadCtxFormat  = errors.New("type assertion failed")
	ErrBadLayerCount = errors.New("manifest: layers count doesn't correspond to config history")
)

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo,
) gql_generated.Config {
	digestInfo := digestinfo.NewDigestInfo(storeController, log)

	resConfig := &Resolver{
		cveInfo:         cveInfo,
		repoDB:          repoDB,
		storeController: storeController,
		digestInfo:      digestInfo,
		log:             log,
	}

	return gql_generated.Config{
		Resolvers: resConfig, Directives: gql_generated.DirectiveRoot{},
		Complexity: gql_generated.ComplexityRoot{},
	}
}

func (r *queryResolver) getImageListForDigest(repoList []string, digest string) ([]*gql_generated.ImageSummary, error) {
	imgResultForDigest := []*gql_generated.ImageSummary{}
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	var errResult error

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("filtering list of tags in image repo by digest")

		imgTags, err := r.digestInfo.GetImageTagsByDigest(repo, digest)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get filtered list of image tags")

			return []*gql_generated.ImageSummary{}, err
		}

		for _, imageInfo := range imgTags {
			imageConfig, err := olu.GetImageConfigInfo(repo, imageInfo.Digest)
			if err != nil {
				return []*gql_generated.ImageSummary{}, err
			}

			imageInfo := BuildImageInfo(repo, imageInfo.Tag, imageInfo.Digest, imageInfo.Manifest, imageConfig)

			imgResultForDigest = append(imgResultForDigest, imageInfo)
		}
	}

	return imgResultForDigest, errResult
}

func repoListWithNewestImage(
	ctx context.Context,
	repoList []string,
	olu common.OciLayoutUtils,
	cveInfo cveinfo.CveInfo,
	log log.Logger,
) ([]*gql_generated.RepoSummary, error) {
	reposSummary := []*gql_generated.RepoSummary{}

	for _, repo := range repoList {
		lastUpdatedTag, err := olu.GetRepoLastUpdated(repo)
		if err != nil {
			msg := fmt.Sprintf("can't get last updated manifest for repo: %s", repo)
			log.Error().Err(err).Msg(msg)

			graphql.AddError(ctx, gqlerror.Errorf(msg))

			continue
		}

		repoSize := int64(0)
		repoBlob2Size := make(map[string]int64, 10)

		manifests, err := olu.GetImageManifests(repo)
		if err != nil {
			msg := fmt.Sprintf("can't get manifests for repo: %s", repo)

			log.Error().Err(err).Msg(msg)
			graphql.AddError(ctx, gqlerror.Errorf(msg))

			continue
		}

		repoVendorsSet := make(map[string]bool, len(manifests))
		repoPlatformsSet := make(map[string]*gql_generated.OsArch, len(manifests))

		repoName := repo

		var lastUpdatedImageSummary gql_generated.ImageSummary

		var brokenManifest bool

		for _, manifest := range manifests {
			imageLayersSize := int64(0)
			manifestSize := olu.GetImageManifestSize(repo, manifest.Digest)

			imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifest.Digest)
			if err != nil {
				msg := fmt.Sprintf("reference not found for manifest %s", manifest.Digest)

				log.Error().Err(err).Msg(msg)
				graphql.AddError(ctx, gqlerror.Errorf(msg))

				brokenManifest = true

				continue
			}

			configSize := imageBlobManifest.Config.Size
			repoBlob2Size[manifest.Digest.String()] = manifestSize
			repoBlob2Size[imageBlobManifest.Config.Digest.Hex] = configSize

			for _, layer := range imageBlobManifest.Layers {
				repoBlob2Size[layer.Digest.String()] = layer.Size
				imageLayersSize += layer.Size
			}

			imageSize := imageLayersSize + manifestSize + configSize

			imageConfigInfo, err := olu.GetImageConfigInfo(repo, manifest.Digest)
			if err != nil {
				msg := fmt.Sprintf("can't get image config for manifest %s", manifest.Digest)

				log.Error().Err(err).Msg(msg)
				graphql.AddError(ctx, gqlerror.Errorf(msg))

				brokenManifest = true

				continue
			}

			opSys, arch := olu.GetImagePlatform(imageConfigInfo)
			osArch := &gql_generated.OsArch{
				Os:   &opSys,
				Arch: &arch,
			}

			if opSys != "" || arch != "" {
				osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
				repoPlatformsSet[osArchString] = &gql_generated.OsArch{Os: &opSys, Arch: &arch}
			}

			// get image info from manifest annotation, if not found get from image config labels.
			annotations := common.GetAnnotations(imageBlobManifest.Annotations, imageConfigInfo.Config.Labels)

			if annotations.Vendor != "" {
				repoVendorsSet[annotations.Vendor] = true
			}

			manifestTag, ok := manifest.Annotations[ispec.AnnotationRefName]
			if !ok {
				msg := fmt.Sprintf("reference not found for manifest %s in repo %s",
					manifest.Digest.String(), repoName)

				log.Error().Msg(msg)
				graphql.AddError(ctx, gqlerror.Errorf(msg))

				brokenManifest = true

				break
			}

			imageCveSummary := cveinfo.ImageCVESummary{}
			// Check if vulnerability scanning is disabled
			if cveInfo != nil {
				imageName := fmt.Sprintf("%s:%s", repoName, manifestTag)
				imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

				if err != nil {
					// Log the error, but we should still include the manifest in results
					msg := fmt.Sprintf(
						"unable to run vulnerability scan on tag %s in repo %s",
						manifestTag,
						repoName,
					)

					log.Error().Msg(msg)
					graphql.AddError(ctx, gqlerror.Errorf(msg))
				}
			}

			tag := manifestTag
			size := strconv.Itoa(int(imageSize))
			manifestDigest := manifest.Digest.Hex()
			configDigest := imageBlobManifest.Config.Digest.Hex
			isSigned := olu.CheckManifestSignature(repo, manifest.Digest)
			lastUpdated := olu.GetImageLastUpdated(imageConfigInfo)
			score := 0

			imageSummary := gql_generated.ImageSummary{
				RepoName:      &repoName,
				Tag:           &tag,
				LastUpdated:   &lastUpdated,
				Digest:        &manifestDigest,
				ConfigDigest:  &configDigest,
				IsSigned:      &isSigned,
				Size:          &size,
				Platform:      osArch,
				Vendor:        &annotations.Vendor,
				Score:         &score,
				Description:   &annotations.Description,
				Title:         &annotations.Title,
				Documentation: &annotations.Documentation,
				Licenses:      &annotations.Licenses,
				Labels:        &annotations.Labels,
				Source:        &annotations.Source,
				Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
					MaxSeverity: &imageCveSummary.MaxSeverity,
					Count:       &imageCveSummary.Count,
				},
			}

			if manifest.Digest.String() == lastUpdatedTag.Digest {
				lastUpdatedImageSummary = imageSummary
			}
		}

		if brokenManifest {
			continue
		}

		for blob := range repoBlob2Size {
			repoSize += repoBlob2Size[blob]
		}

		repoSizeStr := strconv.FormatInt(repoSize, 10)
		index := 0

		repoPlatforms := make([]*gql_generated.OsArch, 0, len(repoPlatformsSet))

		for _, osArch := range repoPlatformsSet {
			repoPlatforms = append(repoPlatforms, osArch)
		}

		repoVendors := make([]*string, 0, len(repoVendorsSet))

		for vendor := range repoVendorsSet {
			vendor := vendor
			repoVendors = append(repoVendors, &vendor)
		}

		reposSummary = append(reposSummary, &gql_generated.RepoSummary{
			Name:        &repoName,
			LastUpdated: &lastUpdatedTag.Timestamp,
			Size:        &repoSizeStr,
			Platforms:   repoPlatforms,
			Vendors:     repoVendors,
			Score:       &index,
			NewestImage: &lastUpdatedImageSummary,
		})
	}

	return reposSummary, nil
}

func cleanQuerry(query string) string {
	query = strings.TrimSpace(query)

	return query
}

func globalSearch(ctx context.Context, query string, repoDB repodb.RepoDB, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput, cveInfo cveinfo.CveInfo, log log.Logger,
) ([]*gql_generated.RepoSummary, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary, error,
) {
	repos := []*gql_generated.RepoSummary{}
	images := []*gql_generated.ImageSummary{}
	layers := []*gql_generated.LayerSummary{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	localFilter := repodb.Filter{}
	if filter != nil {
		localFilter = repodb.Filter{
			Os:            filter.Os,
			Arch:          filter.Arch,
			HasToBeSigned: filter.HasToBeSigned,
		}
	}

	if searchingForRepos(query) {
		pageInput := repodb.PageInput{
			Limit:  safeDerefferencing(requestedPage.Limit, 0),
			Offset: safeDerefferencing(requestedPage.Offset, 0),
			SortBy: repodb.SortCriteria(
				safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
			),
		}

		reposMeta, manifestMetaMap, err := repoDB.SearchRepos(ctx, query, localFilter, pageInput)
		if err != nil {
			return []*gql_generated.RepoSummary{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			repoSummary := RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, cveInfo)

			*repoSummary.Score = calculateImageMatchingScore(repoMeta.Name, strings.Index(repoMeta.Name, query))
			repos = append(repos, repoSummary)
		}
	} else { // search for images
		pageInput := repodb.PageInput{
			Limit:  safeDerefferencing(requestedPage.Limit, 0),
			Offset: safeDerefferencing(requestedPage.Offset, 0),
			SortBy: repodb.SortCriteria(
				safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
			),
		}

		reposMeta, manifestMetaMap, err := repoDB.SearchTags(ctx, query, localFilter, pageInput)
		if err != nil {
			return []*gql_generated.RepoSummary{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			imageSummaries := RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, cveInfo)

			images = append(images, imageSummaries...)
		}
	}

	return repos, images, layers, nil
}

func safeDerefferencing[T any](pointer *T, defaultVal T) T {
	if pointer != nil {
		return *pointer
	}

	return defaultVal
}

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, cveInfo cveinfo.CveInfo,
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
		if cveInfo != nil {
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
			imageLastUpdated = getImageLastUpdated(configContent)
			isSigned         = imageHasSignatures(manifestMetaMap[manifestDigest].Signatures)
			imageSize        = strconv.FormatInt(imgSize, 10)
			os               = configContent.OS
			arch             = configContent.Architecture
			osArch           = gql_generated.OsArch{Os: &os, Arch: &arch}
			downloadCount    = manifestMetaMap[manifestDigest].DownloadCount
		)

		annotations := common.GetAnnotations(manifestContent.Annotations, configContent.Config.Labels)

		imageSummary := gql_generated.ImageSummary{
			RepoName:      &repoName,
			Tag:           &tag,
			Digest:        &manifestDigest,
			ConfigDigest:  &configDigest,
			LastUpdated:   imageLastUpdated,
			IsSigned:      &isSigned,
			Size:          &imageSize,
			Platform:      &osArch,
			Vendor:        &annotations.Vendor,
			DownloadCount: &downloadCount,
			Layers:        getLayersSummary(manifestContent),
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			Vulnerabilities: &gql_generated.ImageVulnerabilitySummary{
				MaxSeverity: &imageCveSummary.MaxSeverity,
				Count:       &imageCveSummary.Count,
			},
		}

		imageSummaries = append(imageSummaries, &imageSummary)
	}

	return imageSummaries
}

func getLayersSummary(manifestContent ispec.Manifest) []*gql_generated.LayerSummary {
	layers := make([]*gql_generated.LayerSummary, 0, len(manifestContent.Layers))

	for _, layer := range manifestContent.Layers {
		size := strconv.FormatInt(layer.Size, 10)
		digest := layer.Digest.String()

		layers = append(layers, &gql_generated.LayerSummary{
			Size:   &size,
			Digest: &digest,
		})
	}

	return layers
}

func RepoMeta2RepoSummary(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata, cveInfo cveinfo.CveInfo,
) *gql_generated.RepoSummary {
	var (
		repoLastUpdatedTimestamp = time.Time{}
		repoPlatformsSet         = map[string]*gql_generated.OsArch{}
		repoVendorsSet           = map[string]bool{}
		lastUpdatedImageSummary  *gql_generated.ImageSummary
		repoStarCount            = repoMeta.Stars
		isBookmarked             = false
		isStarred                = false
		repoDownloadCount        = 0
		repoName                 = repoMeta.Name

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

		imageCveSummary := cveinfo.ImageCVESummary{}
		// Check if vulnerability scanning is disabled
		if cveInfo != nil {
			imageName := fmt.Sprintf("%s:%s", repoMeta.Name, tag)
			imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

			if err != nil {
				// Log the error, but we should still include the manifest in results
				graphql.AddError(ctx, gqlerror.Errorf("unable to run vulnerability scan on tag %s in repo %s: "+
					"manifest digest: %s, error: %s", tag, repoMeta.Name, manifestDigest, err.Error()))
			}
		}

		var (
			tag              = tag
			isSigned         = len(manifestMetaMap[manifestDigest].Signatures) > 0
			configDigest     = manifestContent.Config.Digest.String()
			configSize       = manifestContent.Config.Size
			opSys            = configContent.OS
			arch             = configContent.Architecture
			osArch           = gql_generated.OsArch{Os: &opSys, Arch: &arch}
			imageLastUpdated = getImageLastUpdated(configContent)
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

		imageSummary := gql_generated.ImageSummary{
			RepoName:      &repoName,
			Tag:           &tag,
			Digest:        &manifestDigest,
			ConfigDigest:  &configDigest,
			LastUpdated:   imageLastUpdated,
			IsSigned:      &isSigned,
			Size:          &imageSize,
			Platform:      &osArch,
			Vendor:        &annotations.Vendor,
			DownloadCount: &downloadCount,
			Layers:        getLayersSummary(manifestContent),
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
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
			if imageLastUpdated != nil {
				repoLastUpdatedTimestamp = *imageLastUpdated
			}

			lastUpdatedImageSummary = &imageSummary
		} else if imageLastUpdated != nil && repoLastUpdatedTimestamp.Before(*imageLastUpdated) {
			repoLastUpdatedTimestamp = *imageLastUpdated
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

func imageHasSignatures(signatures map[string][]string) bool {
	// (sigType, signatures)
	for _, sigs := range signatures {
		if len(sigs) > 0 {
			return true
		}
	}

	return false
}

func searchingForRepos(query string) bool {
	return !strings.Contains(query, ":")
}

// updateRepoBlobsMap adds all the image blobs and their respective size to the repo blobs map
// and returnes the total size of the image.
func updateRepoBlobsMap(manifestDigest string, manifestSize int64, configDigest string, configSize int64,
	layers []ispec.Descriptor, repoBlob2Size map[string]int64,
) int64 {
	imgSize := int64(0)

	// add config size
	imgSize += configSize
	repoBlob2Size[configDigest] = configSize

	// add manifest size
	imgSize += manifestSize
	repoBlob2Size[manifestDigest] = manifestSize

	// add layers size
	for _, layer := range layers {
		repoBlob2Size[layer.Digest.String()] = layer.Size
		imgSize += layer.Size
	}

	return imgSize
}

func getImageLastUpdated(configContent ispec.Image) *time.Time {
	var lastUpdated *time.Time

	if configContent.Created != nil {
		lastUpdated = configContent.Created
	}

	for _, update := range configContent.History {
		if update.Created != nil {
			lastUpdated = update.Created

			break
		}
	}

	return lastUpdated
}

// calcalculateImageMatchingScore iterated from the index of the matched string in the
// artifact name until the beginning of the string or until delimitator "/".
// The distance represents the score of the match.
//
// Example:
// 	query: image
// 	repos: repo/test/myimage
// Score will be 2.
func calculateImageMatchingScore(artefactName string, index int) int {
	score := 0

	for index >= 1 {
		if artefactName[index-1] == '/' {
			break
		}
		index--
		score++
	}

	return score
}

func (r *queryResolver) getImageList(store storage.ImageStore, imageName string) (
	[]*gql_generated.ImageSummary, error,
) {
	results := make([]*gql_generated.ImageSummary, 0)

	repoList, err := store.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting repositories list")

		return results, err
	}

	layoutUtils := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	for _, repo := range repoList {
		if (imageName != "" && repo == imageName) || imageName == "" {
			tagsInfo, err := layoutUtils.GetImageTagsWithTimestamp(repo)
			if err != nil {
				r.log.Error().Err(err).Msg("extension api: error getting tag timestamp info")

				return results, nil
			}

			if len(tagsInfo) == 0 {
				r.log.Info().Str("no tagsinfo found for repo", repo).Msg(" continuing traversing")

				continue
			}

			for i := range tagsInfo {
				// using a loop variable called tag would be reassigned after each iteration, using the same memory address
				// directly access the value at the current index in the slice as ImageInfo requires pointers to tag fields
				tag := tagsInfo[i]

				digest := godigest.Digest(tag.Digest)

				manifest, err := layoutUtils.GetImageBlobManifest(repo, digest)
				if err != nil {
					r.log.Error().Err(err).Msg("extension api: error reading manifest")

					return results, err
				}

				imageConfig, err := layoutUtils.GetImageConfigInfo(repo, digest)
				if err != nil {
					return results, err
				}

				imageInfo := BuildImageInfo(repo, tag.Name, digest, manifest, imageConfig)

				results = append(results, imageInfo)
			}
		}
	}

	if len(results) == 0 {
		r.log.Info().Msg("no repositories found")
	}

	return results, nil
}

func BuildImageInfo(repo string, tag string, manifestDigest godigest.Digest,
	manifest v1.Manifest, imageConfig ispec.Image,
) *gql_generated.ImageSummary {
	layers := []*gql_generated.LayerSummary{}
	size := int64(0)

	log := log.NewLogger("debug", "")

	allHistory := []*gql_generated.LayerHistory{}

	formattedManifestDigest := manifestDigest.Hex()

	history := imageConfig.History
	if len(history) == 0 {
		for _, layer := range manifest.Layers {
			size += layer.Size
			digest := layer.Digest.Hex
			layerSize := strconv.FormatInt(layer.Size, 10)

			layer := &gql_generated.LayerSummary{
				Size:   &layerSize,
				Digest: &digest,
			}

			layers = append(
				layers,
				layer,
			)

			allHistory = append(allHistory, &gql_generated.LayerHistory{
				Layer:              layer,
				HistoryDescription: &gql_generated.HistoryDescription{},
			})
		}

		formattedSize := strconv.FormatInt(size, 10)

		imageInfo := &gql_generated.ImageSummary{
			RepoName:     &repo,
			Tag:          &tag,
			Digest:       &formattedManifestDigest,
			ConfigDigest: &manifest.Config.Digest.Hex,
			Size:         &formattedSize,
			Layers:       layers,
			History:      []*gql_generated.LayerHistory{},
		}

		return imageInfo
	}

	// iterator over manifest layers
	var layersIterator int
	// since we are appending pointers, it is important to iterate with an index over slice
	for i := range history {
		allHistory = append(allHistory, &gql_generated.LayerHistory{
			HistoryDescription: &gql_generated.HistoryDescription{
				Created:    history[i].Created,
				CreatedBy:  &history[i].CreatedBy,
				Author:     &history[i].Author,
				Comment:    &history[i].Comment,
				EmptyLayer: &history[i].EmptyLayer,
			},
		})

		if history[i].EmptyLayer {
			continue
		}

		if layersIterator+1 > len(manifest.Layers) {
			formattedSize := strconv.FormatInt(size, 10)

			log.Error().Err(ErrBadLayerCount).Msg("error on creating layer history for ImageSummary")

			return &gql_generated.ImageSummary{
				RepoName:     &repo,
				Tag:          &tag,
				Digest:       &formattedManifestDigest,
				ConfigDigest: &manifest.Config.Digest.Hex,
				Size:         &formattedSize,
				Layers:       layers,
				History:      allHistory,
			}
		}

		size += manifest.Layers[layersIterator].Size
		digest := manifest.Layers[layersIterator].Digest.Hex
		layerSize := strconv.FormatInt(manifest.Layers[layersIterator].Size, 10)

		layer := &gql_generated.LayerSummary{
			Size:   &layerSize,
			Digest: &digest,
		}

		layers = append(
			layers,
			layer,
		)

		allHistory[i].Layer = layer

		layersIterator++
	}

	formattedSize := strconv.FormatInt(size, 10)

	imageInfo := &gql_generated.ImageSummary{
		RepoName:     &repo,
		Tag:          &tag,
		Digest:       &formattedManifestDigest,
		ConfigDigest: &manifest.Config.Digest.Hex,
		Size:         &formattedSize,
		Layers:       layers,
		History:      allHistory,
	}

	return imageInfo
}
