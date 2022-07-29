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

	"github.com/99designs/gqlgen/graphql"
	glob "github.com/bmatcuk/doublestar/v4"            // nolint:gci
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
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo         *cveinfo.CveInfo
	repoDB          repodb.RepoDB
	storeController storage.StoreController
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

type cveDetail struct {
	Title       string
	Description string
	Severity    string
	PackageList []*gql_generated.PackageInfo
}

var ErrBadCtxFormat = errors.New("type assertion failed")

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController, repoDB repodb.RepoDB,
	enableCVE bool,
) gql_generated.Config {
	var cveInfo *cveinfo.CveInfo

	var err error

	if enableCVE {
		cveInfo, err = cveinfo.GetCVEInfo(storeController, log)
		if err != nil {
			panic(err)
		}
	}

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

func (r *queryResolver) getImageListForCVE(repoList []string, cvid string, imgStore storage.ImageStore,
	trivyCtx *cveinfo.TrivyCtx,
) ([]*gql_generated.ImageSummary, error) {
	cveResult := []*gql_generated.ImageSummary{}

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("extracting list of tags available in image repo")

		imageListByCVE, err := r.cveInfo.GetImageListForCVE(repo, cvid, imgStore, trivyCtx)
		if err != nil {
			r.log.Error().Err(err).Msg("error getting tag")

			return cveResult, err
		}

		for _, imageByCVE := range imageListByCVE {
			cveResult = append(
				cveResult,
				buildImageInfo(repo, imageByCVE.Tag, imageByCVE.Digest, imageByCVE.Manifest),
			)
		}
	}

	return cveResult, nil
}

func (r *queryResolver) getImageListForDigest(repoList []string, digest string) ([]*gql_generated.ImageSummary, error) {
	imgResultForDigest := []*gql_generated.ImageSummary{}

	var errResult error

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("filtering list of tags in image repo by digest")

		imgTags, err := r.digestInfo.GetImageTagsByDigest(repo, digest)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get filtered list of image tags")

			return []*gql_generated.ImageSummary{}, err
		}

		for _, imageInfo := range imgTags {
			imageInfo := buildImageInfo(repo, imageInfo.Tag, imageInfo.Digest, imageInfo.Manifest)
			imgResultForDigest = append(imgResultForDigest, imageInfo)
		}
	}

	return imgResultForDigest, errResult
}

// nolint:lll
func (r *queryResolver) repoListWithNewestImage(ctx context.Context, store storage.ImageStore) ([]*gql_generated.RepoSummary, error) {
	repos := []*gql_generated.RepoSummary{}
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	repoNames, err := store.GetRepositories()
	if err != nil {
		return nil, err
	}

	for _, repo := range repoNames {
		lastUpdatedTag, err := olu.GetRepoLastUpdated(repo)
		if err != nil {
			graphql.AddError(ctx, err)

			continue
		}

		repoSize := int64(0)
		repoBlob2Size := make(map[string]int64, 10)
		tagsInfo, _ := olu.GetImageTagsWithTimestamp(repo)

		manifests, err := olu.GetImageManifests(repo)
		if err != nil {
			graphql.AddError(ctx, err)

			continue
		}

		repoPlatforms := make([]*gql_generated.OsArch, 0, len(tagsInfo))
		repoVendors := make([]*string, 0, len(manifests))
		repoName := repo

		var lastUpdatedImageSummary gql_generated.ImageSummary

		var brokenManifest bool

		for i, manifest := range manifests {
			imageLayersSize := int64(0)
			manifestSize := olu.GetImageManifestSize(repo, manifests[i].Digest)

			imageBlobManifest, _ := olu.GetImageBlobManifest(repo, manifests[i].Digest)

			configSize := imageBlobManifest.Config.Size
			repoBlob2Size[manifests[i].Digest.String()] = manifestSize
			repoBlob2Size[imageBlobManifest.Config.Digest.Hex] = configSize

			for _, layer := range imageBlobManifest.Layers {
				repoBlob2Size[layer.Digest.String()] = layer.Size
				imageLayersSize += layer.Size
			}

			imageSize := imageLayersSize + manifestSize + configSize

			imageConfigInfo, _ := olu.GetImageConfigInfo(repo, manifests[i].Digest)

			os, arch := olu.GetImagePlatform(imageConfigInfo)
			osArch := &gql_generated.OsArch{
				Os:   &os,
				Arch: &arch,
			}
			repoPlatforms = append(repoPlatforms, osArch)

			vendor := olu.GetImageVendor(imageConfigInfo)
			repoVendors = append(repoVendors, &vendor)

			manifestTag, ok := manifest.Annotations[ispec.AnnotationRefName]
			if !ok {
				graphql.AddError(ctx, gqlerror.Errorf("reference not found for this manifest"))
				brokenManifest = true

				break
			}

			tag := manifestTag
			size := strconv.Itoa(int(imageSize))
			isSigned := olu.CheckManifestSignature(repo, manifests[i].Digest)
			lastUpdated := olu.GetImageLastUpdated(imageConfigInfo)
			score := 0

			imageSummary := gql_generated.ImageSummary{
				RepoName:    &repoName,
				Tag:         &tag,
				LastUpdated: &lastUpdated,
				IsSigned:    &isSigned,
				Size:        &size,
				Platform:    osArch,
				Vendor:      &vendor,
				Score:       &score,
			}

			if tagsInfo[i].Digest == lastUpdatedTag.Digest {
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

		repos = append(repos, &gql_generated.RepoSummary{
			Name:        &repoName,
			LastUpdated: &lastUpdatedTag.Timestamp,
			Size:        &repoSizeStr,
			Platforms:   repoPlatforms,
			Vendors:     repoVendors,
			Score:       &index,
			NewestImage: &lastUpdatedImageSummary,
		})
	}

	return repos, nil
}

func cleanQuerry(query string) string {
	query = strings.TrimSpace(query)

	return query
}

func globalSearch(ctx context.Context, query string, repoDB repodb.RepoDB, requestedPage *gql_generated.PageInput,
	log log.Logger,
) ([]*gql_generated.RepoSummary, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary, error,
) {
	repos := []*gql_generated.RepoSummary{}
	images := []*gql_generated.ImageSummary{}
	layers := []*gql_generated.LayerSummary{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	if searchingForRepos(query) {
		limit := 0
		if requestedPage.Limit != nil {
			limit = *requestedPage.Limit
		}

		offset := 0
		if requestedPage.Offset != nil {
			offset = *requestedPage.Offset
		}

		sortBy := gql_generated.SortCriteriaRelevance
		if requestedPage.SortBy != nil {
			sortBy = *requestedPage.SortBy
		}

		reposMeta, manifestMetaMap, err := repoDB.SearchRepos(ctx, query, repodb.PageInput{
			Limit:  limit,
			Offset: offset,
			SortBy: repodb.SortCriteria(sortBy),
		})
		if err != nil {
			return []*gql_generated.RepoSummary{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			repoSummary := RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap)

			*repoSummary.Score = calculateImageMatchingScore(repoMeta.Name, strings.Index(repoMeta.Name, query))
			repos = append(repos, repoSummary)
		}
	} else { // search for images
		limit := 0
		if requestedPage.Limit != nil {
			limit = *requestedPage.Limit
		}

		offset := 0
		if requestedPage.Offset != nil {
			offset = *requestedPage.Offset
		}

		sortBy := gql_generated.SortCriteriaRelevance
		if requestedPage.SortBy != nil {
			sortBy = *requestedPage.SortBy
		}
		reposMeta, manifestMetaMap, err := repoDB.SearchTags(ctx, query, repodb.PageInput{
			Limit:  limit,
			Offset: offset,
			SortBy: repodb.SortCriteria(sortBy),
		})
		if err != nil {
			return []*gql_generated.RepoSummary{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			imageSummaries := RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap)

			images = append(images, imageSummaries...)
		}
	}

	return repos, images, layers, nil
}

func RepoMeta2ImageSummaries(ctx context.Context, repoMeta repodb.RepoMetadata,
	manifestMetaMap map[string]repodb.ManifestMetadata,
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
	manifestMetaMap map[string]repodb.ManifestMetadata,
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

		// map used to keep track of all blobs of a repo without dublicates
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
			tag          = tag
			isSigned     = len(manifestMetaMap[manifestDigest].Signatures) > 0
			configDigest = manifestContent.Config.Digest.String()
			configSize   = manifestContent.Config.Size
			opSys        = configContent.OS
			arch         = configContent.Architecture
			osArch       = gql_generated.OsArch{Os: &opSys, Arch: &arch}

			imageLastUpdated = getImageLastUpdated(configContent)

			size = updateRepoBlobsMap(
				manifestDigest, int64(len(manifestMetaMap[manifestDigest].ManifestBlob)),
				configDigest, configSize,
				manifestContent.Layers,
				repoBlob2Size)
			imageSize      = strconv.FormatInt(size, 10)
			downloadCount  = manifestMetaMap[manifestDigest].DownloadCount
			manifestDigest = manifestDigest
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
		} else if imageLastUpdated != nil && repoLastUpdatedTimestamp.After(*imageLastUpdated) {
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

				imageInfo := buildImageInfo(repo, tag.Name, digest, manifest)

				results = append(results, imageInfo)
			}
		}
	}

	if len(results) == 0 {
		r.log.Info().Msg("no repositories found")
	}

	return results, nil
}

func buildImageInfo(repo string, tag string, tagDigest godigest.Digest,
	manifest v1.Manifest,
) *gql_generated.ImageSummary {
	layers := []*gql_generated.LayerSummary{}
	size := int64(0)

	for _, entry := range manifest.Layers {
		size += entry.Size
		digest := entry.Digest.Hex
		layerSize := strconv.FormatInt(entry.Size, 10)

		layers = append(
			layers,
			&gql_generated.LayerSummary{
				Size:   &layerSize,
				Digest: &digest,
			},
		)
	}

	formattedSize := strconv.FormatInt(size, 10)
	formattedTagDigest := tagDigest.Hex()

	imageInfo := &gql_generated.ImageSummary{
		RepoName:     &repo,
		Tag:          &tag,
		Digest:       &formattedTagDigest,
		ConfigDigest: &manifest.Config.Digest.Hex,
		Size:         &formattedSize,
		Layers:       layers,
	}

	return imageInfo
}

// returns either a user has or not rights on 'repository'.
func matchesRepo(globPatterns map[string]bool, repository string) bool {
	var longestMatchedPattern string

	// because of the longest path matching rule, we need to check all patterns from config
	for pattern := range globPatterns {
		matched, err := glob.Match(pattern, repository)
		if err == nil {
			if matched && len(pattern) > len(longestMatchedPattern) {
				longestMatchedPattern = pattern
			}
		}
	}

	allowed := globPatterns[longestMatchedPattern]

	return allowed
}

// get passed context from authzHandler and filter out repos based on permissions.
func userAvailableRepos(ctx context.Context, repoList []string) ([]string, error) {
	var availableRepos []string

	authzCtxKey := localCtx.GetContextKey()
	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(localCtx.AccessControlContext)
		if !ok {
			err := ErrBadCtxFormat

			return []string{}, err
		}

		for _, r := range repoList {
			if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, r) {
				availableRepos = append(availableRepos, r)
			}
		}
	} else {
		availableRepos = repoList
	}

	return availableRepos, nil
}
