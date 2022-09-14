package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	glob "github.com/bmatcuk/doublestar/v4"            // nolint:gci
	v1 "github.com/google/go-containerregistry/pkg/v1" // nolint:gci
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"zotregistry.io/zot/errors"
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
	cveInfo         cveinfo.CveInfo
	storeController storage.StoreController
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController, cveInfo cveinfo.CveInfo,
) gql_generated.Config {
	digestInfo := digestinfo.NewDigestInfo(storeController, log)

	resConfig := &Resolver{cveInfo: cveInfo, storeController: storeController, digestInfo: digestInfo, log: log}

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

			isSigned := olu.CheckManifestSignature(repo, imageInfo.Digest)
			imageInfo := BuildImageInfo(repo, imageInfo.Tag, imageInfo.Digest,
				imageInfo.Manifest, imageConfig, isSigned)

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

		repoPlatforms := make([]*gql_generated.OsArch, 0)
		repoVendors := make([]*string, 0, len(manifests))
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

			os, arch := olu.GetImagePlatform(imageConfigInfo)
			osArch := &gql_generated.OsArch{
				Os:   &os,
				Arch: &arch,
			}
			repoPlatforms = append(repoPlatforms, osArch)

			// get image info from manifest annotation, if not found get from image config labels.
			annotations := common.GetAnnotations(imageBlobManifest.Annotations, imageConfigInfo.Config.Labels)

			repoVendors = append(repoVendors, &annotations.Vendor)

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
	query = strings.ToLower(query)
	query = strings.Replace(query, ":", " ", 1)

	return query
}

func globalSearch(repoList []string, name, tag string, olu common.OciLayoutUtils,
	cveInfo cveinfo.CveInfo, log log.Logger) (
	[]*gql_generated.RepoSummary, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary,
) {
	repos := []*gql_generated.RepoSummary{}
	images := []*gql_generated.ImageSummary{}
	layers := []*gql_generated.LayerSummary{}

	for _, repo := range repoList {
		repo := repo

		// map used for dedube if 2 images reference the same blob
		repoBlob2Size := make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		repoSize := int64(0)

		lastUpdatedTag, err := olu.GetRepoLastUpdated(repo)
		if err != nil {
			log.Error().Err(err).Msgf("can't find latest updated tag for repo: %s", repo)
		}

		manifests, err := olu.GetImageManifests(repo)
		if err != nil {
			log.Error().Err(err).Msgf("can't get manifests for repo: %s", repo)

			continue
		}

		var lastUpdatedImageSummary gql_generated.ImageSummary

		repoPlatforms := make([]*gql_generated.OsArch, 0, len(manifests))
		repoVendors := make([]*string, 0, len(manifests))

		for i, manifest := range manifests {
			imageLayersSize := int64(0)

			manifestTag, ok := manifest.Annotations[ispec.AnnotationRefName]
			if !ok {
				log.Error().Str("digest", manifest.Digest.String()).Msg("reference not found for this manifest")

				continue
			}

			imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifests[i].Digest)
			if err != nil {
				log.Error().Err(err).Msgf("can't read manifest for repo %s %s", repo, manifestTag)

				continue
			}

			manifestSize := olu.GetImageManifestSize(repo, manifest.Digest)
			configSize := imageBlobManifest.Config.Size

			repoBlob2Size[manifest.Digest.String()] = manifestSize
			repoBlob2Size[imageBlobManifest.Config.Digest.Hex] = configSize

			for _, layer := range imageBlobManifest.Layers {
				layer := layer
				layerDigest := layer.Digest.String()
				layerSizeStr := strconv.Itoa(int(layer.Size))
				repoBlob2Size[layer.Digest.String()] = layer.Size
				imageLayersSize += layer.Size

				// if we have a tag we won't match a layer
				if tag != "" {
					continue
				}

				if index := strings.Index(layerDigest, name); index != -1 {
					layers = append(layers, &gql_generated.LayerSummary{
						Digest: &layerDigest,
						Size:   &layerSizeStr,
						Score:  &index,
					})
				}
			}

			imageSize := imageLayersSize + manifestSize + configSize

			index := strings.Index(repo, name)
			matchesTag := strings.HasPrefix(manifestTag, tag)

			if index != -1 {
				imageConfigInfo, err := olu.GetImageConfigInfo(repo, manifests[i].Digest)
				if err != nil {
					log.Error().Err(err).Msgf("can't retrieve config info for the image %s %s", repo, manifestTag)

					continue
				}

				size := strconv.Itoa(int(imageSize))
				isSigned := olu.CheckManifestSignature(repo, manifests[i].Digest)

				// update matching score
				score := calculateImageMatchingScore(repo, index, matchesTag)

				lastUpdated := olu.GetImageLastUpdated(imageConfigInfo)
				os, arch := olu.GetImagePlatform(imageConfigInfo)
				osArch := &gql_generated.OsArch{
					Os:   &os,
					Arch: &arch,
				}

				// get image info from manifest annotation, if not found get from image config labels.
				annotations := common.GetAnnotations(imageBlobManifest.Annotations, imageConfigInfo.Config.Labels)

				manifestDigest := manifest.Digest.Hex()
				configDigest := imageBlobManifest.Config.Digest.Hex

				repoPlatforms = append(repoPlatforms, osArch)
				repoVendors = append(repoVendors, &annotations.Vendor)

				imageCveSummary := cveinfo.ImageCVESummary{}
				// Check if vulnerability scanning is disabled
				if cveInfo != nil {
					imageName := fmt.Sprintf("%s:%s", repo, manifestTag)
					imageCveSummary, err = cveInfo.GetCVESummaryForImage(imageName)

					if err != nil {
						// Log the error, but we should still include the manifest in results
						log.Error().Err(err).Msgf(
							"unable to run vulnerability scan on tag %s in repo %s",
							manifestTag,
							repo,
						)
					}
				}

				imageSummary := gql_generated.ImageSummary{
					RepoName:      &repo,
					Tag:           &manifestTag,
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

				images = append(images, &imageSummary)
			}
		}

		for blob := range repoBlob2Size {
			repoSize += repoBlob2Size[blob]
		}

		if index := strings.Index(repo, name); index != -1 {
			repoSize := strconv.FormatInt(repoSize, 10)

			repos = append(repos, &gql_generated.RepoSummary{
				Name:        &repo,
				LastUpdated: &lastUpdatedTag.Timestamp,
				Size:        &repoSize,
				Platforms:   repoPlatforms,
				Vendors:     repoVendors,
				Score:       &index,
				NewestImage: &lastUpdatedImageSummary,
			})
		}
	}

	sort.Slice(repos, func(i, j int) bool {
		return *repos[i].Score < *repos[j].Score
	})

	sort.Slice(images, func(i, j int) bool {
		return *images[i].Score < *images[j].Score
	})

	sort.Slice(layers, func(i, j int) bool {
		return *layers[i].Score < *layers[j].Score
	})

	return repos, images, layers
}

// calcalculateImageMatchingScore iterated from the index of the matched string in the
// artifact name until the beginning of the string or until delimitator "/".
// The distance represents the score of the match.
//
// Example:
// 	query: image
// 	repos: repo/test/myimage
// Score will be 2.
func calculateImageMatchingScore(artefactName string, index int, matchesTag bool) int {
	score := 0

	for index >= 1 {
		if artefactName[index-1] == '/' {
			break
		}
		index--
		score++
	}

	if !matchesTag {
		score += 10
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

				isSigned := layoutUtils.CheckManifestSignature(repo, digest)
				imageInfo := BuildImageInfo(repo, tag.Name, digest, manifest,
					imageConfig, isSigned)

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
	manifest v1.Manifest, imageConfig ispec.Image, isSigned bool,
) *gql_generated.ImageSummary {
	layers := []*gql_generated.LayerSummary{}
	size := int64(0)
	log := log.NewLogger("debug", "")
	allHistory := []*gql_generated.LayerHistory{}
	formattedManifestDigest := manifestDigest.Hex()
	annotations := common.GetAnnotations(manifest.Annotations, imageConfig.Config.Labels)

	lastUpdated := imageConfig.Created

	if (lastUpdated == nil || *lastUpdated == (time.Time{})) &&
		len(imageConfig.History) > 0 {
		lastUpdated = imageConfig.History[len(imageConfig.History)-1].Created
	}

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
			RepoName:      &repo,
			Tag:           &tag,
			Digest:        &formattedManifestDigest,
			ConfigDigest:  &manifest.Config.Digest.Hex,
			Size:          &formattedSize,
			Layers:        layers,
			History:       allHistory,
			Vendor:        &annotations.Vendor,
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			LastUpdated:   lastUpdated,
			IsSigned:      &isSigned,
			Platform: &gql_generated.OsArch{
				Os:   &imageConfig.OS,
				Arch: &imageConfig.Architecture,
			},
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

			log.Error().Err(errors.ErrBadLayerCount).Msg("error on creating layer history for ImageSummary")

			return &gql_generated.ImageSummary{
				RepoName:      &repo,
				Tag:           &tag,
				Digest:        &formattedManifestDigest,
				ConfigDigest:  &manifest.Config.Digest.Hex,
				Size:          &formattedSize,
				Layers:        layers,
				History:       allHistory,
				Vendor:        &annotations.Vendor,
				Description:   &annotations.Description,
				Title:         &annotations.Title,
				Documentation: &annotations.Documentation,
				Licenses:      &annotations.Licenses,
				Labels:        &annotations.Labels,
				Source:        &annotations.Source,
				LastUpdated:   lastUpdated,
				IsSigned:      &isSigned,
				Platform: &gql_generated.OsArch{
					Os:   &imageConfig.OS,
					Arch: &imageConfig.Architecture,
				},
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
		RepoName:      &repo,
		Tag:           &tag,
		Digest:        &formattedManifestDigest,
		ConfigDigest:  &manifest.Config.Digest.Hex,
		Size:          &formattedSize,
		Layers:        layers,
		History:       allHistory,
		Vendor:        &annotations.Vendor,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		LastUpdated:   lastUpdated,
		IsSigned:      &isSigned,
		Platform: &gql_generated.OsArch{
			Os:   &imageConfig.OS,
			Arch: &imageConfig.Architecture,
		},
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
			err := errors.ErrBadType

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

func extractImageDetails(
	ctx context.Context,
	layoutUtils common.OciLayoutUtils,
	repo, tag string,
	log log.Logger) (
	godigest.Digest, *v1.Manifest, *ispec.Image, error,
) {
	validRepoList, err := userAvailableRepos(ctx, []string{repo})
	if err != nil {
		log.Error().Err(err).Msg("unable to retrieve access token")

		return "", nil, nil, err
	}

	if len(validRepoList) == 0 {
		log.Error().Err(err).Msg("user is not authorized")

		return "", nil, nil, errors.ErrUnauthorizedAccess
	}

	_, dig, err := layoutUtils.GetImageManifest(repo, tag)
	if err != nil {
		log.Error().Err(err).Msg("Could not retrieve image ispec manifest")

		return "", nil, nil, err
	}

	digest := godigest.Digest(dig)

	manifest, err := layoutUtils.GetImageBlobManifest(repo, digest)
	if err != nil {
		log.Error().Err(err).Msg("Could not retrieve image godigest manifest")

		return "", nil, nil, err
	}

	imageConfig, err := layoutUtils.GetImageConfigInfo(repo, digest)
	if err != nil {
		log.Error().Err(err).Msg("Could not retrieve image config")

		return "", nil, nil, err
	}

	return digest, &manifest, &imageConfig, nil
}

func getAccessContext(ctx context.Context) localCtx.AccessControlContext {
	authzCtxKey := localCtx.GetContextKey()
	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, _ := authCtx.(localCtx.AccessControlContext)
		// acCtx.Username = "bob"
		return acCtx
	}

	// anonymous / default is the empty access control ctx
	return localCtx.AccessControlContext{
		IsAdmin:  false,
		Username: "",
	}
}

func filterRepos(acCtx localCtx.AccessControlContext, repoList []string) []string {
	var availableRepos []string

	for _, repoName := range repoList {
		if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, repoName) {
			availableRepos = append(availableRepos, repoName)
		}
	}

	return availableRepos
}
