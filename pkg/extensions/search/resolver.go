package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"sort"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/log" // nolint: gci

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	digestinfo "zotregistry.io/zot/pkg/extensions/search/digest"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo         *cveinfo.CveInfo
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

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController, enableCVE bool) gql_generated.Config {
	var cveInfo *cveinfo.CveInfo

	var err error

	if enableCVE {
		cveInfo, err = cveinfo.GetCVEInfo(storeController, log)
		if err != nil {
			panic(err)
		}
	}

	digestInfo := digestinfo.NewDigestInfo(storeController, log)

	resConfig := &Resolver{cveInfo: cveInfo, storeController: storeController, digestInfo: digestInfo, log: log}

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

func (r *queryResolver) getImageListWithLatestTag(store storage.ImageStore) ([]*gql_generated.ImageSummary, error) {
	results := make([]*gql_generated.ImageSummary, 0)

	repoList, err := store.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting repositories list")

		return results, err
	}

	if len(repoList) == 0 {
		r.log.Info().Msg("no repositories found")
	}

	layoutUtils := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	for _, repo := range repoList {
		tagsInfo, err := layoutUtils.GetImageTagsWithTimestamp(repo)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error getting tag timestamp info")

			return results, err
		}

		if len(tagsInfo) == 0 {
			r.log.Info().Str("no tagsinfo found for repo", repo).Msg(" continuing traversing")

			continue
		}

		latestTag := common.GetLatestTag(tagsInfo)

		digest := godigest.Digest(latestTag.Digest)

		manifest, err := layoutUtils.GetImageBlobManifest(repo, digest)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading manifest")

			return results, err
		}

		size := strconv.FormatInt(manifest.Config.Size, 10)

		name := repo

		imageConfig, err := layoutUtils.GetImageInfo(repo, manifest.Config.Digest)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading image config")

			return results, err
		}

		labels := imageConfig.Config.Labels

		// Read Description
		desc := common.GetDescription(labels)

		// Read licenses
		license := common.GetLicense(labels)

		// Read vendor
		vendor := common.GetVendor(labels)

		// Read categories
		categories := common.GetCategories(labels)

		results = append(results, &gql_generated.ImageSummary{
			RepoName: &name, Tag: &latestTag.Name,
			Description: &desc, Licenses: &license, Vendor: &vendor,
			Labels: &categories, Size: &size, LastUpdated: &latestTag.Timestamp,
		})
	}

	return results, nil
}

func cleanQuerry(query string) string {
	query = strings.ToLower(query)
	query = strings.Replace(query, ":", " ", 1)

	return query
}

func globalSearch(repoList []string, name, tag string, olu common.OciLayoutUtils, log log.Logger) (
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
				log.Error().Msg("reference not found for this manifest")

				continue
			}

			imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifests[i].Digest)
			if err != nil {
				log.Error().Err(err).Msgf("can't read manifest for repo %s %s", repo, manifestTag)

				continue
			}

			manifestSize := olu.GetImageManifestSize(repo, manifests[i].Digest)
			configSize := imageBlobManifest.Config.Size

			repoBlob2Size[manifests[i].Digest.String()] = manifestSize
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

				vendor := olu.GetImageVendor(imageConfigInfo)
				lastUpdated := olu.GetImageLastUpdated(imageConfigInfo)
				os, arch := olu.GetImagePlatform(imageConfigInfo)
				osArch := &gql_generated.OsArch{
					Os:   &os,
					Arch: &arch,
				}

				repoPlatforms = append(repoPlatforms, osArch)
				repoVendors = append(repoVendors, &vendor)

				imageSummary := gql_generated.ImageSummary{
					RepoName:    &repo,
					Tag:         &manifestTag,
					LastUpdated: &lastUpdated,
					IsSigned:    &isSigned,
					Size:        &size,
					Platform:    osArch,
					Vendor:      &vendor,
					Score:       &score,
				}

				if manifests[i].Digest.String() == lastUpdatedTag.Digest {
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
