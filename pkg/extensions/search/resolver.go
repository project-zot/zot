package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"sort"
	"strconv"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/log" // nolint: gci

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
) ([]*gql_generated.ImgResultForCve, error) {
	cveResult := []*gql_generated.ImgResultForCve{}

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("extracting list of tags available in image repo")

		name := repo

		tags, err := r.cveInfo.GetImageListForCVE(repo, cvid, imgStore, trivyCtx)
		if err != nil {
			r.log.Error().Err(err).Msg("error getting tag")

			return cveResult, err
		}

		if len(tags) != 0 {
			cveResult = append(cveResult, &gql_generated.ImgResultForCve{Name: &name, Tags: tags})
		}
	}

	return cveResult, nil
}

func (r *queryResolver) getImageListForDigest(repoList []string,
	digest string,
) ([]*gql_generated.ImgResultForDigest, error) {
	imgResultForDigest := []*gql_generated.ImgResultForDigest{}

	var errResult error

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("filtering list of tags in image repo by digest")

		tags, err := r.digestInfo.GetImageTagsByDigest(repo, digest)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get filtered list of image tags")

			errResult = err

			continue
		}

		if len(tags) != 0 {
			name := repo

			imgResultForDigest = append(imgResultForDigest, &gql_generated.ImgResultForDigest{Name: &name, Tags: tags})
		}
	}

	return imgResultForDigest, errResult
}

func (r *queryResolver) getImageListWithLatestTag(store storage.ImageStore) ([]*gql_generated.ImageInfo, error) {
	results := make([]*gql_generated.ImageInfo, 0)

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

		results = append(results, &gql_generated.ImageInfo{
			Name: &name, Latest: &latestTag.Name,
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

		tagsInfo, err := olu.GetImageTagsWithTimestamp(repo)
		if err != nil {
			log.Error().Err(err).Msgf("can't get tags info for repo: %s", repo)

			continue
		}

		repoInfo, err := olu.GetExpandedRepoInfo(repo)
		if err != nil {
			log.Error().Err(err).Msgf("can't get repo info for repo: %s", repo)

			continue
		}

		var lastUpdatedImageSummary gql_generated.ImageSummary

		repoPlatforms := make([]*gql_generated.OsArch, 0, len(tagsInfo))
		repoVendors := make([]*string, 0, len(repoInfo.Manifests))

		for i, manifest := range repoInfo.Manifests {
			imageLayersSize := int64(0)

			imageBlobManifest, err := olu.GetImageBlobManifest(repo, godigest.Digest(tagsInfo[i].Digest))
			if err != nil {
				log.Error().Err(err).Msgf("can't read manifest for repo %s %s", repo, manifest.Tag)

				continue
			}

			manifestSize := olu.GetImageManifestSize(repo, godigest.Digest(tagsInfo[i].Digest))
			configSize := imageBlobManifest.Config.Size

			repoBlob2Size[tagsInfo[i].Digest] = manifestSize
			repoBlob2Size[imageBlobManifest.Config.Digest.Hex] = configSize

			for _, layer := range manifest.Layers {
				layer := layer

				layerSize, err := strconv.ParseInt(layer.Size, 10, 64)
				if err != nil {
					log.Error().Err(err).Msg("invalid layer size")

					continue
				}

				repoBlob2Size[layer.Digest] = layerSize
				imageLayersSize += layerSize

				// if we have a tag we won't match a layer
				if tag != "" {
					continue
				}

				if index := strings.Index(layer.Digest, name); index != -1 {
					layers = append(layers, &gql_generated.LayerSummary{
						Digest: &layer.Digest,
						Size:   &layer.Size,
						Score:  &index,
					})
				}
			}

			imageSize := imageLayersSize + manifestSize + configSize

			index := strings.Index(repo, name)
			matchesTag := strings.HasPrefix(manifest.Tag, tag)

			if index != -1 {
				imageConfigInfo, err := olu.GetImageConfigInfo(repo, godigest.Digest(tagsInfo[i].Digest))
				if err != nil {
					log.Error().Err(err).Msgf("can't retrieve config info for the image %s %s", repo, manifest.Tag)

					continue
				}

				tag := manifest.Tag
				size := strconv.Itoa(int(imageSize))
				isSigned := manifest.IsSigned

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
				NewestTag:   &lastUpdatedImageSummary,
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

func getGraphqlCompatibleTags(fixedTags []common.TagInfo) []*gql_generated.TagInfo {
	finalTagList := make([]*gql_generated.TagInfo, 0)

	for _, tag := range fixedTags {
		fixTag := tag

		finalTagList = append(finalTagList,
			&gql_generated.TagInfo{Name: &fixTag.Name, Digest: &fixTag.Digest, Timestamp: &fixTag.Timestamp})
	}

	return finalTagList
}
