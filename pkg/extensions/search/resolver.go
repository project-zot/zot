package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/log" // nolint: gci

	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	digestinfo "zotregistry.io/zot/pkg/extensions/search/digest"
	"zotregistry.io/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo         *cveinfo.CveInfo
	storeController storage.StoreController
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

// Query ...
func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

type cveDetail struct {
	Title       string
	Description string
	Severity    string
	PackageList []*PackageInfo
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController, enableCVE bool) Config {
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

	return Config{
		Resolvers: resConfig, Directives: DirectiveRoot{},
		Complexity: ComplexityRoot{},
	}
}

func (r *queryResolver) ExpandedRepoInfo(ctx context.Context, name string) (*RepoInfo, error) {
	olu := common.NewOciLayoutUtils(r.storeController, r.log)

	repo, err := olu.GetExpandedRepoInfo(name)
	if err != nil {
		r.log.Error().Err(err).Msg("error getting repos")

		return &RepoInfo{}, err
	}

	// repos type is of common deep copy this to search
	repoInfo := &RepoInfo{}

	manifests := make([]*ManifestInfo, 0)

	for _, manifest := range repo.Manifests {
		tag := manifest.Tag

		digest := manifest.Digest

		isSigned := manifest.IsSigned

		manifestInfo := &ManifestInfo{Tag: &tag, Digest: &digest, IsSigned: &isSigned}

		layers := make([]*LayerInfo, 0)

		for _, l := range manifest.Layers {
			size := l.Size

			digest := l.Digest

			layerInfo := &LayerInfo{Digest: &digest, Size: &size}

			layers = append(layers, layerInfo)
		}

		manifestInfo.Layers = layers

		manifests = append(manifests, manifestInfo)
	}

	repoInfo.Manifests = manifests

	return repoInfo, nil
}

func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*CVEResultForImage, error) {
	trivyCtx := r.cveInfo.GetTrivyContext(image)

	r.log.Info().Str("image", image).Msg("scanning image")

	isValidImage, err := r.cveInfo.LayoutUtils.IsValidImageFormat(image)
	if !isValidImage {
		r.log.Debug().Str("image", image).Msg("image media type not supported for scanning")

		return &CVEResultForImage{}, err
	}

	report, err := cveinfo.ScanImage(trivyCtx.Ctx)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to scan image repository")

		return &CVEResultForImage{}, err
	}

	var copyImgTag string

	if strings.Contains(image, ":") {
		copyImgTag = strings.Split(image, ":")[1]
	}

	cveidMap := make(map[string]cveDetail)

	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			pkgName := vulnerability.PkgName

			installedVersion := vulnerability.InstalledVersion

			var fixedVersion string
			if vulnerability.FixedVersion != "" {
				fixedVersion = vulnerability.FixedVersion
			} else {
				fixedVersion = "Not Specified"
			}

			_, ok := cveidMap[vulnerability.VulnerabilityID]
			if ok {
				cveDetailStruct := cveidMap[vulnerability.VulnerabilityID]

				pkgList := cveDetailStruct.PackageList

				pkgList = append(pkgList,
					&PackageInfo{Name: &pkgName, InstalledVersion: &installedVersion, FixedVersion: &fixedVersion})

				cveDetailStruct.PackageList = pkgList

				cveidMap[vulnerability.VulnerabilityID] = cveDetailStruct
			} else {
				newPkgList := make([]*PackageInfo, 0)

				newPkgList = append(newPkgList,
					&PackageInfo{Name: &pkgName, InstalledVersion: &installedVersion, FixedVersion: &fixedVersion})

				cveidMap[vulnerability.VulnerabilityID] = cveDetail{
					Title:       vulnerability.Title,
					Description: vulnerability.Description, Severity: vulnerability.Severity, PackageList: newPkgList,
				}
			}
		}
	}

	cveids := []*Cve{}

	for id, cveDetail := range cveidMap {
		vulID := id

		desc := cveDetail.Description

		title := cveDetail.Title

		severity := cveDetail.Severity

		pkgList := cveDetail.PackageList

		cveids = append(cveids,
			&Cve{ID: &vulID, Title: &title, Description: &desc, Severity: &severity, PackageList: pkgList})
	}

	return &CVEResultForImage{Tag: &copyImgTag, CVEList: cveids}, nil
}

func (r *queryResolver) ImageListForCve(ctx context.Context, cvid string) ([]*ImgResultForCve, error) {
	finalCveResult := []*ImgResultForCve{}

	r.log.Info().Msg("extracting repositories")

	defaultStore := r.storeController.DefaultStore

	defaultTrivyCtx := r.cveInfo.CveTrivyController.DefaultCveConfig

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return finalCveResult, err
	}

	r.cveInfo.Log.Info().Msg("scanning each global repository")

	cveResult, err := r.getImageListForCVE(repoList, cvid, defaultStore, defaultTrivyCtx)
	if err != nil {
		r.log.Error().Err(err).Msg("error getting cve list for global repositories")

		return finalCveResult, err
	}

	finalCveResult = append(finalCveResult, cveResult...)

	subStore := r.storeController.SubStore

	for route, store := range subStore {
		subRepoList, err := store.GetRepositories()
		if err != nil {
			r.log.Error().Err(err).Msg("unable to search repositories")

			return cveResult, err
		}

		subTrivyCtx := r.cveInfo.CveTrivyController.SubCveConfig[route]

		subCveResult, err := r.getImageListForCVE(subRepoList, cvid, store, subTrivyCtx)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get cve result for sub repositories")

			return finalCveResult, err
		}

		finalCveResult = append(finalCveResult, subCveResult...)
	}

	return finalCveResult, nil
}

func (r *queryResolver) getImageListForCVE(repoList []string, cvid string, imgStore storage.ImageStore,
	trivyCtx *cveinfo.TrivyCtx,
) ([]*ImgResultForCve, error) {
	cveResult := []*ImgResultForCve{}

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("extracting list of tags available in image repo")

		name := repo

		tags, err := r.cveInfo.GetImageListForCVE(repo, cvid, imgStore, trivyCtx)
		if err != nil {
			r.log.Error().Err(err).Msg("error getting tag")

			return cveResult, err
		}

		if len(tags) != 0 {
			cveResult = append(cveResult, &ImgResultForCve{Name: &name, Tags: tags})
		}
	}

	return cveResult, nil
}

func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, cvid, image string) (*ImgResultForFixedCve, error) { // nolint: lll
	imgResultForFixedCVE := &ImgResultForFixedCve{}

	r.log.Info().Str("image", image).Msg("extracting list of tags available in image")

	tagsInfo, err := r.cveInfo.LayoutUtils.GetImageTagsWithTimestamp(image)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to read image tags")

		return imgResultForFixedCVE, err
	}

	infectedTags := make([]common.TagInfo, 0)

	var hasCVE bool

	for _, tag := range tagsInfo {
		image := fmt.Sprintf("%s:%s", image, tag.Name)

		isValidImage, _ := r.cveInfo.LayoutUtils.IsValidImageFormat(image)
		if !isValidImage {
			r.log.Debug().Str("image",
				fmt.Sprintf("%s:%s", image, tag.Name)).
				Msg("image media type not supported for scanning, adding as an infected image")

			infectedTags = append(infectedTags, common.TagInfo{Name: tag.Name, Timestamp: tag.Timestamp})

			continue
		}

		trivyCtx := r.cveInfo.GetTrivyContext(image)

		r.cveInfo.Log.Info().Str("image", fmt.Sprintf("%s:%s", image, tag.Name)).Msg("scanning image")

		report, err := cveinfo.ScanImage(trivyCtx.Ctx)
		if err != nil {
			r.log.Error().Err(err).
				Str("image", fmt.Sprintf("%s:%s", image, tag.Name)).Msg("unable to scan image")

			continue
		}

		hasCVE = false

		for _, result := range report.Results {
			for _, vulnerability := range result.Vulnerabilities {
				if vulnerability.VulnerabilityID == cvid {
					hasCVE = true

					break
				}
			}
		}

		if hasCVE {
			infectedTags = append(infectedTags, common.TagInfo{Name: tag.Name, Timestamp: tag.Timestamp, Digest: tag.Digest})
		}
	}

	var finalTagList []*TagInfo

	if len(infectedTags) != 0 {
		r.log.Info().Msg("comparing fixed tags timestamp")

		fixedTags := common.GetFixedTags(tagsInfo, infectedTags)

		finalTagList = getGraphqlCompatibleTags(fixedTags)
	} else {
		r.log.Info().Str("image", image).Str("cve-id", cvid).Msg("image does not contain any tag that have given cve")

		finalTagList = getGraphqlCompatibleTags(tagsInfo)
	}

	imgResultForFixedCVE = &ImgResultForFixedCve{Tags: finalTagList}

	return imgResultForFixedCVE, nil
}

func (r *queryResolver) ImageListForDigest(ctx context.Context, digestID string) ([]*ImgResultForDigest, error) {
	imgResultForDigest := []*ImgResultForDigest{}

	r.log.Info().Msg("extracting repositories")

	defaultStore := r.storeController.DefaultStore

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return imgResultForDigest, err
	}

	r.log.Info().Msg("scanning each global repository")

	partialImgResultForDigest, err := r.getImageListForDigest(repoList, digestID)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to get image and tag list for global repositories")

		return imgResultForDigest, err
	}

	imgResultForDigest = append(imgResultForDigest, partialImgResultForDigest...)

	subStore := r.storeController.SubStore
	for _, store := range subStore {
		subRepoList, err := store.GetRepositories()
		if err != nil {
			r.log.Error().Err(err).Msg("unable to search sub-repositories")

			return imgResultForDigest, err
		}

		partialImgResultForDigest, err = r.getImageListForDigest(subRepoList, digestID)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get image and tag list for sub-repositories")

			return imgResultForDigest, err
		}

		imgResultForDigest = append(imgResultForDigest, partialImgResultForDigest...)
	}

	return imgResultForDigest, nil
}

func (r *queryResolver) getImageListForDigest(repoList []string,
	digest string,
) ([]*ImgResultForDigest, error) {
	imgResultForDigest := []*ImgResultForDigest{}

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

			imgResultForDigest = append(imgResultForDigest, &ImgResultForDigest{Name: &name, Tags: tags})
		}
	}

	return imgResultForDigest, errResult
}

func (r *queryResolver) ImageListWithLatestTag(ctx context.Context) ([]*ImageInfo, error) {
	r.log.Info().Msg("extension api: finding image list")

	imageList := make([]*ImageInfo, 0)

	defaultStore := r.storeController.DefaultStore

	dsImageList, err := r.getImageListWithLatestTag(defaultStore)
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting default store image list")

		return imageList, err
	}

	if len(dsImageList) != 0 {
		imageList = append(imageList, dsImageList...)
	}

	subStore := r.storeController.SubStore

	for _, store := range subStore {
		ssImageList, err := r.getImageListWithLatestTag(store)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error extracting default store image list")

			return imageList, err
		}

		if len(ssImageList) != 0 {
			imageList = append(imageList, ssImageList...)
		}
	}

	return imageList, nil
}

func (r *queryResolver) getImageListWithLatestTag(store storage.ImageStore) ([]*ImageInfo, error) {
	results := make([]*ImageInfo, 0)

	repoList, err := store.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting repositories list")

		return results, err
	}

	if len(repoList) == 0 {
		r.log.Info().Msg("no repositories found")
	}

	layoutUtils := common.NewOciLayoutUtils(r.storeController, r.log)

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

		results = append(results, &ImageInfo{
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

func (r *queryResolver) GlobalSearch(ctx context.Context, query string) (*GlobalSearchResult, error) {
	query = cleanQuerry(query)
	defaultStore := r.storeController.DefaultStore
	olu := common.NewOciLayoutUtils(r.storeController, r.log)

	var name, tag string

	_, err := fmt.Sscanf(query, "%s %s", &name, &tag)
	if err != nil {
		name = query
	}

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return &GlobalSearchResult{}, err
	}

	repos, images, layers := globalSearch(repoList, name, tag, olu, r.log)

	return &GlobalSearchResult{
		Images: images,
		Repos:  repos,
		Layers: layers,
	}, nil
}

func globalSearch(repoList []string, name, tag string, olu *common.OciLayoutUtils, log log.Logger) (
	[]*RepoSummary, []*ImageSummary, []*LayerSummary,
) {
	repos := []*RepoSummary{}
	images := []*ImageSummary{}
	layers := []*LayerSummary{}

	for _, repo := range repoList {
		repo := repo

		// map used for dedube if 2 images reference the same blob
		repoLayerBlob2Size := make(map[string]int64, 10)

		// made up of all manifests, configs and image layers
		repoSize := int64(0)

		lastUpdate, err := olu.GetRepoLastUpdated(repo)
		if err != nil {
			log.Error().Err(err).Msgf("can't find latest update timestamp for repo: %s", repo)
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

		repoPlatforms := make([]*OsArch, 0, len(tagsInfo))
		repoVendors := make([]*string, 0, len(repoInfo.Manifests))

		for i, manifest := range repoInfo.Manifests {
			imageLayersSize := int64(0)
			manifestSize := olu.GetImageManifestSize(repo, godigest.Digest(tagsInfo[i].Digest))
			configSize := olu.GetImageConfigSize(repo, godigest.Digest(tagsInfo[i].Digest))

			for _, layer := range manifest.Layers {
				layer := layer

				layerSize, err := strconv.ParseInt(layer.Size, 10, 64)
				if err != nil {
					olu.Log.Error().Err(err).Msg("invalid layer size")

					continue
				}

				repoLayerBlob2Size[layer.Digest] = layerSize
				imageLayersSize += layerSize

				// if we have a tag we won't match a layer
				if tag != "" {
					continue
				}

				if index := strings.Index(layer.Digest, name); index != -1 {
					layers = append(layers, &LayerSummary{
						Digest: &layer.Digest,
						Size:   &layer.Size,
						Score:  &index,
					})
				}
			}

			imageSize := imageLayersSize + manifestSize + configSize
			repoSize += manifestSize + configSize

			index := strings.Index(repo, name)
			matchesTag := strings.HasPrefix(manifest.Tag, tag)

			if index != -1 {
				tag := manifest.Tag
				size := strconv.Itoa(int(imageSize))
				vendor := olu.GetImageVendor(repo, godigest.Digest(tagsInfo[i].Digest))
				lastUpdated := olu.GetImageLastUpdated(repo, godigest.Digest(tagsInfo[i].Digest))

				// update matching score
				score := calculateImageMatchingScore(repo, index, matchesTag)

				os, arch := olu.GetImagePlatform(repo, godigest.Digest(tagsInfo[i].Digest))
				osArch := &OsArch{
					Os:   &os,
					Arch: &arch,
				}

				repoPlatforms = append(repoPlatforms, osArch)
				repoVendors = append(repoVendors, &vendor)

				images = append(images, &ImageSummary{
					RepoName:    &repo,
					Tag:         &tag,
					LastUpdated: &lastUpdated,
					Size:        &size,
					Platform:    osArch,
					Vendor:      &vendor,
					Score:       &score,
				})
			}
		}

		for layerBlob := range repoLayerBlob2Size {
			repoSize += repoLayerBlob2Size[layerBlob]
		}

		if index := strings.Index(repo, name); index != -1 {
			repoSize := strconv.FormatInt(repoSize, 10)

			repos = append(repos, &RepoSummary{
				Name:        &repo,
				LastUpdated: &lastUpdate,
				Size:        &repoSize,
				Platforms:   repoPlatforms,
				Vendors:     repoVendors,
				Score:       &index,
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

	for index > 1 {
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

func getGraphqlCompatibleTags(fixedTags []common.TagInfo) []*TagInfo {
	finalTagList := make([]*TagInfo, 0)

	for _, tag := range fixedTags {
		fixTag := tag

		finalTagList = append(finalTagList,
			&TagInfo{Name: &fixTag.Name, Digest: &fixTag.Digest, Timestamp: &fixTag.Timestamp})
	}

	return finalTagList
}
