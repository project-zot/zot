package search

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
)

// CVEListForImage is the resolver for the CVEListForImage field.
func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*gql_generated.CVEResultForImage, error) {
	trivyCtx := r.cveInfo.GetTrivyContext(image)

	r.log.Info().Str("image", image).Msg("scanning image")

	isValidImage, err := r.cveInfo.LayoutUtils.IsValidImageFormat(image)
	if !isValidImage {
		r.log.Debug().Str("image", image).Msg("image media type not supported for scanning")

		return &gql_generated.CVEResultForImage{}, err
	}

	report, err := cveinfo.ScanImage(trivyCtx.Ctx)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to scan image repository")

		return &gql_generated.CVEResultForImage{}, err
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
					&gql_generated.PackageInfo{Name: &pkgName, InstalledVersion: &installedVersion, FixedVersion: &fixedVersion})

				cveDetailStruct.PackageList = pkgList

				cveidMap[vulnerability.VulnerabilityID] = cveDetailStruct
			} else {
				newPkgList := make([]*gql_generated.PackageInfo, 0)

				newPkgList = append(newPkgList,
					&gql_generated.PackageInfo{Name: &pkgName, InstalledVersion: &installedVersion, FixedVersion: &fixedVersion})

				cveidMap[vulnerability.VulnerabilityID] = cveDetail{
					Title:       vulnerability.Title,
					Description: vulnerability.Description, Severity: vulnerability.Severity, PackageList: newPkgList,
				}
			}
		}
	}

	cveids := []*gql_generated.Cve{}

	for id, cveDetail := range cveidMap {
		vulID := id

		desc := cveDetail.Description

		title := cveDetail.Title

		severity := cveDetail.Severity

		pkgList := cveDetail.PackageList

		cveids = append(cveids,
			&gql_generated.Cve{ID: &vulID, Title: &title, Description: &desc, Severity: &severity, PackageList: pkgList})
	}

	return &gql_generated.CVEResultForImage{Tag: &copyImgTag, CVEList: cveids}, nil
}

// ImageListForCve is the resolver for the ImageListForCVE field.
func (r *queryResolver) ImageListForCve(ctx context.Context, id string) ([]*gql_generated.ImageSummary, error) {
	finalCveResult := []*gql_generated.ImageSummary{}

	r.log.Info().Msg("extracting repositories")

	defaultStore := r.storeController.DefaultStore

	defaultTrivyCtx := r.cveInfo.CveTrivyController.DefaultCveConfig

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return finalCveResult, err
	}

	r.cveInfo.Log.Info().Msg("scanning each global repository")

	cveResult, err := r.getImageListForCVE(repoList, id, defaultStore, defaultTrivyCtx)
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

		subCveResult, err := r.getImageListForCVE(subRepoList, id, store, subTrivyCtx)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get cve result for sub repositories")

			return finalCveResult, err
		}

		finalCveResult = append(finalCveResult, subCveResult...)
	}

	return finalCveResult, nil
}

// ImageListWithCVEFixed is the resolver for the ImageListWithCVEFixed field.
func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string) ([]*gql_generated.ImageSummary, error) {
	tagListForCVE := []*gql_generated.ImageSummary{}

	r.log.Info().Str("image", image).Msg("extracting list of tags available in image")

	tagsInfo, err := r.cveInfo.LayoutUtils.GetImageTagsWithTimestamp(image)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to read image tags")

		return tagListForCVE, err
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
				if vulnerability.VulnerabilityID == id {
					hasCVE = true

					break
				}
			}
		}

		if hasCVE {
			infectedTags = append(infectedTags, common.TagInfo{Name: tag.Name, Timestamp: tag.Timestamp, Digest: tag.Digest})
		}
	}

	if len(infectedTags) != 0 {
		r.log.Info().Msg("comparing fixed tags timestamp")

		tagsInfo = common.GetFixedTags(tagsInfo, infectedTags)
	} else {
		r.log.Info().Str("image", image).Str("cve-id", id).Msg("image does not contain any tag that have given cve")
	}

	for _, tag := range tagsInfo {
		digest := godigest.Digest(tag.Digest)

		manifest, err := r.cveInfo.LayoutUtils.GetImageBlobManifest(image, digest)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading manifest")

			return []*gql_generated.ImageSummary{}, err
		}

		imageInfo := buildImageInfo(image, tag.Name, digest, manifest)
		tagListForCVE = append(tagListForCVE, imageInfo)
	}

	return tagListForCVE, nil
}

// ImageListForDigest is the resolver for the ImageListForDigest field.
func (r *queryResolver) ImageListForDigest(ctx context.Context, id string) ([]*gql_generated.ImageSummary, error) {
	imgResultForDigest := []*gql_generated.ImageSummary{}

	r.log.Info().Msg("extracting repositories")

	defaultStore := r.storeController.DefaultStore

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return imgResultForDigest, err
	}

	r.log.Info().Msg("scanning each global repository")

	partialImgResultForDigest, err := r.getImageListForDigest(repoList, id)
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

		partialImgResultForDigest, err = r.getImageListForDigest(subRepoList, id)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get image and tag list for sub-repositories")

			return imgResultForDigest, err
		}

		imgResultForDigest = append(imgResultForDigest, partialImgResultForDigest...)
	}

	return imgResultForDigest, nil
}

// RepoListWithNewestImage is the resolver for the RepoListWithNewestImage field.
func (r *queryResolver) RepoListWithNewestImage(ctx context.Context) ([]*gql_generated.RepoSummary, error) {
	r.log.Info().Msg("extension api: finding image list")

	repoList := make([]*gql_generated.RepoSummary, 0)

	defaultStore := r.storeController.DefaultStore

	dsRepoList, err := r.repoListWithNewestImage(ctx, defaultStore)
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting default store image list")

		return repoList, err
	}

	if len(dsRepoList) != 0 {
		repoList = append(repoList, dsRepoList...)
	}

	subStore := r.storeController.SubStore

	for _, store := range subStore {
		ssRepoList, err := r.repoListWithNewestImage(ctx, store)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error extracting substore image list")

			return repoList, err
		}

		if len(ssRepoList) != 0 {
			repoList = append(repoList, ssRepoList...)
		}
	}

	return repoList, nil
}

// ImageList is the resolver for the ImageList field.
func (r *queryResolver) ImageList(ctx context.Context, repo string) ([]*gql_generated.ImageSummary, error) {
	r.log.Info().Msg("extension api: getting a list of all images")

	imageList := make([]*gql_generated.ImageSummary, 0)

	defaultStore := r.storeController.DefaultStore

	dsImageList, err := r.getImageList(defaultStore, repo)
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting default store image list")

		return imageList, err
	}

	if len(dsImageList) != 0 {
		imageList = append(imageList, dsImageList...)
	}

	subStore := r.storeController.SubStore

	for _, store := range subStore {
		ssImageList, err := r.getImageList(store, repo)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error extracting substore image list")

			return imageList, err
		}

		if len(ssImageList) != 0 {
			imageList = append(imageList, ssImageList...)
		}
	}

	return imageList, nil
}

// ExpandedRepoInfo is the resolver for the ExpandedRepoInfo field.
func (r *queryResolver) ExpandedRepoInfo(ctx context.Context, repo string) (*gql_generated.RepoInfo, error) {
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	origRepoInfo, err := olu.GetExpandedRepoInfo(repo)
	if err != nil {
		r.log.Error().Err(err).Msgf("error getting repo '%s'", repo)

		return &gql_generated.RepoInfo{}, err
	}

	// repos type is of common deep copy this to search
	repoInfo := &gql_generated.RepoInfo{}

	images := make([]*gql_generated.ImageSummary, 0)

	summary := &gql_generated.RepoSummary{}

	summary.LastUpdated = &origRepoInfo.Summary.LastUpdated
	summary.Name = &origRepoInfo.Summary.Name
	summary.Platforms = []*gql_generated.OsArch{}

	for _, platform := range origRepoInfo.Summary.Platforms {
		platform := platform

		summary.Platforms = append(summary.Platforms, &gql_generated.OsArch{
			Os:   &platform.Os,
			Arch: &platform.Arch,
		})
	}

	summary.Size = &origRepoInfo.Summary.Size

	for _, vendor := range origRepoInfo.Summary.Vendors {
		vendor := vendor
		summary.Vendors = append(summary.Vendors, &vendor)
	}

	score := -1 // score not relevant for this query
	summary.Score = &score

	for _, image := range origRepoInfo.Images {
		tag := image.Tag

		digest := image.Digest

		isSigned := image.IsSigned

		imageSummary := &gql_generated.ImageSummary{Tag: &tag, Digest: &digest, IsSigned: &isSigned}

		layers := make([]*gql_generated.LayerSummary, 0)

		for _, l := range image.Layers {
			size := l.Size

			digest := l.Digest

			layerInfo := &gql_generated.LayerSummary{Digest: &digest, Size: &size}

			layers = append(layers, layerInfo)
		}

		imageSummary.Layers = layers

		images = append(images, imageSummary)
	}

	repoInfo.Summary = summary
	repoInfo.Images = images

	return repoInfo, nil
}

// GlobalSearch is the resolver for the GlobalSearch field.
func (r *queryResolver) GlobalSearch(ctx context.Context, query string, requestedPage *gql_generated.PageInput) (*gql_generated.GlobalSearchResult, error) {
	query = cleanQuerry(query)

	repos, images, layers, err := globalSearch(ctx, query, r.repoDB, requestedPage, r.log)

	return &gql_generated.GlobalSearchResult{
		Images: images,
		Repos:  repos,
		Layers: layers,
	}, err
}

// DependencyListForImage is the resolver for the DependencyListForImage field.
func (r *queryResolver) DerivedImageList(ctx context.Context, image string) ([]*gql_generated.ImageSummary, error) {
	layoutUtils := common.NewBaseOciLayoutUtils(r.storeController, r.log)
	imageList := make([]*gql_generated.ImageSummary, 0)

	repoList, err := layoutUtils.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to get repositories list")

		return nil, err
	}

	if len(repoList) == 0 {
		r.log.Info().Msg("no repositories found")

		return imageList, nil
	}

	imageDir, imageTag := common.GetImageDirAndTag(image)

	imageManifest, err := layoutUtils.GetImageManifest(imageDir, imageTag)
	if err != nil {
		r.log.Info().Str("image", image).Msg("image not found")

		return imageList, err
	}

	imageLayers := imageManifest.Layers

	for _, repo := range repoList {
		repoInfo, err := r.ExpandedRepoInfo(ctx, repo)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get image list")

			return nil, err
		}

		manifests := repoInfo.Images

		// verify every image
		for _, manifest := range manifests {
			layers := manifest.Layers

			sameLayer := 0
			imageSize := 0

			for _, l := range imageLayers {
				for _, k := range layers {
					if *k.Digest == l.Digest.Encoded() {
						sameLayer++
						layerSize, _ := strconv.Atoi(*k.Size)
						imageSize += layerSize
					}
				}
			}

			// if all layers are the same
			if sameLayer == len(imageLayers) {
				// add to returned list
				name := repo
				manifest.RepoName = &name
				size := strconv.Itoa(imageSize)
				manifest.Size = &size
				imageList = append(imageList, manifest)
			}
		}
	}

	return imageList, nil
}

// Query returns gql_generated.QueryResolver implementation.
func (r *Resolver) Query() gql_generated.QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }
