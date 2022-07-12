package search

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"
	"strings"

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
func (r *queryResolver) ImageListForCve(ctx context.Context, id string) ([]*gql_generated.ImgResultForCve, error) {
	finalCveResult := []*gql_generated.ImgResultForCve{}

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
func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string) (*gql_generated.ImgResultForFixedCve, error) {
	imgResultForFixedCVE := &gql_generated.ImgResultForFixedCve{}

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

	var finalTagList []*gql_generated.TagInfo

	if len(infectedTags) != 0 {
		r.log.Info().Msg("comparing fixed tags timestamp")

		fixedTags := common.GetFixedTags(tagsInfo, infectedTags)

		finalTagList = getGraphqlCompatibleTags(fixedTags)
	} else {
		r.log.Info().Str("image", image).Str("cve-id", id).Msg("image does not contain any tag that have given cve")

		finalTagList = getGraphqlCompatibleTags(tagsInfo)
	}

	imgResultForFixedCVE = &gql_generated.ImgResultForFixedCve{Tags: finalTagList}

	return imgResultForFixedCVE, nil
}

// ImageListForDigest is the resolver for the ImageListForDigest field.
func (r *queryResolver) ImageListForDigest(ctx context.Context, id string) ([]*gql_generated.ImgResultForDigest, error) {
	imgResultForDigest := []*gql_generated.ImgResultForDigest{}

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

// ImageListWithLatestTag is the resolver for the ImageListWithLatestTag field.
func (r *queryResolver) ImageListWithLatestTag(ctx context.Context) ([]*gql_generated.ImageInfo, error) {
	r.log.Info().Msg("extension api: finding image list")

	imageList := make([]*gql_generated.ImageInfo, 0)

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

	manifests := make([]*gql_generated.ManifestInfo, 0)

	for _, manifest := range origRepoInfo.Manifests {
		tag := manifest.Tag

		digest := manifest.Digest

		isSigned := manifest.IsSigned

		manifestInfo := &gql_generated.ManifestInfo{Tag: &tag, Digest: &digest, IsSigned: &isSigned}

		layers := make([]*gql_generated.LayerInfo, 0)

		for _, l := range manifest.Layers {
			size := l.Size

			digest := l.Digest

			layerInfo := &gql_generated.LayerInfo{Digest: &digest, Size: &size}

			layers = append(layers, layerInfo)
		}

		manifestInfo.Layers = layers

		manifests = append(manifests, manifestInfo)
	}

	repoInfo.Manifests = manifests

	return repoInfo, nil
}

// GlobalSearch is the resolver for the GlobalSearch field.
func (r *queryResolver) GlobalSearch(ctx context.Context, query string) (*gql_generated.GlobalSearchResult, error) {
	query = cleanQuerry(query)
	defaultStore := r.storeController.DefaultStore
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	var name, tag string

	_, err := fmt.Sscanf(query, "%s %s", &name, &tag)
	if err != nil {
		name = query
	}

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("unable to search repositories")

		return &gql_generated.GlobalSearchResult{}, err
	}

	repos, images, layers := globalSearch(repoList, name, tag, olu, r.log)

	return &gql_generated.GlobalSearchResult{
		Images: images,
		Repos:  repos,
		Layers: layers,
	}, nil
}

// Query returns gql_generated.QueryResolver implementation.
func (r *Resolver) Query() gql_generated.QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }
