package search

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"

	godigest "github.com/opencontainers/go-digest"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
)

// CVEListForImage is the resolver for the CVEListForImage field.
func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*gql_generated.CVEResultForImage, error) {
	cveidMap, err := r.cveInfo.GetCVEListForImage(image)
	if err != nil {
		return &gql_generated.CVEResultForImage{}, err
	}

	_, copyImgTag := common.GetImageDirAndTag(image)

	cveids := []*gql_generated.Cve{}

	for id, cveDetail := range cveidMap {
		vulID := id
		desc := cveDetail.Description
		title := cveDetail.Title
		severity := cveDetail.Severity

		pkgList := make([]*gql_generated.PackageInfo, 0)

		for _, pkg := range cveDetail.PackageList {
			pkg := pkg

			pkgList = append(pkgList,
				&gql_generated.PackageInfo{
					Name:             &pkg.Name,
					InstalledVersion: &pkg.InstalledVersion,
					FixedVersion:     &pkg.FixedVersion,
				},
			)
		}

		cveids = append(cveids,
			&gql_generated.Cve{
				ID:          &vulID,
				Title:       &title,
				Description: &desc,
				Severity:    &severity,
				PackageList: pkgList,
			},
		)
	}

	return &gql_generated.CVEResultForImage{Tag: &copyImgTag, CVEList: cveids}, nil
}

// ImageListForCve is the resolver for the ImageListForCVE field.
func (r *queryResolver) ImageListForCve(ctx context.Context, id string) ([]*gql_generated.ImageSummary, error) {
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	affectedImages := []*gql_generated.ImageSummary{}

	r.log.Info().Msg("extracting repositories")
	repoList, err := olu.GetRepositories()
	if err != nil { // nolint: wsl
		r.log.Error().Err(err).Msg("unable to search repositories")

		return affectedImages, err
	}

	r.log.Info().Msg("scanning each repository")

	for _, repo := range repoList {
		r.log.Info().Str("repo", repo).Msg("extracting list of tags available in image repo")

		imageListByCVE, err := r.cveInfo.GetImageListForCVE(repo, id)
		if err != nil {
			r.log.Error().Str("repo", repo).Str("CVE", id).Err(err).
				Msg("error getting image list for CVE from repo")

			return affectedImages, err
		}

		for _, imageByCVE := range imageListByCVE {
			imageConfig, err := olu.GetImageConfigInfo(repo, imageByCVE.Digest)
			if err != nil {
				return affectedImages, err
			}

			imageInfo := BuildImageInfo(repo, imageByCVE.Tag, imageByCVE.Digest, imageByCVE.Manifest, imageConfig)

			affectedImages = append(
				affectedImages,
				imageInfo,
			)
		}
	}

	return affectedImages, nil
}

// ImageListWithCVEFixed is the resolver for the ImageListWithCVEFixed field.
func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string) ([]*gql_generated.ImageSummary, error) {
	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	unaffectedImages := []*gql_generated.ImageSummary{}

	tagsInfo, err := r.cveInfo.GetImageListWithCVEFixed(image, id)
	if err != nil {
		return unaffectedImages, err
	}

	for _, tag := range tagsInfo {
		digest := godigest.Digest(tag.Digest)

		manifest, err := olu.GetImageBlobManifest(image, digest)
		if err != nil {
			r.log.Error().Err(err).Str("repo", image).Str("digest", tag.Digest).
				Msg("extension api: error reading manifest")

			return unaffectedImages, err
		}

		imageConfig, err := olu.GetImageConfigInfo(image, digest)
		if err != nil {
			return []*gql_generated.ImageSummary{}, err
		}

		imageInfo := BuildImageInfo(image, tag.Name, digest, manifest, imageConfig)

		unaffectedImages = append(unaffectedImages, imageInfo)
	}

	return unaffectedImages, nil
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

	olu := common.NewBaseOciLayoutUtils(r.storeController, r.log)

	reposSummary := make([]*gql_generated.RepoSummary, 0)

	repoList := []string{}

	defaultRepoList, err := r.storeController.DefaultStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting default store repo list")

		return reposSummary, err
	}

	if len(defaultRepoList) > 0 {
		repoList = append(repoList, defaultRepoList...)
	}

	subStore := r.storeController.SubStore
	for _, store := range subStore {
		subRepoList, err := store.GetRepositories()
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error extracting substore repo list")

			return reposSummary, err
		}

		repoList = append(repoList, subRepoList...)
	}

	reposSummary, err = repoListWithNewestImage(ctx, repoList, olu, r.cveInfo, r.log)
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting substore image list")

		return reposSummary, err
	}

	return reposSummary, nil
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
	summary.NewestImage = &gql_generated.ImageSummary{
		RepoName:     &origRepoInfo.Summary.NewestImage.RepoName,
		Tag:          &origRepoInfo.Summary.NewestImage.Tag,
		LastUpdated:  &origRepoInfo.Summary.NewestImage.LastUpdated,
		Digest:       &origRepoInfo.Summary.NewestImage.Digest,
		ConfigDigest: &origRepoInfo.Summary.NewestImage.ConfigDigest,
		IsSigned:     &origRepoInfo.Summary.NewestImage.IsSigned,
		Size:         &origRepoInfo.Summary.NewestImage.Size,
		Platform: &gql_generated.OsArch{
			Os:   &origRepoInfo.Summary.NewestImage.Platform.Os,
			Arch: &origRepoInfo.Summary.NewestImage.Platform.Arch,
		},
		Vendor:        &origRepoInfo.Summary.NewestImage.Vendor,
		Score:         &origRepoInfo.Summary.NewestImage.Score,
		Description:   &origRepoInfo.Summary.NewestImage.Description,
		Title:         &origRepoInfo.Summary.NewestImage.Title,
		Documentation: &origRepoInfo.Summary.NewestImage.Documentation,
		Licenses:      &origRepoInfo.Summary.NewestImage.Licenses,
		Labels:        &origRepoInfo.Summary.NewestImage.Labels,
		Source:        &origRepoInfo.Summary.NewestImage.Source,
	}

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

	for _, image := range origRepoInfo.ImageSummaries {
		tag := image.Tag
		digest := image.Digest
		isSigned := image.IsSigned
		size := image.Size

		imageSummary := &gql_generated.ImageSummary{Tag: &tag, Digest: &digest, IsSigned: &isSigned, RepoName: &repo}

		layers := make([]*gql_generated.LayerSummary, 0)

		for _, l := range image.Layers {
			size := l.Size
			digest := l.Digest

			layerInfo := &gql_generated.LayerSummary{Digest: &digest, Size: &size}

			layers = append(layers, layerInfo)
		}

		imageSummary.Layers = layers
		imageSummary.Size = &size
		images = append(images, imageSummary)
	}

	repoInfo.Summary = summary
	repoInfo.Images = images

	return repoInfo, nil
}

// GlobalSearch is the resolver for the GlobalSearch field.
func (r *queryResolver) GlobalSearch(ctx context.Context, query string, filter *gql_generated.Filter, requestedPage *gql_generated.PageInput) (*gql_generated.GlobalSearchResult, error) {
	query = cleanQuerry(query)

	repos, images, layers, err := globalSearch(ctx, query, r.repoDB, filter, requestedPage, r.cveInfo, r.log)

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

		imageSummaries := repoInfo.Images

		// verify every image
		for _, imageSummary := range imageSummaries {
			if imageTag == *imageSummary.Tag && imageDir == repo {
				continue
			}

			layers := imageSummary.Layers

			sameLayer := 0

			for _, l := range imageLayers {
				for _, k := range layers {
					if *k.Digest == l.Digest.Encoded() {
						sameLayer++
					}
				}
			}

			// if all layers are the same
			if sameLayer == len(imageLayers) {
				// add to returned list
				imageList = append(imageList, imageSummary)
			}
		}
	}

	return imageList, nil
}

// BaseImageList is the resolver for the BaseImageList field.
func (r *queryResolver) BaseImageList(ctx context.Context, image string) ([]*gql_generated.ImageSummary, error) {
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

	// This logic may not scale well in the future as we need to read all the
	// manifest files from the disk when the call is made, we should improve in a future PR
	for _, repo := range repoList {
		repoInfo, err := r.ExpandedRepoInfo(ctx, repo)
		if err != nil {
			r.log.Error().Err(err).Msg("unable to get image list")

			return nil, err
		}

		imageSummaries := repoInfo.Images

		var addImageToList bool
		// verify every image
		for _, imageSummary := range imageSummaries {
			if imageTag == *imageSummary.Tag && imageDir == repo {
				continue
			}

			addImageToList = true
			layers := imageSummary.Layers

			for _, l := range layers {
				foundLayer := false

				for _, k := range imageLayers {
					if *l.Digest == k.Digest.Encoded() {
						foundLayer = true

						break
					}
				}

				if !foundLayer {
					addImageToList = false

					break
				}
			}

			if addImageToList {
				imageList = append(imageList, imageSummary)
			}
		}
	}

	return imageList, nil
}

// Query returns gql_generated.QueryResolver implementation.
func (r *Resolver) Query() gql_generated.QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }
