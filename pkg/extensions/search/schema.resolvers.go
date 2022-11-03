package search

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"errors"

	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/convert"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	msConfig "zotregistry.io/zot/pkg/meta/config"
	"zotregistry.io/zot/pkg/storage/repodb"
)

// ToggleBookmark is the resolver for the ToggleBookmark field.
func (r *mutationResolver) ToggleBookmark(ctx context.Context, repo string) (*gql_generated.MutationResult, error) {
	acCtx := getAccessContext(ctx)
	// empty user is anonymous
	if acCtx.Username == "" {
		return &gql_generated.MutationResult{Success: false},
			ErrAnonymousIsNotAuthorized
	}
	// check user access level
	filteredRepos := filterRepos(acCtx, []string{repo})
	if len(filteredRepos) == 0 {
		return &gql_generated.MutationResult{Success: false},
			ErrNotAuthorized
	}

	// store to db
	_, err := r.metadata.ToggleBookmarkRepo(acCtx.Username, repo)
	if err != nil {
		return &gql_generated.MutationResult{Success: false}, err
	}

	return &gql_generated.MutationResult{Success: true}, nil
}

// ToggleStar is the resolver for the ToggleStar field.
func (r *mutationResolver) ToggleStar(ctx context.Context, repo string) (*gql_generated.MutationResult, error) {
	acCtx := getAccessContext(ctx)

	// empty user is anonymous
	if acCtx.Username == "" {
		return &gql_generated.MutationResult{Success: false},
			ErrAnonymousIsNotAuthorized
	}

	// check user access level
	filteredRepos := filterRepos(acCtx, []string{repo})
	if len(filteredRepos) == 0 {
		return &gql_generated.MutationResult{Success: false},
			ErrNotAuthorized
	}

	res, err := r.metadata.ToggleStarRepo(acCtx.Username, repo)
	if err != nil {
		return &gql_generated.MutationResult{Success: false}, err
	}

	if res == msConfig.Added {
		err = r.repoDB.IncrementRepoStars(repo)
	}

	if res == msConfig.Removed {
		err = r.repoDB.DecrementRepoStars(repo)
	}

	if err != nil {
		return &gql_generated.MutationResult{Success: false}, err
	}

	return &gql_generated.MutationResult{Success: true}, nil
}

// CVEListForImage is the resolver for the CVEListForImage field.
func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*gql_generated.CVEResultForImage, error) {
	return getCVEListForImage(ctx, image, r.cveInfo, r.log)
}

// ImageListForCve is the resolver for the ImageListForCVE field.
func (r *queryResolver) ImageListForCve(ctx context.Context, id string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	return getImageListForCVE(ctx, id, r.cveInfo, requestedPage, r.repoDB, r.log)
}

// ImageListWithCVEFixed is the resolver for the ImageListWithCVEFixed field.
func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	return getImageListWithCVEFixed(ctx, id, image, r.cveInfo, requestedPage, r.repoDB, r.log)
}

// ImageListForDigest is the resolver for the ImageListForDigest field.
func (r *queryResolver) ImageListForDigest(ctx context.Context, id string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	r.log.Info().Msg("extracting repositories")

	imgResultForDigest, err := getImageListForDigest(ctx, id, r.repoDB, r.cveInfo, requestedPage)

	return imgResultForDigest, err
}

// RepoListWithNewestImage is the resolver for the RepoListWithNewestImage field.
func (r *queryResolver) RepoListWithNewestImage(ctx context.Context, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedReposResult, error) {
	r.log.Info().Msg("extension api: finding image list")

	paginatedReposResult, err := repoListWithNewestImage(ctx, r.cveInfo, r.log, requestedPage, r.repoDB)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to retrieve repo list")

		return paginatedReposResult, err
	}

	return paginatedReposResult, nil
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
	repoInfo, err := expandedRepoInfo(ctx, repo, r.repoDB, r.cveInfo, r.log)

	return repoInfo, err
}

// GlobalSearch is the resolver for the GlobalSearch field.
func (r *queryResolver) GlobalSearch(ctx context.Context, query string, filter *gql_generated.Filter, requestedPage *gql_generated.PageInput) (*gql_generated.GlobalSearchResult, error) {
	if err := validateGlobalSearchInput(query, filter, requestedPage); err != nil {
		return &gql_generated.GlobalSearchResult{}, err
	}

	query = cleanQuery(query)
	filter = cleanFilter(filter)

	paginatedReposResult, images, layers, err := globalSearch(ctx, query, r.repoDB, filter, requestedPage, r.cveInfo, r.log)

	return &gql_generated.GlobalSearchResult{
		Page:   paginatedReposResult.Page,
		Images: images,
		Repos:  paginatedReposResult.Results,
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

	imageManifest, _, err := layoutUtils.GetImageManifest(imageDir, imageTag)
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
					if *k.Digest == l.Digest.String() {
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

	imageManifest, _, err := layoutUtils.GetImageManifest(imageDir, imageTag)
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
					if *l.Digest == k.Digest.String() {
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

// Image is the resolver for the Image field.
func (r *queryResolver) Image(ctx context.Context, image string) (*gql_generated.ImageSummary, error) {
	repo, tag := common.GetImageDirAndTag(image)

	return getImageSummary(ctx, repo, tag, r.repoDB, r.cveInfo, r.log)
}

// StarredRepos is the resolver for the StarredRepos field.
func (r *queryResolver) StarredRepos(ctx context.Context, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedReposResult, error) {
	paginatedRepos := &gql_generated.PaginatedReposResult{Results: []*gql_generated.RepoSummary{}}
	acCtx := getAccessContext(ctx)

	r.log.Info().Str("user", acCtx.Username).Msg("resolve StarredRepos for user")

	repoList, err := r.metadata.GetStarredRepos(acCtx.Username)
	if err != nil {
		return paginatedRepos, err
	}

	r.log.Info().Str("user", acCtx.Username).Int("repolist size", len(repoList)).
		Msg("resolve StarredRepos for user")

	// check user access level
	filteredRepos := filterReposMap(acCtx, repoList)
	filterFn := func(repoMeta repodb.RepoMetadata) bool {
		_, ok := filteredRepos[repoMeta.Name]

		return ok
	}

	r.log.Info().Str("user", acCtx.Username).Msg("after filteredReposMap")

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	r.log.Info().Str("user", acCtx.Username).Msg("after init requestedPage")

	requestedPageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaAlphabeticAsc),
		),
	}

	r.log.Info().Msg("resolve StarredRepos bf GetMultipleRepoMeta  for user")

	multiReposMeta, foundManifestMetadataMap, pageInfo, err := r.repoDB.FilterRepos(
		ctx, filterFn, requestedPageInput)
	if err != nil {
		return nil, err
	}

	repoSummaries := make([]*gql_generated.RepoSummary, len(multiReposMeta))
	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	r.log.Info().Msg("resolve StarredRepos af GetMultipleRepoMeta  for user")

	for index, repoMeta := range multiReposMeta {
		r.log.Info().Str("repoName", repoMeta.Name).
			Msg("resolve StarredRepos bf RepoMeta2RepoSummary for repoName")

		repoSummaries[index] = convert.RepoMeta2RepoSummary(
			ctx,
			repoMeta,
			foundManifestMetadataMap,
			skip,
			r.cveInfo,
		)

		r.log.Info().Str("repoName", repoMeta.Name).
			Msg("resolve StarredRepos af GetManifestMeta for manifestDigest")
	}

	paginatedRepos = &gql_generated.PaginatedReposResult{
		Results: repoSummaries,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}

	return paginatedRepos, nil
}

// BookmarkedRepos is the resolver for the BookmarkedRepos field.
func (r *queryResolver) BookmarkedRepos(ctx context.Context, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedReposResult, error) {
	paginatedRepos := &gql_generated.PaginatedReposResult{Results: []*gql_generated.RepoSummary{}}
	acCtx := getAccessContext(ctx)

	repoList, err := r.metadata.GetBookmarkedRepos(acCtx.Username)
	if err != nil {
		return paginatedRepos, err
	}

	// check user access level
	filteredRepos := filterReposMap(acCtx, repoList)
	filterFn := func(repoMeta repodb.RepoMetadata) bool {
		_, ok := filteredRepos[repoMeta.Name]

		return ok
	}

	requestedPageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	multiReposMeta, foundManifestMetadataMap, pageInfo, err := r.repoDB.FilterRepos(
		ctx, filterFn, requestedPageInput)
	if err != nil {
		return nil, err
	}

	repoSummaries := make([]*gql_generated.RepoSummary, len(multiReposMeta))
	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	for index, repoMeta := range multiReposMeta {
		repoSummaries[index] = convert.RepoMeta2RepoSummary(
			ctx,
			repoMeta,
			foundManifestMetadataMap,
			skip,
			r.cveInfo,
		)
	}

	paginatedRepos = &gql_generated.PaginatedReposResult{
		Results: repoSummaries,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}

	return paginatedRepos, nil
}

// Mutation returns gql_generated.MutationResolver implementation.
func (r *Resolver) Mutation() gql_generated.MutationResolver { return &mutationResolver{r} }

// Query returns gql_generated.QueryResolver implementation.
func (r *Resolver) Query() gql_generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }

// !!! WARNING !!!
// The code below was going to be deleted when updating resolvers. It has been copied here so you have
// one last chance to move it out of harms way if you want. There are two reasons this happens:
//   - When renaming or deleting a resolver the old code will be put in here. You can safely delete
//     it when you're done.
//   - You have helper methods in this file. Move them out to keep these resolver files clean.
var (
	ErrAnonymousIsNotAuthorized = errors.New("unidentified users cannot star repos")
	ErrNotAuthorized            = errors.New("resource does not exist or you are not authorized to see it")
)
