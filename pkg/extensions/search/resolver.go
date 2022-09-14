package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	glob "github.com/bmatcuk/doublestar/v4"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	digestinfo "zotregistry.io/zot/pkg/extensions/search/digest"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log" //nolint: gci
	"zotregistry.io/zot/pkg/meta"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

const (
	querySizeLimit = 256
)

// Resolver ...
type Resolver struct {
	cveInfo         cveinfo.CveInfo
	repoDB          repodb.RepoDB
	storeController storage.StoreController
	metadata        *meta.MetadataStore
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo, metadata *meta.MetadataStore,
) gql_generated.Config {
	digestInfo := digestinfo.NewDigestInfo(storeController, log)

	resConfig := &Resolver{
		cveInfo:         cveInfo,
		repoDB:          repoDB,
		storeController: storeController,
		digestInfo:      digestInfo,
		log:             log,
		metadata:        metadata,
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

			isSigned := olu.CheckManifestSignature(repo, imageInfo.Digest)
			imageInfo := convert.BuildImageInfo(repo, imageInfo.Tag, imageInfo.Digest,
				imageInfo.Manifest, imageConfig, isSigned)

			imgResultForDigest = append(imgResultForDigest, imageInfo)
		}
	}

	return imgResultForDigest, errResult
}

func getImageSummary(ctx context.Context, repo, tag string, repoDB repodb.RepoDB,
	cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) (
	*gql_generated.ImageSummary, error,
) {
	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil {
		return nil, err
	}

	manifestDigest, ok := repoMeta.Tags[tag]
	if !ok {
		return nil, gqlerror.Errorf("can't find image: %s:%s", repo, tag)
	}

	manifestMeta, err := repoDB.GetManifestMeta(godigest.Digest(manifestDigest))
	if err != nil {
		return nil, err
	}

	manifestMetaMap := map[string]repodb.ManifestMetadata{
		manifestDigest: manifestMeta,
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

	return imageSummaries[0], nil
}

func repoListWithNewestImage(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	repoDB repodb.RepoDB,
) ([]*gql_generated.RepoSummary, error) {
	repos := []*gql_generated.RepoSummary{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "NewestImage.Vulnerabilities"),
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	reposMeta, manifestMetaMap, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, pageInput)
	if err != nil {
		return []*gql_generated.RepoSummary{}, err
	}

	for _, repoMeta := range reposMeta {
		repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, skip, cveInfo)
		repos = append(repos, repoSummary)
	}

	return repos, nil
}

func globalSearch(ctx context.Context, query string, repoDB repodb.RepoDB, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput, cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) ([]*gql_generated.RepoSummary, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary, error,
) {
	preloads := convert.GetPreloads(ctx)
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
		skip := convert.SkipQGLField{
			Vulnerabilities: canSkipField(preloads, "Repos.NewestImage.Vulnerabilities"),
		}

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
			repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

			repos = append(repos, repoSummary)
		}
	} else { // search for images
		skip := convert.SkipQGLField{
			Vulnerabilities: canSkipField(preloads, "Images.Vulnerabilities"),
		}

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
			imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

			images = append(images, imageSummaries...)
		}
	}

	return repos, images, layers, nil
}

func canSkipField(preloads map[string]bool, s string) bool {
	fieldIsPresent := preloads[s]

	return !fieldIsPresent
}

func validateGlobalSearchInput(query string, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput,
) error {
	if len(query) > querySizeLimit {
		format := "global-search: max string size limit exeeded for query parameter. max=%d current=%d"

		return errors.Wrapf(zerr.ErrInvalidRequestParams, format, querySizeLimit, len(query))
	}

	err := checkFilter(filter)
	if err != nil {
		return err
	}

	err = checkRequestedPage(requestedPage)
	if err != nil {
		return err
	}

	return nil
}

func checkFilter(filter *gql_generated.Filter) error {
	if filter == nil {
		return nil
	}

	for _, arch := range filter.Arch {
		if len(*arch) > querySizeLimit {
			format := "global-search: max string size limit exeeded for arch parameter. max=%d current=%d"

			return errors.Wrapf(zerr.ErrInvalidRequestParams, format, querySizeLimit, len(*arch))
		}
	}

	for _, osSys := range filter.Os {
		if len(*osSys) > querySizeLimit {
			format := "global-search: max string size limit exeeded for os parameter. max=%d current=%d"

			return errors.Wrapf(zerr.ErrInvalidRequestParams, format, querySizeLimit, len(*osSys))
		}
	}

	return nil
}

func checkRequestedPage(requestedPage *gql_generated.PageInput) error {
	if requestedPage == nil {
		return nil
	}

	if requestedPage.Limit != nil && *requestedPage.Limit < 0 {
		format := "global-search: requested page limit parameter can't be negative"

		return errors.Wrap(zerr.ErrInvalidRequestParams, format)
	}

	if requestedPage.Offset != nil && *requestedPage.Offset < 0 {
		format := "global-search: requested page offset parameter can't be negative"

		return errors.Wrap(zerr.ErrInvalidRequestParams, format)
	}

	return nil
}

func cleanQuery(query string) string {
	query = strings.TrimSpace(query)
	query = strings.Trim(query, "/")
	query = strings.ToLower(query)

	return query
}

func cleanFilter(filter *gql_generated.Filter) *gql_generated.Filter {
	if filter == nil {
		return nil
	}

	if filter.Arch != nil {
		for i := range filter.Arch {
			*filter.Arch[i] = strings.ToLower(*filter.Arch[i])
			*filter.Arch[i] = strings.TrimSpace(*filter.Arch[i])
		}

		filter.Arch = deleteEmptyElements(filter.Arch)
	}

	if filter.Os != nil {
		for i := range filter.Os {
			*filter.Os[i] = strings.ToLower(*filter.Os[i])
			*filter.Os[i] = strings.TrimSpace(*filter.Os[i])
		}

		filter.Os = deleteEmptyElements(filter.Os)
	}

	return filter
}

func deleteEmptyElements(slice []*string) []*string {
	i := 0
	for i < len(slice) {
		if elementIsEmpty(*slice[i]) {
			slice = deleteElementAt(slice, i)
		} else {
			i++
		}
	}

	return slice
}

func elementIsEmpty(s string) bool {
	return s == ""
}

func deleteElementAt(slice []*string, i int) []*string {
	slice[i] = slice[len(slice)-1]
	slice = slice[:len(slice)-1]

	return slice
}

func expandedRepoInfo(ctx context.Context, repo string, repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.RepoInfo, error) {
	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		log.Info().Err(err).Msgf("resolver: 'repo %s is user available' = %v", repo, ok)

		return &gql_generated.RepoInfo{}, nil //nolint:nilerr // don't give details to a potential attacker
	}

	repoMeta, err := repoDB.GetRepoMeta(repo)
	if err != nil {
		log.Error().Err(err).Msgf("resolver: can't retrieve repoMeta for repo %s", repo)

		return &gql_generated.RepoInfo{}, err
	}

	manifestMetaMap := map[string]repodb.ManifestMetadata{}

	for tag, digest := range repoMeta.Tags {
		if _, alreadyDownloaded := manifestMetaMap[digest]; alreadyDownloaded {
			continue
		}

		manifestMeta, err := repoDB.GetManifestMeta(godigest.Digest(digest))
		if err != nil {
			graphql.AddError(ctx, errors.Wrapf(err,
				"resolver: failed to get manifest meta for image %s:%s with manifest digest %s", repo, tag, digest))

			continue
		}

		manifestMetaMap[digest] = manifestMeta
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Summary.NewestImage.Vulnerabilities"),
	}

	repoSummary, imageSummaries := convert.RepoMeta2ExpandedRepoInfo(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

	return &gql_generated.RepoInfo{Summary: repoSummary, Images: imageSummaries}, nil
}

func safeDerefferencing[T any](pointer *T, defaultVal T) T {
	if pointer != nil {
		return *pointer
	}

	return defaultVal
}

func searchingForRepos(query string) bool {
	return !strings.Contains(query, ":")
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
				digest := tag.Digest

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

				tagPrefix := strings.HasPrefix(tag.Name, "sha256-")
				tagSuffix := strings.HasSuffix(tag.Name, ".sig")

				imageInfo := convert.BuildImageInfo(repo, tag.Name, digest, manifest,
					imageConfig, isSigned)

				// check if it's an image or a signature
				if !tagPrefix && !tagSuffix {
					results = append(results, imageInfo)
				}
			}
		}
	}

	if len(results) == 0 {
		r.log.Info().Msg("no repositories found")
	}

	return results, nil
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
			err := zerr.ErrBadType

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
	repo, tag string, //nolint:unparam // function only called in the tests
	log log.Logger) (
	godigest.Digest, *ispec.Manifest, *ispec.Image, error,
) {
	validRepoList, err := userAvailableRepos(ctx, []string{repo})
	if err != nil {
		log.Error().Err(err).Msg("unable to retrieve access token")

		return "", nil, nil, err
	}

	if len(validRepoList) == 0 {
		log.Error().Err(err).Msg("user is not authorized")

		return "", nil, nil, zerr.ErrUnauthorizedAccess
	}

	manifest, dig, err := layoutUtils.GetImageManifest(repo, tag)
	if err != nil {
		log.Error().Err(err).Msg("Could not retrieve image ispec manifest")

		return "", nil, nil, err
	}

	digest := dig

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

func filterReposMap(acCtx localCtx.AccessControlContext, repoList []string) map[string]bool {
	availableRepos := map[string]bool{}

	for _, repoName := range repoList {
		if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, repoName) {
			availableRepos[repoName] = true
		}
	}

	return availableRepos
}
