package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"encoding/json"
	"sort"
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
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

const (
	querySizeLimit = 256
)

// Resolver ...
type Resolver struct {
	cveInfo         cveinfo.CveInfo
	repoDB          repodb.RepoDB
	storeController storage.StoreController
	digestInfo      *digestinfo.DigestInfo
	log             log.Logger
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo,
) gql_generated.Config {
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

func FilterByDigest(digest string) repodb.FilterFunc {
	return func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
		lookupDigest := digest
		contains := false

		var manifest ispec.Manifest

		err := json.Unmarshal(manifestMeta.ManifestBlob, &manifest)
		if err != nil {
			return false
		}

		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()

		// Check the image manifest in index.json matches the search digest
		// This is a blob with mediaType application/vnd.oci.image.manifest.v1+json
		if strings.Contains(manifestDigest, lookupDigest) {
			contains = true
		}

		// Check the image config matches the search digest
		// This is a blob with mediaType application/vnd.oci.image.config.v1+json
		if strings.Contains(manifest.Config.Digest.String(), lookupDigest) {
			contains = true
		}

		// Check to see if the individual layers in the oci image manifest match the digest
		// These are blobs with mediaType application/vnd.oci.image.layer.v1.tar+gzip
		for _, layer := range manifest.Layers {
			if strings.Contains(layer.Digest.String(), lookupDigest) {
				contains = true
			}
		}

		return contains
	}
}

func getImageListForDigest(ctx context.Context, digest string, repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
) ([]*gql_generated.ImageSummary, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, _, err := repoDB.FilterTags(ctx, FilterByDigest(digest), pageInput)
	if err != nil {
		return []*gql_generated.ImageSummary{}, err
	}

	for _, repoMeta := range reposMeta {
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return imageList, nil
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

	for t := range repoMeta.Tags {
		if t != tag {
			delete(repoMeta.Tags, t)
		}
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

func getCVEListForImage(
	ctx context.Context, //nolint:unparam // may be used in the future to filter by permissions
	image string,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
) (*gql_generated.CVEResultForImage, error) {
	cveList, err := cveInfo.GetCVEListForImage(image)
	if err != nil {
		return &gql_generated.CVEResultForImage{}, err
	}

	_, copyImgTag := common.GetImageDirAndTag(image)

	cveids := []*gql_generated.Cve{}

	for _, cveDetail := range cveList {
		vulID := cveDetail.ID
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

func FilterByTagInfo(tagsInfo []common.TagInfo) repodb.FilterFunc {
	return func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()

		for _, tagInfo := range tagsInfo {
			if tagInfo.Digest.String() == manifestDigest {
				return true
			}
		}

		return false
	}
}

func getImageListForCVE(
	ctx context.Context,
	cveID string,
	cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
	repoDB repodb.RepoDB,
	log log.Logger,
) ([]*gql_generated.ImageSummary, error) {
	// Obtain all repos and tags
	// Infinite page to make sure we scan all repos in advance, before filtering results
	// The CVE scan logic is called from here, not in the actual filter,
	// this is because we shouldn't keep the DB locked while we wait on scan results
	reposMeta, err := repoDB.GetMultipleRepoMeta(ctx,
		func(repoMeta repodb.RepoMetadata) bool { return true },
		repodb.PageInput{Limit: 0, Offset: 0, SortBy: repodb.SortCriteria(gql_generated.SortCriteriaUpdateTime)},
	)
	if err != nil {
		return []*gql_generated.ImageSummary{}, err
	}

	affectedImages := []common.TagInfo{}

	for _, repoMeta := range reposMeta {
		repo := repoMeta.Name

		log.Info().Str("repo", repo).Str("CVE", cveID).Msg("extracting list of tags affected by CVE")

		tagsInfo, err := cveInfo.GetImageListForCVE(repo, cveID)
		if err != nil {
			log.Error().Str("repo", repo).Str("CVE", cveID).Err(err).
				Msg("error getting image list for CVE from repo")

			return []*gql_generated.ImageSummary{}, err
		}

		affectedImages = append(affectedImages, tagsInfo...)
	}

	imageList := make([]*gql_generated.ImageSummary, 0)

	// We're not interested in other vulnerabilities
	skip := convert.SkipQGLField{Vulnerabilities: true}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	// Actual page requested by user
	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, _, err := repoDB.FilterTags(ctx, FilterByTagInfo(affectedImages), pageInput)
	if err != nil {
		return []*gql_generated.ImageSummary{}, err
	}

	for _, repoMeta := range reposMeta {
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return imageList, nil
}

func getImageListWithCVEFixed(
	ctx context.Context,
	cveID string,
	repo string,
	cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
	repoDB repodb.RepoDB,
	log log.Logger,
) ([]*gql_generated.ImageSummary, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	log.Info().Str("repo", repo).Str("CVE", cveID).Msg("extracting list of tags where CVE is fixed")

	tagsInfo, err := cveInfo.GetImageListWithCVEFixed(repo, cveID)
	if err != nil {
		log.Error().Str("repo", repo).Str("CVE", cveID).Err(err).
			Msg("error getting image list with CVE fixed from repo")

		return imageList, err
	}

	// We're not interested in other vulnerabilities
	skip := convert.SkipQGLField{Vulnerabilities: true}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	// Actual page requested by user
	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, _, err := repoDB.FilterTags(ctx, FilterByTagInfo(tagsInfo), pageInput)
	if err != nil {
		return []*gql_generated.ImageSummary{}, err
	}

	for _, repoMeta := range reposMeta {
		if repoMeta.Name != repo {
			continue
		}

		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)
		imageList = append(imageList, imageSummaries...)
	}

	return imageList, nil
}

func repoListWithNewestImage(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	repoDB repodb.RepoDB,
) (*gql_generated.PaginatedReposResult, error) {
	repos := []*gql_generated.RepoSummary{}
	paginatedRepos := &gql_generated.PaginatedReposResult{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Results.NewestImage.Vulnerabilities"),
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	reposMeta, manifestMetaMap, pageInfo, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	for _, repoMeta := range reposMeta {
		repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, skip, cveInfo)
		repos = append(repos, repoSummary)
	}

	paginatedRepos.Page = &gql_generated.PageInfo{
		TotalCount: pageInfo.TotalCount,
		ItemCount:  pageInfo.ItemCount,
	}
	paginatedRepos.Results = repos

	return paginatedRepos, nil
}

func globalSearch(ctx context.Context, query string, repoDB repodb.RepoDB, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput, cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) (*gql_generated.PaginatedReposResult, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary, error,
) {
	preloads := convert.GetPreloads(ctx)
	repos := []*gql_generated.RepoSummary{}
	paginatedRepos := gql_generated.PaginatedReposResult{}
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

		reposMeta, manifestMetaMap, pageInfo, err := repoDB.SearchRepos(ctx, query, localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

			repos = append(repos, repoSummary)
		}

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}

		paginatedRepos.Results = repos
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

		reposMeta, manifestMetaMap, pageInfo, err := repoDB.SearchTags(ctx, query, localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

			images = append(images, imageSummaries...)
		}

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}
	}

	return &paginatedRepos, images, layers, nil
}

func canSkipField(preloads map[string]bool, s string) bool {
	fieldIsPresent := preloads[s]

	return !fieldIsPresent
}

func derivedImageList(ctx context.Context, image string, repoDB repodb.RepoDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	derivedList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := common.GetImageDirAndTag(image)

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, repoDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, nil
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	reposMeta, manifestMetaMap, pageInfo, err := repoDB.FilterTags(ctx,
		filterDerivedImages(searchedImage),
		pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		summary := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)
		derivedList = append(derivedList, summary...)
	}

	if len(derivedList) == 0 {
		log.Info().Msg("no images found")

		return &gql_generated.PaginatedImagesResult{
			Page:    &gql_generated.PageInfo{},
			Results: derivedList,
		}, nil
	}

	return &gql_generated.PaginatedImagesResult{
		Results: derivedList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func filterDerivedImages(image *gql_generated.ImageSummary) repodb.FilterFunc {
	return func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
		var addImageToList bool

		var imageManifest ispec.Manifest

		err := json.Unmarshal(manifestMeta.ManifestBlob, &imageManifest)
		if err != nil {
			return false
		}

		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()
		if manifestDigest == *image.Digest {
			return false
		}

		imageLayers := image.Layers

		addImageToList = false
		layers := imageManifest.Layers

		sameLayer := 0

		for _, l := range imageLayers {
			for _, k := range layers {
				if k.Digest.String() == *l.Digest {
					sameLayer++
				}
			}
		}

		// if all layers are the same
		if sameLayer == len(imageLayers) {
			// it's a derived image
			addImageToList = true
		}

		return addImageToList
	}
}

func baseImageList(ctx context.Context, image string, repoDB repodb.RepoDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	imageSummaries := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := common.GetImageDirAndTag(image)

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, repoDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, nil
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	reposMeta, manifestMetaMap, pageInfo, err := repoDB.FilterTags(ctx,
		filterBaseImages(searchedImage),
		pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		summary := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)
		imageSummaries = append(imageSummaries, summary...)
	}

	if len(imageSummaries) == 0 {
		log.Info().Msg("no images found")

		return &gql_generated.PaginatedImagesResult{
			Results: imageSummaries,
			Page:    &gql_generated.PageInfo{},
		}, nil
	}

	return &gql_generated.PaginatedImagesResult{
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
		Results: imageSummaries,
	}, nil
}

func filterBaseImages(image *gql_generated.ImageSummary) repodb.FilterFunc {
	return func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
		var addImageToList bool

		var imageManifest ispec.Manifest

		err := json.Unmarshal(manifestMeta.ManifestBlob, &imageManifest)
		if err != nil {
			return false
		}

		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()
		if manifestDigest == *image.Digest {
			return false
		}

		imageLayers := image.Layers

		addImageToList = true
		layers := imageManifest.Layers

		for _, l := range layers {
			foundLayer := false

			for _, k := range imageLayers {
				if l.Digest.String() == *k.Digest {
					foundLayer = true

					break
				}
			}

			if !foundLayer {
				addImageToList = false

				break
			}
		}

		return addImageToList
	}
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

	dateSortedImages := make(timeSlice, 0, len(imageSummaries))
	for _, imgSummary := range imageSummaries {
		dateSortedImages = append(dateSortedImages, imgSummary)
	}

	sort.Sort(dateSortedImages)

	return &gql_generated.RepoInfo{Summary: repoSummary, Images: dateSortedImages}, nil
}

type timeSlice []*gql_generated.ImageSummary

func (p timeSlice) Len() int {
	return len(p)
}

func (p timeSlice) Less(i, j int) bool {
	return p[i].LastUpdated.After(*p[j].LastUpdated)
}

func (p timeSlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
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

func getImageList(ctx context.Context, repo string, repoDB repodb.RepoDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput, log log.Logger, //nolint:unparam
) ([]*gql_generated.ImageSummary, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := repodb.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: repodb.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	// reposMeta, manifestMetaMap, err := repoDB.SearchRepos(ctx, repo, repodb.Filter{}, pageInput)
	reposMeta, manifestMetaMap, _, err := repoDB.FilterTags(ctx,
		func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
			return true
		},
		pageInput)
	if err != nil {
		return []*gql_generated.ImageSummary{}, err
	}

	for _, repoMeta := range reposMeta {
		if repoMeta.Name != repo && repo != "" {
			continue
		}
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return imageList, nil
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
