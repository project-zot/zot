package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage"
)

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

const (
	querySizeLimit = 256
)

// Resolver ...
type Resolver struct {
	cveInfo         cveinfo.CveInfo
	metaDB          metaTypes.MetaDB
	storeController storage.StoreController
	log             log.Logger
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController,
	metaDB metaTypes.MetaDB, cveInfo cveinfo.CveInfo,
) gql_generated.Config {
	resConfig := &Resolver{
		cveInfo:         cveInfo,
		metaDB:          metaDB,
		storeController: storeController,
		log:             log,
	}

	return gql_generated.Config{
		Resolvers: resConfig, Directives: gql_generated.DirectiveRoot{},
		Complexity: gql_generated.ComplexityRoot{},
	}
}

func NewResolver(log log.Logger, storeController storage.StoreController,
	metaDB metaTypes.MetaDB, cveInfo cveinfo.CveInfo,
) *Resolver {
	resolver := &Resolver{
		cveInfo:         cveInfo,
		metaDB:          metaDB,
		storeController: storeController,
		log:             log,
	}

	return resolver
}

func FilterByDigest(digest string) metaTypes.FilterFunc {
	return func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
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

func getImageListForDigest(ctx context.Context, digest string, metaDB metaTypes.MetaDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
) (*gql_generated.PaginatedImagesResult, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx, FilterByDigest(digest), pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap,
			skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getImageSummary(ctx context.Context, repo, tag string, digest *string, metaDB metaTypes.MetaDB,
	cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) (
	*gql_generated.ImageSummary, error,
) {
	repoMeta, err := metaDB.GetRepoMeta(repo)
	if err != nil {
		return nil, err
	}

	manifestDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return nil, gqlerror.Errorf("can't find image: %s:%s", repo, tag)
	}

	for t := range repoMeta.Tags {
		if t != tag {
			delete(repoMeta.Tags, t)
		}
	}

	var (
		manifestMetaMap = map[string]metaTypes.ManifestMetadata{}
		indexDataMap    = map[string]metaTypes.IndexData{}
	)

	switch manifestDescriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		manifestDigest := manifestDescriptor.Digest

		if digest != nil && *digest != manifestDigest {
			return nil, fmt.Errorf("resolver: can't get ManifestData for digest %s for image '%s:%s' %w",
				manifestDigest, repo, tag, zerr.ErrManifestDataNotFound)
		}

		manifestData, err := metaDB.GetManifestData(godigest.Digest(manifestDigest))
		if err != nil {
			return nil, err
		}

		manifestMetaMap[manifestDigest] = metaTypes.ManifestMetadata{
			ManifestBlob: manifestData.ManifestBlob,
			ConfigBlob:   manifestData.ConfigBlob,
		}
	case ispec.MediaTypeImageIndex:
		indexDigest := manifestDescriptor.Digest

		indexData, err := metaDB.GetIndexData(godigest.Digest(indexDigest))
		if err != nil {
			return nil, err
		}

		var indexContent ispec.Index

		err = json.Unmarshal(indexData.IndexBlob, &indexContent)
		if err != nil {
			return nil, err
		}

		if digest != nil {
			manifestDigest := *digest

			digestFound := false

			for _, manifest := range indexContent.Manifests {
				if manifest.Digest.String() == manifestDigest {
					digestFound = true

					break
				}
			}

			if !digestFound {
				return nil, fmt.Errorf("resolver: can't get ManifestData for digest %s for image '%s:%s' %w",
					manifestDigest, repo, tag, zerr.ErrManifestDataNotFound)
			}

			manifestData, err := metaDB.GetManifestData(godigest.Digest(manifestDigest))
			if err != nil {
				return nil, fmt.Errorf("resolver: can't get ManifestData for digest %s for image '%s:%s' %w",
					manifestDigest, repo, tag, err)
			}

			manifestMetaMap[manifestDigest] = metaTypes.ManifestMetadata{
				ManifestBlob: manifestData.ManifestBlob,
				ConfigBlob:   manifestData.ConfigBlob,
			}

			// We update the tag descriptor to be the manifest descriptor with digest specified in the
			// 'digest' parameter. We treat it as a standalone image.
			repoMeta.Tags[tag] = metaTypes.Descriptor{
				Digest:    manifestDigest,
				MediaType: ispec.MediaTypeImageManifest,
			}

			break
		}

		for _, manifest := range indexContent.Manifests {
			manifestData, err := metaDB.GetManifestData(manifest.Digest)
			if err != nil {
				return nil, fmt.Errorf("resolver: can't get ManifestData for digest %s for image '%s:%s' %w",
					manifest.Digest, repo, tag, err)
			}

			manifestMetaMap[manifest.Digest.String()] = metaTypes.ManifestMetadata{
				ManifestBlob: manifestData.ManifestBlob,
				ConfigBlob:   manifestData.ConfigBlob,
			}
		}

		indexDataMap[indexDigest] = indexData
	default:
		log.Error().Str("mediaType", manifestDescriptor.MediaType).Msg("resolver: media type not supported")
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}
	imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)

	if len(imageSummaries) == 0 {
		return &gql_generated.ImageSummary{}, nil
	}

	return imageSummaries[0], nil
}

func getCVEListForImage(
	ctx context.Context, //nolint:unparam // may be used in the future to filter by permissions
	image string,
	cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
	searchedCVE string,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
) (*gql_generated.CVEResultForImage, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := cveinfo.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: cveinfo.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaSeverity),
		),
	}

	repo, ref, isTag := zcommon.GetImageDirAndReference(image)

	if ref == "" {
		return &gql_generated.CVEResultForImage{}, gqlerror.Errorf("no reference provided")
	}

	if !isTag {
		return &gql_generated.CVEResultForImage{}, gqlerror.Errorf("reference by digest not supported")
	}

	cveList, pageInfo, err := cveInfo.GetCVEListForImage(repo, ref, searchedCVE, pageInput)
	if err != nil {
		return &gql_generated.CVEResultForImage{}, err
	}

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

	return &gql_generated.CVEResultForImage{
		Tag:     &ref,
		CVEList: cveids,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func FilterByTagInfo(tagsInfo []cvemodel.TagInfo) metaTypes.FilterFunc {
	return func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()

		for _, tagInfo := range tagsInfo {
			if tagInfo.Descriptor.Digest.String() == manifestDigest {
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
	metaDB metaTypes.MetaDB,
	log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	// Obtain all repos and tags
	// Infinite page to make sure we scan all repos in advance, before filtering results
	// The CVE scan logic is called from here, not in the actual filter,
	// this is because we shouldn't keep the DB locked while we wait on scan results
	reposMeta, err := metaDB.GetMultipleRepoMeta(ctx,
		func(repoMeta metaTypes.RepoMetadata) bool { return true },
		metaTypes.PageInput{Limit: 0, Offset: 0, SortBy: metaTypes.SortCriteria(gql_generated.SortCriteriaUpdateTime)},
	)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	affectedImages := []cvemodel.TagInfo{}

	for _, repoMeta := range reposMeta {
		repo := repoMeta.Name

		log.Info().Str("repository", repo).Str("CVE", cveID).Msg("extracting list of tags affected by CVE")

		tagsInfo, err := cveInfo.GetImageListForCVE(repo, cveID)
		if err != nil {
			log.Error().Str("repository", repo).Str("CVE", cveID).Err(err).
				Msg("error getting image list for CVE from repo")

			return &gql_generated.PaginatedImagesResult{}, err
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
	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx,
		FilterByTagInfo(affectedImages), pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getImageListWithCVEFixed(
	ctx context.Context,
	cveID string,
	repo string,
	cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
	metaDB metaTypes.MetaDB,
	log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	log.Info().Str("repository", repo).Str("CVE", cveID).Msg("extracting list of tags where CVE is fixed")

	tagsInfo, err := cveInfo.GetImageListWithCVEFixed(repo, cveID)
	if err != nil {
		log.Error().Str("repository", repo).Str("CVE", cveID).Err(err).
			Msg("error getting image list with CVE fixed from repo")

		return &gql_generated.PaginatedImagesResult{
			Page:    &gql_generated.PageInfo{},
			Results: imageList,
		}, err
	}

	// We're not interested in other vulnerabilities
	skip := convert.SkipQGLField{Vulnerabilities: true}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	// Actual page requested by user
	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx, FilterByTagInfo(tagsInfo), pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		if repoMeta.Name != repo {
			continue
		}

		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)
		imageList = append(imageList, imageSummaries...)
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func repoListWithNewestImage(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB metaTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	repos := []*gql_generated.RepoSummary{}
	paginatedRepos := &gql_generated.PaginatedReposResult{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Results.NewestImage.Vulnerabilities"),
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.SearchRepos(ctx, "", metaTypes.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	for _, repoMeta := range reposMeta {
		repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, indexDataMap,
			skip, cveInfo)
		repos = append(repos, repoSummary)
	}

	paginatedRepos.Page = &gql_generated.PageInfo{
		TotalCount: pageInfo.TotalCount,
		ItemCount:  pageInfo.ItemCount,
	}
	paginatedRepos.Results = repos

	return paginatedRepos, nil
}

func getBookmarkedRepos(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB metaTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	repoNames, err := metaDB.GetBookmarkedRepos(ctx)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	filterFn := func(repoMeta metaTypes.RepoMetadata) bool {
		return zcommon.Contains(repoNames, repoMeta.Name)
	}

	return getFilteredPaginatedRepos(ctx, cveInfo, filterFn, log, requestedPage, metaDB)
}

func getStarredRepos(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB metaTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	repoNames, err := metaDB.GetStarredRepos(ctx)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	filterFn := func(repoMeta metaTypes.RepoMetadata) bool {
		return zcommon.Contains(repoNames, repoMeta.Name)
	}

	return getFilteredPaginatedRepos(ctx, cveInfo, filterFn, log, requestedPage, metaDB)
}

func getFilteredPaginatedRepos(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	filterFn metaTypes.FilterRepoFunc,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB metaTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	repos := []*gql_generated.RepoSummary{}
	paginatedRepos := &gql_generated.PaginatedReposResult{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Results.NewestImage.Vulnerabilities"),
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterRepos(ctx, filterFn, pageInput)
	if err != nil {
		return paginatedRepos, err
	}

	for _, repoMeta := range reposMeta {
		repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, indexDataMap,
			skip, cveInfo)
		repos = append(repos, repoSummary)
	}

	paginatedRepos.Page = &gql_generated.PageInfo{
		TotalCount: pageInfo.TotalCount,
		ItemCount:  pageInfo.ItemCount,
	}
	paginatedRepos.Results = repos

	return paginatedRepos, nil
}

func globalSearch(ctx context.Context, query string, metaDB metaTypes.MetaDB, filter *gql_generated.Filter,
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

	localFilter := metaTypes.Filter{}
	if filter != nil {
		localFilter = metaTypes.Filter{
			Os:            filter.Os,
			Arch:          filter.Arch,
			HasToBeSigned: filter.HasToBeSigned,
			IsBookmarked:  filter.IsBookmarked,
			IsStarred:     filter.IsStarred,
		}
	}

	if searchingForRepos(query) {
		skip := convert.SkipQGLField{
			Vulnerabilities: canSkipField(preloads, "Repos.NewestImage.Vulnerabilities"),
		}

		pageInput := metaTypes.PageInput{
			Limit:  safeDerefferencing(requestedPage.Limit, 0),
			Offset: safeDerefferencing(requestedPage.Offset, 0),
			SortBy: metaTypes.SortCriteria(
				safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
			),
		}

		reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.SearchRepos(ctx, query, localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			repoSummary := convert.RepoMeta2RepoSummary(ctx, repoMeta, manifestMetaMap, indexDataMap,
				skip, cveInfo)

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

		pageInput := metaTypes.PageInput{
			Limit:  safeDerefferencing(requestedPage.Limit, 0),
			Offset: safeDerefferencing(requestedPage.Offset, 0),
			SortBy: metaTypes.SortCriteria(
				safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
			),
		}

		reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.SearchTags(ctx, query, localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		for _, repoMeta := range reposMeta {
			imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)

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

func derivedImageList(ctx context.Context, image string, digest *string, metaDB metaTypes.MetaDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	derivedList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := zcommon.GetImageDirAndTag(image)
	if imageTag == "" {
		return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("no reference provided")
	}

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, digest, metaDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("repository: not found")
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx,
		filterDerivedImages(searchedImage),
		pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		summary := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)
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

func filterDerivedImages(image *gql_generated.ImageSummary) metaTypes.FilterFunc {
	return func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
		var addImageToList bool

		var imageManifest ispec.Manifest

		err := json.Unmarshal(manifestMeta.ManifestBlob, &imageManifest)
		if err != nil {
			return false
		}

		for i := range image.Manifests {
			manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()
			if manifestDigest == *image.Manifests[i].Digest {
				return false
			}
			imageLayers := image.Manifests[i].Layers

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

			if addImageToList {
				return true
			}
		}

		return false
	}
}

func baseImageList(ctx context.Context, image string, digest *string, metaDB metaTypes.MetaDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	imageSummaries := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := zcommon.GetImageDirAndTag(image)

	if imageTag == "" {
		return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("no reference provided")
	}

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, digest, metaDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("repository: not found")
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx,
		filterBaseImages(searchedImage),
		pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		summary := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)
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

func filterBaseImages(image *gql_generated.ImageSummary) metaTypes.FilterFunc {
	return func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
		var addImageToList bool

		var manifestContent ispec.Manifest

		err := json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
		if err != nil {
			return false
		}

		for i := range image.Manifests {
			manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()
			if manifestDigest == *image.Manifests[i].Digest {
				return false
			}

			addImageToList = true

			for _, l := range manifestContent.Layers {
				foundLayer := false

				for _, k := range image.Manifests[i].Layers {
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

			if addImageToList {
				return true
			}
		}

		return false
	}
}

func validateGlobalSearchInput(query string, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput,
) error {
	if len(query) > querySizeLimit {
		return fmt.Errorf("global-search: max string size limit exeeded for query parameter. max=%d current=%d %w",
			querySizeLimit, len(query), zerr.ErrInvalidRequestParams)
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
			return fmt.Errorf("global-search: max string size limit exeeded for arch parameter. max=%d current=%d %w",
				querySizeLimit, len(*arch), zerr.ErrInvalidRequestParams)
		}
	}

	for _, osSys := range filter.Os {
		if len(*osSys) > querySizeLimit {
			return fmt.Errorf("global-search: max string size limit exeeded for os parameter. max=%d current=%d %w",
				querySizeLimit, len(*osSys), zerr.ErrInvalidRequestParams)
		}
	}

	return nil
}

func checkRequestedPage(requestedPage *gql_generated.PageInput) error {
	if requestedPage == nil {
		return nil
	}

	if requestedPage.Limit != nil && *requestedPage.Limit < 0 {
		return fmt.Errorf("global-search: requested page limit parameter can't be negative %w",
			zerr.ErrInvalidRequestParams)
	}

	if requestedPage.Offset != nil && *requestedPage.Offset < 0 {
		return fmt.Errorf("global-search: requested page offset parameter can't be negative %w",
			zerr.ErrInvalidRequestParams)
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

func expandedRepoInfo(ctx context.Context, repo string, metaDB metaTypes.MetaDB, cveInfo cveinfo.CveInfo,
	log log.Logger,
) (*gql_generated.RepoInfo, error) {
	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		log.Info().Err(err).Str("repository", repo).Bool("availability", ok).Msg("resolver: repo user availability")

		return &gql_generated.RepoInfo{}, nil //nolint:nilerr // don't give details to a potential attacker
	}

	repoMeta, err := metaDB.GetUserRepoMeta(ctx, repo)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Msg("resolver: can't retrieve repoMeta for repo")

		return &gql_generated.RepoInfo{}, err
	}

	var (
		manifestMetaMap = map[string]metaTypes.ManifestMetadata{}
		indexDataMap    = map[string]metaTypes.IndexData{}
	)

	for tag, descriptor := range repoMeta.Tags {
		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			digest := descriptor.Digest

			if _, alreadyDownloaded := manifestMetaMap[digest]; alreadyDownloaded {
				continue
			}

			manifestMeta, err := metaDB.GetManifestMeta(repo, godigest.Digest(digest))
			if err != nil {
				graphql.AddError(ctx, fmt.Errorf("resolver: failed to get manifest meta for image %s:%s with manifest digest %s %w",
					repo, tag, digest, err))

				continue
			}

			manifestMetaMap[digest] = manifestMeta
		case ispec.MediaTypeImageIndex:
			digest := descriptor.Digest

			if _, alreadyDownloaded := indexDataMap[digest]; alreadyDownloaded {
				continue
			}

			indexData, err := metaDB.GetIndexData(godigest.Digest(digest))
			if err != nil {
				graphql.AddError(ctx, fmt.Errorf("resolver: failed to get manifest meta for image %s:%s with manifest digest %s %w",
					repo, tag, digest, err))

				continue
			}

			var indexContent ispec.Index

			err = json.Unmarshal(indexData.IndexBlob, &indexContent)
			if err != nil {
				graphql.AddError(ctx, fmt.Errorf("resolver: failed to unmarshal index content for image %s:%s with digest %s %w",
					repo, tag, digest, err))

				continue
			}

			var errorOccured bool

			for _, descriptor := range indexContent.Manifests {
				manifestMeta, err := metaDB.GetManifestMeta(repo, descriptor.Digest)
				if err != nil {
					graphql.AddError(ctx,
						fmt.Errorf("resolver: failed to get manifest meta with digest '%s' for multiarch image %s:%s %w",
							digest, repo, tag, err),
					)

					errorOccured = true

					break
				}

				manifestMetaMap[descriptor.Digest.String()] = manifestMeta
			}

			if errorOccured {
				continue
			}

			indexDataMap[digest] = indexData
		default:
		}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Summary.NewestImage.Vulnerabilities") &&
			canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	repoSummary, imageSummaries := convert.RepoMeta2ExpandedRepoInfo(ctx, repoMeta, manifestMetaMap, indexDataMap,
		skip, cveInfo, log)

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

func getImageList(ctx context.Context, repo string, metaDB metaTypes.MetaDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput, log log.Logger, //nolint:unparam
) (*gql_generated.PaginatedImagesResult, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := metaTypes.PageInput{
		Limit:  safeDerefferencing(requestedPage.Limit, 0),
		Offset: safeDerefferencing(requestedPage.Offset, 0),
		SortBy: metaTypes.SortCriteria(
			safeDerefferencing(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	// reposMeta, manifestMetaMap, err := metaDB.SearchRepos(ctx, repo, metaTypes.Filter{}, pageInput)
	reposMeta, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(ctx,
		func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
			return true
		},
		pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	for _, repoMeta := range reposMeta {
		if repoMeta.Name != repo && repo != "" {
			continue
		}
		imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, manifestMetaMap, indexDataMap, skip, cveInfo)

		imageList = append(imageList, imageSummaries...)
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getReferrers(metaDB metaTypes.MetaDB, repo string, referredDigest string, artifactTypes []string,
	log log.Logger,
) ([]*gql_generated.Referrer, error) {
	refDigest := godigest.Digest(referredDigest)
	if err := refDigest.Validate(); err != nil {
		log.Error().Err(err).Str("digest", referredDigest).Msg("graphql: bad referenced digest string from request")

		return []*gql_generated.Referrer{}, fmt.Errorf("graphql: bad digest string from request '%s' %w",
			referredDigest, err)
	}

	referrers, err := metaDB.GetReferrersInfo(repo, refDigest, artifactTypes)
	if err != nil {
		return nil, err
	}

	results := make([]*gql_generated.Referrer, 0, len(referrers))

	for _, referrer := range referrers {
		referrer := referrer

		results = append(results, &gql_generated.Referrer{
			MediaType:    &referrer.MediaType,
			ArtifactType: &referrer.ArtifactType,
			Digest:       &referrer.Digest,
			Size:         &referrer.Size,
			Annotations:  convert.StringMap2Annotations(referrer.Annotations),
		})
	}

	return results, nil
}
