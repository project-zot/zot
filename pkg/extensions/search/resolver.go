package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vektah/gqlparser/v2/gqlerror"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.dev/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/pkg/extensions/search/pagination"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	"zotregistry.dev/zot/pkg/storage"
)

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

const (
	querySizeLimit = 256
)

// Resolver ...
type Resolver struct {
	cveInfo         cveinfo.CveInfo
	metaDB          mTypes.MetaDB
	storeController storage.StoreController
	log             log.Logger
}

// GetResolverConfig ...
func GetResolverConfig(log log.Logger, storeController storage.StoreController,
	metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo,
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
	metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo,
) *Resolver {
	resolver := &Resolver{
		cveInfo:         cveInfo,
		metaDB:          metaDB,
		storeController: storeController,
		log:             log,
	}

	return resolver
}

func FilterByDigest(digest string) mTypes.FilterFunc {
	// imageMeta will always contain 1 manifest
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		lookupDigest := digest

		// Check in case of an index if the index digest matches the search digest
		// For Manifests, this is equivalent to imageMeta.Manifests[0]
		if imageMeta.Digest.String() == lookupDigest {
			return true
		}

		manifest := imageMeta.Manifests[0]

		manifestDigest := manifest.Digest.String()

		// Check the image manifest in index.json matches the search digest
		// This is a blob with mediaType application/vnd.oci.image.manifest.v1+json
		if strings.Contains(manifestDigest, lookupDigest) {
			return true
		}

		// Check the image config matches the search digest
		// This is a blob with mediaType application/vnd.oci.image.config.v1+json
		if strings.Contains(manifest.Manifest.Config.Digest.String(), lookupDigest) {
			return true
		}

		// Check to see if the individual layers in the oci image manifest match the digest
		// These are blobs with mediaType application/vnd.oci.image.layer.v1.tar+gzip
		for _, layer := range manifest.Manifest.Layers {
			if strings.Contains(layer.Digest.String(), lookupDigest) {
				return true
			}
		}

		return false
	}
}

func getImageListForDigest(ctx context.Context, digest string, metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
) (*gql_generated.PaginatedImagesResult, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, FilterByDigest(digest))
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList, skip,
		cveInfo, mTypes.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageSummaries,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getImageSummary(ctx context.Context, repo, tag string, digest *string, skipCVE convert.SkipQGLField,
	metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) (
	*gql_generated.ImageSummary, error,
) {
	repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		return nil, err
	}

	manifestDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return nil, gqlerror.Errorf("can't find image: %s:%s", repo, tag)
	}

	repoMeta.Tags = map[mTypes.Tag]mTypes.Descriptor{tag: manifestDescriptor}

	imageDigest := manifestDescriptor.Digest
	if digest != nil {
		imageDigest = *digest
		repoMeta.Tags[tag] = mTypes.Descriptor{
			Digest:    imageDigest,
			MediaType: ispec.MediaTypeImageManifest,
		}
	}

	imageMetaMap, err := metaDB.FilterImageMeta(ctx, []string{imageDigest})
	if err != nil {
		return &gql_generated.ImageSummary{}, err
	}

	imageSummaries := convert.RepoMeta2ImageSummaries(ctx, repoMeta, imageMetaMap, skipCVE, cveInfo)

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
	excludedCVE string,
	severity string,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
) (*gql_generated.CVEResultForImage, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := cvemodel.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: cvemodel.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaSeverity),
		),
	}

	repo, ref, _ := zcommon.GetImageDirAndReference(image)

	if ref == "" {
		return &gql_generated.CVEResultForImage{}, gqlerror.Errorf("no reference provided")
	}

	cveList, imageCveSummary, pageInfo, err := cveInfo.GetCVEListForImage(ctx, repo, ref,
		searchedCVE, excludedCVE, severity, pageInput)
	if err != nil {
		return &gql_generated.CVEResultForImage{}, err
	}

	cveids := []*gql_generated.Cve{}

	for _, cveDetail := range cveList {
		vulID := cveDetail.ID
		desc := cveDetail.Description
		title := cveDetail.Title
		severity := cveDetail.Severity
		referenceURL := cveDetail.Reference

		pkgList := make([]*gql_generated.PackageInfo, 0)

		for _, pkg := range cveDetail.PackageList {
			pkg := pkg

			pkgList = append(pkgList,
				&gql_generated.PackageInfo{
					Name:             &pkg.Name,
					PackagePath:      &pkg.PackagePath,
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
				Reference:   &referenceURL,
				PackageList: pkgList,
			},
		)
	}

	return &gql_generated.CVEResultForImage{
		Tag:     &ref,
		CVEList: cveids,
		Summary: &gql_generated.ImageVulnerabilitySummary{
			MaxSeverity:   &imageCveSummary.MaxSeverity,
			UnknownCount:  &imageCveSummary.UnknownCount,
			LowCount:      &imageCveSummary.LowCount,
			MediumCount:   &imageCveSummary.MediumCount,
			HighCount:     &imageCveSummary.HighCount,
			CriticalCount: &imageCveSummary.CriticalCount,
			Count:         &imageCveSummary.Count,
		},
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getCVEDiffListForImages(
	ctx context.Context, //nolint:unparam // may be used in the future to filter by permissions
	minuend gql_generated.ImageInput,
	subtrahend gql_generated.ImageInput,
	metaDB mTypes.MetaDB,
	cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput,
	searchedCVE string,
	excludedCVE string,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
) (*gql_generated.CVEDiffResult, error) {
	minuend, err := resolveImageData(ctx, minuend, metaDB)
	if err != nil {
		return nil, err
	}

	resultMinuend := getImageIdentifier(minuend)
	resultSubtrahend := gql_generated.ImageIdentifier{}

	if subtrahend.Repo != "" {
		subtrahend, err = resolveImageData(ctx, subtrahend, metaDB)
		if err != nil {
			return nil, err
		}
		resultSubtrahend = getImageIdentifier(subtrahend)
	} else {
		// search for base images
		// get minuend image meta
		minuendSummary, err := metaDB.GetImageMeta(godigest.Digest(deref(minuend.Digest, "")))
		if err != nil {
			return &gql_generated.CVEDiffResult{}, err
		}

		// get the base images for the minuend
		minuendBaseImages, err := metaDB.FilterTags(ctx, mTypes.AcceptOnlyRepo(minuend.Repo),
			filterBaseImagesForMeta(minuendSummary))
		if err != nil {
			return &gql_generated.CVEDiffResult{}, err
		}

		// get the best base image as subtrahend
		// get the one with most layers in common
		imgLayers := map[string]struct{}{}

		for _, layer := range minuendSummary.Manifests[0].Manifest.Layers {
			imgLayers[layer.Digest.String()] = struct{}{}
		}

		bestMatchingScore := 0

		for _, baseImage := range minuendBaseImages {
			for _, baseManifest := range baseImage.Manifests {
				currentMatchingScore := 0

				for _, layer := range baseManifest.Manifest.Layers {
					if _, ok := imgLayers[layer.Digest.String()]; ok {
						currentMatchingScore++
					}
				}

				if currentMatchingScore > bestMatchingScore {
					bestMatchingScore = currentMatchingScore

					resultSubtrahend = gql_generated.ImageIdentifier{
						Repo:   baseImage.Repo,
						Tag:    baseImage.Tag,
						Digest: ref(baseImage.Manifests[0].Digest.String()),
						Platform: &gql_generated.Platform{
							Os:   ref(baseImage.Manifests[0].Config.OS),
							Arch: ref(getArch(baseImage.Manifests[0].Config.Platform)),
						},
					}
					subtrahend.Repo = baseImage.Repo
					subtrahend.Tag = baseImage.Tag
					subtrahend.Digest = ref(baseImage.Manifests[0].Digest.String())
				}
			}
		}
	}

	minuendRepoRef := minuend.Repo + "@" + deref(minuend.Digest, "")
	subtrahendRepoRef := subtrahend.Repo + "@" + deref(subtrahend.Digest, "")
	page := dderef(requestedPage)

	diffCVEs, diffSummary, _, err := cveInfo.GetCVEDiffListForImages(ctx, minuendRepoRef, subtrahendRepoRef, searchedCVE,
		excludedCVE, cvemodel.PageInput{
			Limit:  deref(page.Limit, 0),
			Offset: deref(page.Offset, 0),
			SortBy: cvemodel.SortCriteria(deref(page.SortBy, gql_generated.SortCriteriaSeverity)),
		})
	if err != nil {
		return nil, err
	}

	cveids := []*gql_generated.Cve{}

	for _, cveDetail := range diffCVEs {
		vulID := cveDetail.ID
		desc := cveDetail.Description
		title := cveDetail.Title
		severity := cveDetail.Severity
		referenceURL := cveDetail.Reference

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
				Reference:   &referenceURL,
				PackageList: pkgList,
			},
		)
	}

	return &gql_generated.CVEDiffResult{
		Minuend:    &resultMinuend,
		Subtrahend: &resultSubtrahend,
		Summary: &gql_generated.ImageVulnerabilitySummary{
			Count:         &diffSummary.Count,
			UnknownCount:  &diffSummary.UnknownCount,
			LowCount:      &diffSummary.LowCount,
			MediumCount:   &diffSummary.MediumCount,
			HighCount:     &diffSummary.HighCount,
			CriticalCount: &diffSummary.CriticalCount,
			MaxSeverity:   &diffSummary.MaxSeverity,
		},
		CVEList: cveids,
		Page:    &gql_generated.PageInfo{},
	}, nil
}

func getImageIdentifier(img gql_generated.ImageInput) gql_generated.ImageIdentifier {
	return gql_generated.ImageIdentifier{
		Repo:     img.Repo,
		Tag:      img.Tag,
		Digest:   img.Digest,
		Platform: getIdentifierPlatform(img.Platform),
	}
}

func getIdentifierPlatform(platform *gql_generated.PlatformInput) *gql_generated.Platform {
	if platform == nil {
		return nil
	}

	return &gql_generated.Platform{
		Os:   platform.Os,
		Arch: platform.Arch,
	}
}

// rename idea: identify image from input.
func resolveImageData(ctx context.Context, imageInput gql_generated.ImageInput, metaDB mTypes.MetaDB,
) (gql_generated.ImageInput, error) {
	if imageInput.Repo == "" {
		return gql_generated.ImageInput{}, zerr.ErrEmptyRepoName
	}

	if imageInput.Tag == "" {
		return gql_generated.ImageInput{}, zerr.ErrEmptyTag
	}

	// try checking if the tag is a simple image first
	repoMeta, err := metaDB.GetRepoMeta(ctx, imageInput.Repo)
	if err != nil {
		return gql_generated.ImageInput{}, err
	}

	descriptor, ok := repoMeta.Tags[imageInput.Tag]
	if !ok {
		return gql_generated.ImageInput{}, zerr.ErrImageNotFound
	}

	switch descriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		imageInput.Digest = ref(descriptor.Digest)

		return imageInput, nil
	case ispec.MediaTypeImageIndex:
		if dderef(imageInput.Digest) == "" && !isPlatformSpecified(imageInput.Platform) {
			return gql_generated.ImageInput{},
				fmt.Errorf("%w: platform or specific manifest digest needed", zerr.ErrAmbiguousInput)
		}

		imageMeta, err := metaDB.GetImageMeta(godigest.Digest(descriptor.Digest))
		if err != nil {
			return gql_generated.ImageInput{}, err
		}

		for _, manifest := range imageMeta.Manifests {
			if manifest.Digest.String() == dderef(imageInput.Digest) ||
				isMatchingPlatform(manifest.Config.Platform, dderef(imageInput.Platform)) {
				imageInput.Digest = ref(manifest.Digest.String())
				imageInput.Platform = &gql_generated.PlatformInput{
					Os:   ref(manifest.Config.OS),
					Arch: ref(getArch(manifest.Config.Platform)),
				}

				return imageInput, nil
			}
		}

		return imageInput, zerr.ErrImageNotFound
	}

	return imageInput, nil
}

func isPlatformSpecified(platformInput *gql_generated.PlatformInput) bool {
	if platformInput == nil {
		return false
	}

	if dderef(platformInput.Os) == "" || dderef(platformInput.Arch) == "" {
		return false
	}

	return true
}

func isMatchingPlatform(platform ispec.Platform, platformInput gql_generated.PlatformInput) bool {
	if platform.OS != deref(platformInput.Os, "") {
		return false
	}

	arch := getArch(platform)

	return arch == deref(platformInput.Arch, "")
}

func getArch(platform ispec.Platform) string {
	arch := platform.Architecture
	if arch != "" && platform.Variant != "" {
		arch += "/" + platform.Variant
	}

	return arch
}

func FilterByTagInfo(tagsInfo []cvemodel.TagInfo) mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		manifestDigest := imageMeta.Manifests[0].Digest.String()

		for _, tagInfo := range tagsInfo {
			switch tagInfo.Descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				if tagInfo.Descriptor.Digest.String() == manifestDigest {
					return true
				}
			case ispec.MediaTypeImageIndex:
				for _, manifestDesc := range tagInfo.Manifests {
					if manifestDesc.Digest.String() == manifestDigest {
						return true
					}
				}
			}
		}

		return false
	}
}

func FilterByRepoAndTagInfo(repo string, tagsInfo []cvemodel.TagInfo) mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		if repoMeta.Name != repo {
			return false
		}

		manifestDigest := imageMeta.Manifests[0].Digest.String()

		for _, tagInfo := range tagsInfo {
			switch tagInfo.Descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				if tagInfo.Descriptor.Digest.String() == manifestDigest {
					return true
				}
			case ispec.MediaTypeImageIndex:
				for _, manifestDesc := range tagInfo.Manifests {
					if manifestDesc.Digest.String() == manifestDigest {
						return true
					}
				}
			}
		}

		return false
	}
}

func getImageListForCVE(
	ctx context.Context,
	cveID string,
	cveInfo cveinfo.CveInfo,
	filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput,
	metaDB mTypes.MetaDB,
	log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	// Obtain all repos and tags
	// Infinite page to make sure we scan all repos in advance, before filtering results
	// The CVE scan logic is called from here, not in the actual filter,
	// this is because we shouldn't keep the DB locked while we wait on scan results
	reposMeta, err := metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	affectedImages := []cvemodel.TagInfo{}

	for _, repoMeta := range reposMeta {
		repo := repoMeta.Name

		log.Info().Str("repository", repo).Str("CVE", cveID).Msg("extracting list of tags affected by this cve")

		tagsInfo, err := cveInfo.GetImageListForCVE(ctx, repo, cveID)
		if err != nil {
			log.Error().Str("repository", repo).Str("CVE", cveID).Err(err).
				Msg("failed to get image list for this cve from repository")

			return &gql_generated.PaginatedImagesResult{}, err
		}

		affectedImages = append(affectedImages, tagsInfo...)
	}

	// We're not interested in other vulnerabilities
	skip := convert.SkipQGLField{Vulnerabilities: true}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	localFilter := mTypes.Filter{}
	if filter != nil {
		localFilter = mTypes.Filter{
			Os:            filter.Os,
			Arch:          filter.Arch,
			HasToBeSigned: filter.HasToBeSigned,
			IsBookmarked:  filter.IsBookmarked,
			IsStarred:     filter.IsStarred,
		}
	}

	// Actual page requested by user
	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, FilterByTagInfo(affectedImages))
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList,
		skip, cveInfo, localFilter, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageSummaries,
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
	filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput,
	metaDB mTypes.MetaDB,
	log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	imageList := make([]*gql_generated.ImageSummary, 0)

	log.Info().Str("repository", repo).Str("CVE", cveID).Msg("extracting list of tags where this cve is fixed")

	tagsInfo, err := cveInfo.GetImageListWithCVEFixed(ctx, repo, cveID)
	if err != nil {
		log.Error().Str("repository", repo).Str("CVE", cveID).Err(err).
			Msg("failed to get image list with this cve fixed from repository")

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

	localFilter := mTypes.Filter{}
	if filter != nil {
		localFilter = mTypes.Filter{
			Os:            filter.Os,
			Arch:          filter.Arch,
			HasToBeSigned: filter.HasToBeSigned,
			IsBookmarked:  filter.IsBookmarked,
			IsStarred:     filter.IsStarred,
		}
	}

	// Actual page requested by user
	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	// get all repos
	fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, FilterByRepoAndTagInfo(repo, tagsInfo))
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList,
		skip, cveInfo, localFilter, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageSummaries,
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
	metaDB mTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	paginatedRepos := &gql_generated.PaginatedReposResult{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Results.NewestImage.Vulnerabilities"),
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	repoMetaList, err := metaDB.SearchRepos(ctx, "")
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	imageMetaMap, err := metaDB.FilterImageMeta(ctx, mTypes.GetLatestImageDigests(repoMetaList))
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	repos, pageInfo, err := convert.PaginatedRepoMeta2RepoSummaries(ctx, repoMetaList, imageMetaMap,
		mTypes.Filter{}, pageInput, cveInfo, skip)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
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
	metaDB mTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	bookmarkedRepos, err := metaDB.GetBookmarkedRepos(ctx)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	filterByName := func(repo string) bool {
		return zcommon.Contains(bookmarkedRepos, repo)
	}

	return getFilteredPaginatedRepos(ctx, cveInfo, filterByName, log, requestedPage, metaDB)
}

func getStarredRepos(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB mTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	starredRepos, err := metaDB.GetStarredRepos(ctx)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	filterFn := func(repo string) bool {
		return zcommon.Contains(starredRepos, repo)
	}

	return getFilteredPaginatedRepos(ctx, cveInfo, filterFn, log, requestedPage, metaDB)
}

func getFilteredPaginatedRepos(
	ctx context.Context,
	cveInfo cveinfo.CveInfo,
	filterFn mTypes.FilterRepoNameFunc,
	log log.Logger, //nolint:unparam // may be used by devs for debugging
	requestedPage *gql_generated.PageInput,
	metaDB mTypes.MetaDB,
) (*gql_generated.PaginatedReposResult, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Results.NewestImage.Vulnerabilities"),
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	repoMetaList, err := metaDB.FilterRepos(ctx, filterFn, mTypes.AcceptAllRepoMeta)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	latestImageMeta, err := metaDB.FilterImageMeta(ctx, mTypes.GetLatestImageDigests(repoMetaList))
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	repos, pageInfo, err := convert.PaginatedRepoMeta2RepoSummaries(ctx, repoMetaList, latestImageMeta,
		mTypes.Filter{}, pageInput, cveInfo, skip)
	if err != nil {
		return &gql_generated.PaginatedReposResult{}, err
	}

	return &gql_generated.PaginatedReposResult{
		Results: repos,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func globalSearch(ctx context.Context, query string, metaDB mTypes.MetaDB, filter *gql_generated.Filter,
	requestedPage *gql_generated.PageInput, cveInfo cveinfo.CveInfo, log log.Logger, //nolint:unparam
) (*gql_generated.PaginatedReposResult, []*gql_generated.ImageSummary, []*gql_generated.LayerSummary, error,
) {
	preloads := convert.GetPreloads(ctx)
	paginatedRepos := gql_generated.PaginatedReposResult{}
	images := []*gql_generated.ImageSummary{}
	layers := []*gql_generated.LayerSummary{}

	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	localFilter := mTypes.Filter{}
	if filter != nil {
		localFilter = mTypes.Filter{
			Os:            filter.Os,
			Arch:          filter.Arch,
			HasToBeSigned: filter.HasToBeSigned,
			IsBookmarked:  filter.IsBookmarked,
			IsStarred:     filter.IsStarred,
		}
	}

	switch getSearchTarget(query) {
	case RepoTarget:
		skip := convert.SkipQGLField{Vulnerabilities: canSkipField(preloads, "Repos.NewestImage.Vulnerabilities")}
		pageInput := getPageInput(requestedPage)

		repoMetaList, err := metaDB.SearchRepos(ctx, query)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{},
				[]*gql_generated.LayerSummary{}, err
		}

		imageMetaMap, err := metaDB.FilterImageMeta(ctx, mTypes.GetLatestImageDigests(repoMetaList))
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{},
				[]*gql_generated.LayerSummary{}, err
		}

		repos, pageInfo, err := convert.PaginatedRepoMeta2RepoSummaries(ctx, repoMetaList, imageMetaMap, localFilter,
			pageInput, cveInfo,
			skip)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{},
				[]*gql_generated.LayerSummary{}, err
		}

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}

		paginatedRepos.Results = repos
	case ImageTarget:
		skip := convert.SkipQGLField{Vulnerabilities: canSkipField(preloads, "Images.Vulnerabilities")}
		pageInput := getPageInput(requestedPage)

		fullImageMetaList, err := metaDB.SearchTags(ctx, query)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList, skip, cveInfo,
			localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		images = imageSummaries

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}
	case TagTarget:
		skip := convert.SkipQGLField{Vulnerabilities: canSkipField(preloads, "Images.Vulnerabilities")}
		pageInput := getPageInput(requestedPage)

		expectedTag := strings.TrimPrefix(query, `:`)
		matchTagName := func(repoName, actualTag string) bool { return strings.Contains(actualTag, expectedTag) }

		fullImageMetaList, err := metaDB.FilterTags(ctx, matchTagName, mTypes.AcceptAllImageMeta)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList, skip, cveInfo,
			localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		images = imageSummaries

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}
	case DigestTarget:
		skip := convert.SkipQGLField{Vulnerabilities: canSkipField(preloads, "Images.Vulnerabilities")}
		pageInput := getPageInput(requestedPage)

		searchedDigest := query

		fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, FilterByDigest(searchedDigest))
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		imageSummaries, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList, skip, cveInfo,
			localFilter, pageInput)
		if err != nil {
			return &gql_generated.PaginatedReposResult{}, []*gql_generated.ImageSummary{}, []*gql_generated.LayerSummary{}, err
		}

		images = imageSummaries

		paginatedRepos.Page = &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		}
	default:
		return &paginatedRepos, images, layers, zerr.ErrInvalidSearchQuery
	}

	return &paginatedRepos, images, layers, nil
}

func getPageInput(requestedPage *gql_generated.PageInput) pagination.PageInput {
	return pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}
}

type SearchTarget int

const (
	RepoTarget = iota
	ImageTarget
	DigestTarget
	InvalidTarget
	TagTarget
)

func getSearchTarget(query string) SearchTarget {
	if !strings.ContainsAny(query, ":@") {
		return RepoTarget
	}

	if strings.HasPrefix(query, string(godigest.SHA256)+":") {
		return DigestTarget
	}

	if before, after, found := strings.Cut(query, ":"); found {
		if before != "" {
			return ImageTarget
		} else if after != "" {
			return TagTarget
		}
	}

	return InvalidTarget
}

func canSkipField(preloads map[string]bool, s string) bool {
	fieldIsPresent := preloads[s]

	return !fieldIsPresent
}

func derivedImageList(ctx context.Context, image string, digest *string, metaDB mTypes.MetaDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := zcommon.GetImageDirAndTag(image)
	if imageTag == "" {
		return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("no reference provided")
	}

	skipReferenceImage := convert.SkipQGLField{
		Vulnerabilities: true,
	}

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, digest, skipReferenceImage, metaDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("repository not found")
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, filterDerivedImages(searchedImage))
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	derivedList, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList, skip, cveInfo,
		mTypes.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Results: derivedList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func filterDerivedImages(image *gql_generated.ImageSummary) mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		var addImageToList bool

		imageManifest := imageMeta.Manifests[0]

		for i := range image.Manifests {
			manifestDigest := imageManifest.Digest.String()
			if manifestDigest == *image.Manifests[i].Digest {
				return false
			}
			imageLayers := image.Manifests[i].Layers

			addImageToList = false
			layers := imageManifest.Manifest.Layers

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

func baseImageList(ctx context.Context, image string, digest *string, metaDB mTypes.MetaDB,
	requestedPage *gql_generated.PageInput,
	cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.PaginatedImagesResult, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaUpdateTime),
		),
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Vulnerabilities"),
	}

	imageRepo, imageTag := zcommon.GetImageDirAndTag(image)

	if imageTag == "" {
		return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("no reference provided")
	}

	skipReferenceImage := convert.SkipQGLField{
		Vulnerabilities: true,
	}

	searchedImage, err := getImageSummary(ctx, imageRepo, imageTag, digest, skipReferenceImage, metaDB, cveInfo, log)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return &gql_generated.PaginatedImagesResult{}, gqlerror.Errorf("repository not found")
		}

		return &gql_generated.PaginatedImagesResult{}, err
	}

	// we need all available tags
	fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, filterBaseImages(searchedImage))
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	baseList, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, fullImageMetaList,
		skip, cveInfo, mTypes.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
		Results: baseList,
	}, nil
}

func filterBaseImages(image *gql_generated.ImageSummary) mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		var addImageToList bool

		manifest := imageMeta.Manifests[0]

		for i := range image.Manifests {
			manifestDigest := manifest.Digest.String()
			if manifestDigest == *image.Manifests[i].Digest {
				return false
			}

			addImageToList = true

			for _, l := range manifest.Manifest.Layers {
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

func filterBaseImagesForMeta(image mTypes.ImageMeta) mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		var addImageToList bool

		manifest := imageMeta.Manifests[0]

		for i := range image.Manifests {
			manifestDigest := manifest.Digest.String()
			if manifestDigest == image.Manifests[i].Digest.String() {
				return false
			}

			addImageToList = true

			for _, l := range manifest.Manifest.Layers {
				foundLayer := false

				for _, k := range image.Manifests[i].Manifest.Layers {
					if l.Digest.String() == k.Digest.String() {
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
		return fmt.Errorf("max string size limit exceeded for query parameter. max=%d current=%d %w",
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
			return fmt.Errorf("max string size limit exceeded for arch parameter. max=%d current=%d %w",
				querySizeLimit, len(*arch), zerr.ErrInvalidRequestParams)
		}
	}

	for _, osSys := range filter.Os {
		if len(*osSys) > querySizeLimit {
			return fmt.Errorf("max string size limit exceeded for os parameter. max=%d current=%d %w",
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
		return fmt.Errorf("requested page limit parameter can't be negative %w",
			zerr.ErrInvalidRequestParams)
	}

	if requestedPage.Offset != nil && *requestedPage.Offset < 0 {
		return fmt.Errorf("requested page offset parameter can't be negative %w",
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

func expandedRepoInfo(ctx context.Context, repo string, metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo, log log.Logger,
) (*gql_generated.RepoInfo, error) {
	if ok, err := reqCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		log.Info().Err(err).Str("repository", repo).Bool("availability", ok).Str("component", "graphql").
			Msg("repo user availability")

		return &gql_generated.RepoInfo{}, nil //nolint:nilerr // don't give details to a potential attacker
	}

	repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("component", "graphql").
			Msg("can't retrieve repoMeta for repository")

		return &gql_generated.RepoInfo{}, err
	}

	tagsDigests := []string{}

	for i := range repoMeta.Tags {
		if i == "" {
			continue
		}

		tagsDigests = append(tagsDigests, repoMeta.Tags[i].Digest)
	}

	imageMetaMap, err := metaDB.FilterImageMeta(ctx, tagsDigests)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("component", "graphql").
			Msg("can't retrieve imageMeta for repo")

		return &gql_generated.RepoInfo{}, err
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Summary.NewestImage.Vulnerabilities") &&
			canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	repoSummary, imageSummaries := convert.RepoMeta2ExpandedRepoInfo(ctx, repoMeta, imageMetaMap,
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

// dderef is a default deref.
func dderef[T any](pointer *T) T {
	var defValue T

	if pointer != nil {
		return *pointer
	}

	return defValue
}

func deref[T any](pointer *T, defaultVal T) T {
	if pointer != nil {
		return *pointer
	}

	return defaultVal
}

func ref[T any](input T) *T {
	ref := input

	return &ref
}

func getImageList(ctx context.Context, repo string, metaDB mTypes.MetaDB, cveInfo cveinfo.CveInfo,
	requestedPage *gql_generated.PageInput, log log.Logger, //nolint:unparam
) (*gql_generated.PaginatedImagesResult, error) {
	if requestedPage == nil {
		requestedPage = &gql_generated.PageInput{}
	}

	skip := convert.SkipQGLField{
		Vulnerabilities: canSkipField(convert.GetPreloads(ctx), "Images.Vulnerabilities"),
	}

	pageInput := pagination.PageInput{
		Limit:  deref(requestedPage.Limit, 0),
		Offset: deref(requestedPage.Offset, 0),
		SortBy: pagination.SortCriteria(
			deref(requestedPage.SortBy, gql_generated.SortCriteriaRelevance),
		),
	}

	var matchRepoName mTypes.FilterRepoTagFunc

	if repo == "" {
		matchRepoName = mTypes.AcceptAllRepoTag
	} else {
		matchRepoName = func(repoName, tag string) bool { return repoName == repo }
	}

	imageMeta, err := metaDB.FilterTags(ctx, matchRepoName, mTypes.AcceptAllImageMeta)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	imageList, pageInfo, err := convert.PaginatedFullImageMeta2ImageSummaries(ctx, imageMeta, skip,
		cveInfo, mTypes.Filter{}, pageInput)
	if err != nil {
		return &gql_generated.PaginatedImagesResult{}, err
	}

	return &gql_generated.PaginatedImagesResult{
		Results: imageList,
		Page: &gql_generated.PageInfo{
			TotalCount: pageInfo.TotalCount,
			ItemCount:  pageInfo.ItemCount,
		},
	}, nil
}

func getReferrers(metaDB mTypes.MetaDB, repo string, referredDigest string, artifactTypes []string,
	log log.Logger,
) ([]*gql_generated.Referrer, error) {
	refDigest := godigest.Digest(referredDigest)
	if err := refDigest.Validate(); err != nil {
		log.Error().Err(err).Str("digest", referredDigest).Str("component", "graphql").
			Msg("bad referenced digest string from request")

		return []*gql_generated.Referrer{}, fmt.Errorf("bad digest string from request '%s' %w",
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
