package search

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"strconv"

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

		results = append(results, &gql_generated.ImageInfo{
			Name: &name, Latest: &latestTag.Name,
			Description: &desc, Licenses: &license, Vendor: &vendor,
			Labels: &categories, Size: &size, LastUpdated: &latestTag.Timestamp,
		})
	}

	return results, nil
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
