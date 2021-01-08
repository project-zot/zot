package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/anuvu/zot/pkg/log"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/storage"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo  *cveinfo.CveInfo
	imgStore *storage.ImageStore
	dir      string
	log      log.Logger
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
func GetResolverConfig(dir string, log log.Logger, imgstorage *storage.ImageStore) Config {
	config, err := cveinfo.NewTrivyConfig(dir)
	if err != nil {
		panic(err)
	}

	cve := &cveinfo.CveInfo{Log: log, CveTrivyConfig: config}

	resConfig := &Resolver{cveInfo: cve, imgStore: imgstorage, dir: dir, log: log}

	return Config{
		Resolvers: resConfig, Directives: DirectiveRoot{},
		Complexity: ComplexityRoot{},
	}
}

func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*CVEResultForImage, error) {
	r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, image)

	r.cveInfo.Log.Info().Str("image", image).Msg("scanning image")

	isValidImage, err := IsValidImageFormat(r.cveInfo.CveTrivyConfig.TrivyConfig.Input, r.cveInfo.Log)
	if !isValidImage {
		r.cveInfo.Log.Debug().Str("image", image).Msg("image media type not supported for scanning")

		return &CVEResultForImage{}, err
	}

	cveResults, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("unable to scan image repository")

		return &CVEResultForImage{}, err
	}

	var copyImgTag string

	if strings.Contains(image, ":") {
		copyImgTag = strings.Split(image, ":")[1]
	}

	cveidMap := make(map[string]cveDetail)

	for _, result := range cveResults {
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

func (r *queryResolver) ImageListForCve(ctx context.Context, id string) ([]*ImgResultForCve, error) {
	cveResult := []*ImgResultForCve{}

	r.cveInfo.Log.Info().Msg("extracting repositories")

	repoList, err := r.imgStore.GetRepositories()
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("unable to search repositories")

		return cveResult, err
	}

	r.cveInfo.Log.Info().Msg("scanning each repository")

	for _, repo := range repoList {
		r.cveInfo.Log.Info().Str("repo", repo).Msg("extracting list of tags available in image repo")

		tagList, err := r.imgStore.GetImageTags(repo)
		if err != nil {
			r.cveInfo.Log.Error().Err(err).Msg("unable to get list of image tag")
		}

		var name string

		tags := make([]*string, 0)

		for _, tag := range tagList {
			r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, repo+":"+tag)

			isValidImage, _ := IsValidImageFormat(r.cveInfo.CveTrivyConfig.TrivyConfig.Input, r.cveInfo.Log)
			if !isValidImage {
				r.cveInfo.Log.Debug().Str("image", repo+":"+tag).Msg("image media type not supported for scanning")

				continue
			}

			r.cveInfo.Log.Info().Str("image", repo+":"+tag).Msg("scanning image")

			results, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
			if err != nil {
				r.cveInfo.Log.Error().Err(err).Str("image", repo+":"+tag).Msg("unable to scan image")

				continue
			}

			name = repo

			for _, result := range results {
				for _, vulnerability := range result.Vulnerabilities {
					if vulnerability.VulnerabilityID == id {
						copyImgTag := tag
						tags = append(tags, &copyImgTag)

						break
					}
				}
			}
		}

		if len(tags) != 0 {
			cveResult = append(cveResult, &ImgResultForCve{Name: &name, Tags: tags})
		}
	}

	return cveResult, nil
}

func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string) (*ImgResultForFixedCve, error) { // nolint: lll
	imgResultForFixedCVE := &ImgResultForFixedCve{}

	r.cveInfo.Log.Info().Str("image", image).Msg("extracting list of tags available in image")

	tagsInfo, err := GetImageTagsWithTimestamp(r.dir, image, r.cveInfo.Log)
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("unable to read image tags")

		return imgResultForFixedCVE, err
	}

	infectedTags := make([]TagInfo, 0)

	var hasCVE bool

	for _, tag := range tagsInfo {
		r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, fmt.Sprintf("%s:%s", image, *tag.Name))

		isValidImage, _ := IsValidImageFormat(r.cveInfo.CveTrivyConfig.TrivyConfig.Input, r.cveInfo.Log)
		if !isValidImage {
			r.cveInfo.Log.Debug().Str("image",
				fmt.Sprintf("%s:%s", image, *tag.Name)).Msg("image media type not supported for scanning, adding as an infected image")

			infectedTags = append(infectedTags, TagInfo{Name: tag.Name, Timestamp: tag.Timestamp})

			continue
		}

		r.cveInfo.Log.Info().Str("image", fmt.Sprintf("%s:%s", image, *tag.Name)).Msg("scanning image")

		results, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
		if err != nil {
			r.cveInfo.Log.Error().Err(err).Str("image", fmt.Sprintf("%s:%s", image, *tag.Name)).Msg("unable to scan image")

			continue
		}

		hasCVE = false

		for _, result := range results {
			for _, vulnerability := range result.Vulnerabilities {
				if vulnerability.VulnerabilityID == id {
					hasCVE = true

					break
				}
			}
		}

		if hasCVE {
			infectedTags = append(infectedTags, TagInfo{Name: tag.Name, Timestamp: tag.Timestamp})
		}
	}

	var finalTagList []*TagInfo

	if len(infectedTags) != 0 {
		r.cveInfo.Log.Info().Msg("comparing fixed tags timestamp")

		fixedTags := GetFixedTags(tagsInfo, infectedTags)

		finalTagList = getGraphqlCompatibleTags(fixedTags)
	} else {
		r.cveInfo.Log.Info().Str("image", image).Str("cve-id", id).Msg("image does not contain any tag that have given cve")

		finalTagList = getGraphqlCompatibleTags(tagsInfo)
	}

	imgResultForFixedCVE = &ImgResultForFixedCve{Tags: finalTagList}

	return imgResultForFixedCVE, nil
}

func (r *queryResolver) ImageListWithLatestTag(ctx context.Context) ([]*ImageInfo, error) {
	r.log.Info().Msg("extension api: finding image list")
	var result []*ImageInfo

	repoList, err := r.imgStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting repositories list")

		return result, err
	}

	for _, repo := range repoList {
		r.log.Info().Msg("extension api: reading repositories list")

		tagsInfo, err := GetImageTagsWithTimestamp(r.dir, repo, r.log)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error getting tag timestamp info")

			return result, nil
		}

		if len(tagsInfo) == 0 {
			continue
		}

		latestTag := getLatestTag(tagsInfo)

		manifestByte, _, _, err := r.imgStore.GetImageManifest(repo, *latestTag.Name)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading manifest")

			return result, nil
		}

		manifest, err := unmarshalManifest(manifestByte)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading manifest")

			return result, err
		}

		size := strconv.FormatInt(manifest.Config.Size, 10)

		name := repo

		imageConfig, err := getManifestConfigBlob(path.Join(r.dir, repo), manifest.Config.Digest, r.log)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error reading image config")

			return result, err
		}

		labels := imageConfig.Config.Labels

		// Read Description

		desc, ok := labels[ispec.AnnotationDescription]
		if !ok {
			desc, ok = labels[LabelAnnotationDescription]
			if !ok {
				desc = ""
			}
		}

		// Read licenses
		license, ok := labels[ispec.AnnotationLicenses]
		if !ok {
			license, ok = labels[LabelAnnotationLicenses]
			if !ok {
				license = ""
			}
		}

		// Read vendor
		vendor, ok := labels[ispec.AnnotationVendor]
		if !ok {
			vendor, ok = labels[LabelAnnotationVendor]
			if !ok {
				vendor = ""
			}
		}

		categories, ok := labels[AnnotationLabels]
		if !ok {
			categories = ""
		}

		result = append(result, &ImageInfo{Name: &name, Latest: latestTag.Name, Description: &desc, Licenses: &license, Vendor: &vendor, Labels: &categories, Size: &size, LastUpdated: latestTag.Timestamp})
	}

	return result, nil
}
