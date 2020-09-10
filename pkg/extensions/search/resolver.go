package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"path"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/storage"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	cveInfo  *cveinfo.CveInfo
	imgStore *storage.ImageStore
	dir      string
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

	resConfig := &Resolver{cveInfo: cve, imgStore: imgstorage, dir: dir}

	return Config{Resolvers: resConfig, Directives: DirectiveRoot{},
		Complexity: ComplexityRoot{}}
}

func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*CVEResultForImage, error) {
	r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, image)

	r.cveInfo.Log.Info().Str("Scanning Image", image).Msg("")

	isValidImage, err := r.cveInfo.IsValidImageFormat(r.cveInfo.CveTrivyConfig.TrivyConfig.Input)
	if !isValidImage {
		r.cveInfo.Log.Debug().Msg("Image media type not supported for scanning")

		return &CVEResultForImage{}, errors.ErrScanNotSupported
	}

	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("Error scanning image repository")

		return &CVEResultForImage{}, err
	}

	cveResults, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("Error scanning image repository")

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

				cveidMap[vulnerability.VulnerabilityID] = cveDetail{Title: vulnerability.Title,
					Description: vulnerability.Description, Severity: vulnerability.Severity, PackageList: newPkgList}
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

	r.cveInfo.Log.Info().Msg("Extracting Repositories")

	repoList, err := r.imgStore.GetRepositories()
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("Not able to search repositories")

		return cveResult, err
	}

	r.cveInfo.Log.Info().Msg("Scanning each repository")

	for _, repo := range repoList {
		r.cveInfo.Log.Info().Str("Extracting list of tags available in image", repo).Msg("")

		isValidImage, err := r.cveInfo.IsValidImageFormat(path.Join(r.dir, repo))
		if !isValidImage {
			r.cveInfo.Log.Debug().Str("Image media type not supported for scanning", repo)

			continue
		}

		if err != nil {
			r.cveInfo.Log.Error().Err(err).Str("Error reading image media type", repo)

			return cveResult, err
		}

		if err != nil {
			r.cveInfo.Log.Error().Err(err).Str("Error reading image media type", repo)

			return cveResult, err
		}

		tagList, err := r.imgStore.GetImageTags(repo)
		if err != nil {
			r.cveInfo.Log.Error().Err(err).Msg("Not able to get list of Image Tag")
		}

		var name string

		tags := make([]*string, 0)

		for _, tag := range tagList {
			r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, repo+":"+tag)

			r.cveInfo.Log.Info().Str("Scanning Image", path.Join(r.dir, repo+":"+tag)).Msg("")

			results, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
			if err != nil {
				r.cveInfo.Log.Error().Err(err).Str("Error scanning image", repo+":"+tag)

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

	r.cveInfo.Log.Info().Str("Extracting list of tags available in image", image).Msg("")

	isValidImage, err := r.cveInfo.IsValidImageFormat(path.Join(r.dir, image))
	if !isValidImage {
		r.cveInfo.Log.Debug().Msg("Image media type not supported for scanning")

		return imgResultForFixedCVE, errors.ErrScanNotSupported
	}

	if err != nil {
		return imgResultForFixedCVE, err
	}

	tagsInfo, err := r.cveInfo.GetImageTagsWithTimestamp(r.dir, image)
	if err != nil {
		r.cveInfo.Log.Error().Err(err).Msg("Error while readling image media type")

		return imgResultForFixedCVE, err
	}

	infectedTags := make([]cveinfo.TagInfo, 0)

	var hasCVE bool

	for _, tag := range tagsInfo {
		r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, image+":"+tag.Name)

		r.cveInfo.Log.Info().Str("Scanning image", path.Join(r.dir, image+":"+tag.Name)).Msg("")

		results, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
		if err != nil {
			r.cveInfo.Log.Error().Err(err).Str("Error scanning image", image+":"+tag.Name).Msg("")

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
			infectedTags = append(infectedTags, cveinfo.TagInfo{Name: tag.Name, Timestamp: tag.Timestamp})
		}
	}

	if len(infectedTags) != 0 {
		r.cveInfo.Log.Info().Msg("Comparing fixed tags timestamp")

		fixedTags := cveinfo.GetFixedTags(tagsInfo, infectedTags)

		finalTagList := make([]*TagInfo, 0)

		for _, tag := range fixedTags {
			copyTag := tag.Name

			copyTimeStamp := tag.Timestamp

			finalTagList = append(finalTagList, &TagInfo{Name: &copyTag, Timestamp: &copyTimeStamp})
		}

		imgResultForFixedCVE = &ImgResultForFixedCve{Tags: finalTagList}

		return imgResultForFixedCVE, nil
	}

	r.cveInfo.Log.Info().Msg("Input image does not contain any tag that does not have given cve")

	return imgResultForFixedCVE, nil
}
