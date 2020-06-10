package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"path"
	"strings"

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

// ResConfig ...
// nolint:gochecknoglobals
var ResConfig *Resolver

// Query ...
func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

// GetResolverConfig ...
func GetResolverConfig(dir string, log log.Logger, imgstorage *storage.ImageStore) Config {
	config, err := cveinfo.NewTrivyConfig(dir)
	if err != nil {
		panic(err)
	}

	cve := &cveinfo.CveInfo{Log: log, CveTrivyConfig: config}

	ResConfig = &Resolver{cveInfo: cve, imgStore: imgstorage, dir: dir}

	return Config{Resolvers: ResConfig}
}

func (r *queryResolver) CVEListForImage(ctx context.Context, image string) ([]*CVEResultForImage, error) {
	imgResult := []*CVEResultForImage{}

	r.cveInfo.CveTrivyConfig.TrivyConfig.Input = path.Join(r.dir, image)

	r.cveInfo.Log.Info().Str("Scanning Image", image).Msg("")

	results, err := cveinfo.ScanImage(r.cveInfo.CveTrivyConfig)
	if err != nil {
		return imgResult, err
	}

	var copyImgTag string

	if strings.Contains(image, ":") {
		copyImgTag = strings.Split(image, ":")[1]
	}

	for _, result := range results {
		cveids := []*Cve{}

		for _, vulnerability := range result.Vulnerabilities {
			id := vulnerability.VulnerabilityID

			desc := vulnerability.Description

			severity := vulnerability.Severity

			cveids = append(cveids, &Cve{ID: &id, Description: &desc, Severity: &severity})
		}

		imgResult = append(imgResult, &CVEResultForImage{Tag: &copyImgTag, CVEList: cveids})
	}

	return imgResult, nil
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
