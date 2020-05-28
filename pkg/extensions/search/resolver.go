package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"path"
	"strings"

	"github.com/anuvu/zot/pkg/log"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/storage"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	CVEInfo  *cveinfo.CveInfo
	ImgStore *storage.ImageStore
	//Config   config.Config
	dir string
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
	cve := &cveinfo.CveInfo{Log: log, RootDir: dir}
	ResConfig = &Resolver{CVEInfo: cve, ImgStore: imgstorage, dir: dir}

	return Config{Resolvers: ResConfig}
}

func (r *queryResolver) CVEListForImage(ctx context.Context, repo string) ([]*CVEResultForImage, error) {
	imgResult := []*CVEResultForImage{}

	config, err := config.NewConfig()
	if err != nil {
		panic(err)
	}

	config.Input = path.Join(r.dir, repo)

	results, err := integration.Run(config)
	if err != nil {
		return imgResult, err
	}

	for _, result := range results {
		tagExtract := strings.Split(result.Target, " ")

		copyImgTag := strings.Split(tagExtract[2], ")")[0]

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

func (r *queryResolver) ImageListForCve(ctx context.Context, text string) ([]*ImgResultForCve, error) {
	cveResult := []*ImgResultForCve{}

	repoList, err := r.ImgStore.GetRepositories()
	if err != nil {
		return cveResult, nil
	}

	config, err := config.NewConfig()
	if err != nil {
		panic(err)
	}

	for _, repo := range repoList {
		config.Input = path.Join(r.dir, repo)

		results, err := integration.Run(config)
		if err != nil {
			continue
		}

		tags := make([]*string, 0)

		for _, result := range results {
			tagExtract := strings.Split(result.Target, " ")

			name := tagExtract[0]

			for _, vulnerability := range result.Vulnerabilities {
				if vulnerability.VulnerabilityID == text {
					copyImgTag := strings.Split(tagExtract[2], ")")[0]
					tags = append(tags, &copyImgTag)

					break
				}
			}

			if len(tags) != 0 {
				cveResult = append(cveResult, &ImgResultForCve{Name: &name, Tags: tags})
			}
		}
	}

	if err != nil {
		r.CVEInfo.Log.Error().Err(err).Msg("Not able to search repositories")
	}

	return cveResult, nil
}
