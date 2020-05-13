package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"path"

	"github.com/anuvu/zot/pkg/log"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
	"github.com/anuvu/zot/pkg/storage"
	"go.etcd.io/bbolt"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	DB       *bbolt.DB
	CVEInfo  *cveinfo.CveInfo
	ImgStore *storage.ImageStore
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
	db := cve.InitDB(path.Join(dir, "search.db"), true)
	ResConfig = &Resolver{DB: db, CVEInfo: cve, ImgStore: imgstorage}

	return Config{Resolvers: ResConfig}
}

func (r *queryResolver) Cve(ctx context.Context, text string) (*CVEIdResult, error) {
	cveidresult := &CVEIdResult{}
	ans := r.CVEInfo.QueryByCVEId(r.DB, text)
	cveidresult.Name = &ans.CveID
	cveidresult.VulDesc = &ans.VulDesc
	cveidresult.VulDetails = make([]*VulDetail, len(ans.VulDetails))

	for i, vuldes := range ans.VulDetails {
		cveidresult.VulDetails[i] = new(VulDetail)
		name := vuldes.PkgName
		cveidresult.VulDetails[i].PkgName = &name
		vendor := vuldes.PkgVendor
		cveidresult.VulDetails[i].PkgVendor = &vendor
		version := vuldes.PkgVersion
		cveidresult.VulDetails[i].PkgVersion = &version
	}

	return cveidresult, nil
}

func (r *queryResolver) CVEListForPkgVendor(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.CVEInfo.QueryByPkgType("NvdPkgVendor", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}

func (r *queryResolver) CVEListForPkgName(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.CVEInfo.QueryByPkgType("NvdPkgName", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}

func (r *queryResolver) CVEListForPkgNameVer(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.CVEInfo.QueryByPkgType("NvdPkgNameVer", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}

func (r *queryResolver) CVEListForImage(ctx context.Context, repo string) ([]*ImgCVEResult, error) {
	imgResult := []*ImgCVEResult{}

	// Getting Repo Image Tag and its corresponding package list
	tagpkgMap, err := r.CVEInfo.GetImageAnnotations(repo)

	if err != nil {
		r.CVEInfo.Log.Error().Err(err).Msg("Unable to get package list from Image")

		return imgResult, nil
	}

	// Traversing through all Image Tags
	for imgTag, pkgList := range tagpkgMap {
		copyImgTag := imgTag
		// Each Image Tag have their own CveId list
		cveids := []*Cveid{}
		// Maintaining Map for removind duplicate CveId
		uniqueCveID := make(map[string]struct{})
		// Traversing through each image tag package list
		for _, pkg := range pkgList {
			// Getting list of CveIDs corresponding to given package name
			// Need to change this method calling for package version
			ans := r.CVEInfo.QueryByPkgType("NvdPkgName", r.DB, pkg)

			// Traversing through list of CveIds and appending it to result
			for _, cveid := range ans {
				name := cveid.Name

				_, ok := uniqueCveID[name]
				if !ok {
					cveids = append(cveids, &Cveid{Name: &name})
					uniqueCveID[name] = struct{}{}
				}
			}
		}

		imgResult = append(imgResult, &ImgCVEResult{Tag: &copyImgTag, CVEIdList: cveids})
	}

	return imgResult, nil
}

func (r *queryResolver) CVEListForImageTag(ctx context.Context, repo string, tag string) ([]*Cveid, error) {
	cveids := []*Cveid{}
	uniqueCveID := make(map[string]struct{})

	imgList, err := r.CVEInfo.GetImageAnnotations(repo)

	if err != nil {
		r.CVEInfo.Log.Error().Err(err).Msg("Unable to get package list from Image")
	}

	for imgTag, pkgList := range imgList {
		if imgTag == tag {
			for _, pkg := range pkgList {
				ans := r.CVEInfo.QueryByPkgType("NvdPkgName", r.DB, pkg)

				for _, cveid := range ans {
					name := cveid.Name

					_, ok := uniqueCveID[name]
					if !ok {
						cveids = append(cveids, &Cveid{Name: &name})
						uniqueCveID[name] = struct{}{}
					}
				}
			}
		}
	}

	return cveids, nil
}

func (r *queryResolver) ImageListForCve(ctx context.Context, text string) ([]*CVEImgResult, error) {
	repoList, err := r.ImgStore.GetRepositories()

	if err != nil {
		r.CVEInfo.Log.Error().Err(err).Msg("Not able to search repositories")
	}

	cveimgResult := []*CVEImgResult{}

	cvepkgSet := make(map[string]struct{})

	// Returning the CveDetails for given CveId
	cveDetails := r.CVEInfo.QueryByCVEId(r.DB, text)

	// Maintaining a Set of packages in Cveid for O(1) search
	for _, vulDetail := range cveDetails.VulDetails {
		_, ok := cvepkgSet[vulDetail.PkgName]
		if !ok {
			cvepkgSet[vulDetail.PkgName] = struct{}{}
		}
	}

	// Traversing through each repo
	for _, repo := range repoList {
		copyRepo := repo
		// Getting Map of Tag and Package List
		imgTagList, err := r.CVEInfo.GetImageAnnotations(repo)

		if err != nil {
			r.CVEInfo.Log.Error().Err(err).Msg("Not able to search Image ")

			return nil, err
		}

		imgTagResult := make([]*string, 0)

		// Traversing through each tag and package list
		for imgTag, pkgList := range imgTagList {
			// Traversing through each package list of Image
			copyImgTag := imgTag

			for _, pkg := range pkgList {
				// Checking if the package is in Cve package set
				_, ok := cvepkgSet[pkg]

				// If found that means Image Tag should be added in our result.
				if ok {
					imgTagResult = append(imgTagResult, &copyImgTag)
					break
				}
			}
		}

		if len(imgTagResult) != 0 {
			cveimgResult = append(cveimgResult, &CVEImgResult{Name: &copyRepo, Tags: imgTagResult})
		}
	}

	return cveimgResult, nil
}
