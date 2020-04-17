package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"path"

	"github.com/anuvu/zot/pkg/log"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/utils"
	"go.etcd.io/bbolt"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	DB  *bbolt.DB
	Cve *cveinfo.CveInfo
}

// nolint (gochecknoglobals)
var ResConfig *Resolver

// Query ...
func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

func (r *queryResolver) Repositories(ctx context.Context, name *string) ([]*Repository, error) {
	return []*Repository{}, nil
}

func GetResolverConfig(dir string, log log.Logger) Config {
	cve := &cveinfo.CveInfo{Log: log}
	db := cve.InitSearch(path.Join(dir, "search.db"))
	ResConfig = &Resolver{DB: db, Cve: &cveinfo.CveInfo{Log: log}}

	return Config{Resolvers: ResConfig}
}

func (r *queryResolver) CveIDSearch(ctx context.Context, text string) (*CVEIdResult, error) {
	cveidresult := &CVEIdResult{}
	ans := r.Cve.SearchByCVEId(r.DB, text)
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

func (r *queryResolver) PkgVendor(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.Cve.SearchByPkgType("NvdPkgVendor", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}

func (r *queryResolver) PkgName(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.Cve.SearchByPkgType("NvdPkgName", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}

func (r *queryResolver) PkgNameVer(ctx context.Context, text string) ([]*Cveid, error) {
	ans := r.Cve.SearchByPkgType("NvdPkgNameVer", r.DB, text)
	cveids := []*Cveid{}

	for _, cveid := range ans {
		name := cveid.Name

		cveids = append(cveids, &Cveid{Name: &name})
	}

	return cveids, nil
}
