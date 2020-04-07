package search

//go:generate go run github.com/99designs/gqlgen

import (
	"context"

	"github.com/anuvu/zot/pkg/extensions/search/utils"
	"github.com/boltdb/bolt"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	Db *bolt.DB
}

// Query ...
func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

func (r *queryResolver) Repositories(ctx context.Context, name *string) ([]*Repository, error) {

	return []*Repository{}, nil
}

func (r *queryResolver) CveIDSearch(ctx context.Context, text string) (*CVEIdResult, error) {
	var cveidresult = &CVEIdResult{}
	ans := utils.SearchByCVEId(r.Db, text)
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
	ans := utils.SearchByPkgType("NvdPkgVendor", r.Db, text)
	var cveids []*Cveid
	for _, cveid := range ans {
		name := cveid.Name
		cveids = append(cveids, &Cveid{Name: &name})
	}
	return cveids, nil
}

func (r *queryResolver) PkgName(ctx context.Context, text string) ([]*Cveid, error) {
	ans := utils.SearchByPkgType("NvdPkgName", r.Db, text)
	var cveids []*Cveid
	for _, cveid := range ans {
		name := cveid.Name
		cveids = append(cveids, &Cveid{Name: &name})
	}
	return cveids, nil
}

func (r *queryResolver) PkgNameVer(ctx context.Context, text string) ([]*Cveid, error) {
	ans := utils.SearchByPkgType("NvdPkgNameVer", r.Db, text)
	var cveids []*Cveid
	for _, cveid := range ans {
		name := cveid.Name
		cveids = append(cveids, &Cveid{Name: &name})
	}
	return cveids, nil
}
