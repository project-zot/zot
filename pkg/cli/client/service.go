//go:build search
// +build search

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/dustin/go-humanize"
	jsoniter "github.com/json-iterator/go"
	"github.com/olekukonko/tablewriter"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v2"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
)

const (
	jsonFormat = "json"
	yamlFormat = "yaml"
	ymlFormat  = "yml"
)

type SearchService interface { //nolint:interfacebloat
	getImagesGQL(ctx context.Context, config SearchConfig, username, password string,
		imageName string) (*common.ImageListResponse, error)
	getImagesForDigestGQL(ctx context.Context, config SearchConfig, username, password string,
		digest string) (*common.ImagesForDigest, error)
	getCveByImageGQL(ctx context.Context, config SearchConfig, username, password,
		imageName string, searchedCVE string) (*cveResult, error)
	getTagsForCVEGQL(ctx context.Context, config SearchConfig, username, password, repo,
		cveID string) (*common.ImagesForCve, error)
	getFixedTagsForCVEGQL(ctx context.Context, config SearchConfig, username, password, imageName,
		cveID string) (*common.ImageListWithCVEFixedResponse, error)
	getDerivedImageListGQL(ctx context.Context, config SearchConfig, username, password string,
		derivedImage string) (*common.DerivedImageListResponse, error)
	getBaseImageListGQL(ctx context.Context, config SearchConfig, username, password string,
		baseImage string) (*common.BaseImageListResponse, error)
	getReferrersGQL(ctx context.Context, config SearchConfig, username, password string,
		repo, digest string) (*common.ReferrersResp, error)
	getCVEDiffListGQL(ctx context.Context, config SearchConfig, username, password string,
		minuend, subtrahend ImageIdentifier,
	) (*cveDiffListResp, error)
	globalSearchGQL(ctx context.Context, config SearchConfig, username, password string,
		query string) (*common.GlobalSearch, error)

	getAllImages(ctx context.Context, config SearchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImagesByDigest(ctx context.Context, config SearchConfig, username, password, digest string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getRepos(ctx context.Context, config SearchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImageByName(ctx context.Context, config SearchConfig, username, password, imageName string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getReferrers(ctx context.Context, config SearchConfig, username, password string, repo, digest string,
	) (referrersResult, error)
}

type SearchConfig struct {
	SearchService SearchService
	ServURL       string
	User          string
	OutputFormat  string
	SortBy        string
	VerifyTLS     bool
	FixedFlag     bool
	Verbose       bool
	Debug         bool
	ResultWriter  io.Writer
	Spinner       spinnerState
}

type searchService struct{}

func NewSearchService() SearchService {
	return searchService{}
}

func (service searchService) getDerivedImageListGQL(ctx context.Context, config SearchConfig, username, password string,
	derivedImage string,
) (*common.DerivedImageListResponse, error) {
	query := fmt.Sprintf(`
		{
			DerivedImageList(image:"%s", requestedPage: {sortBy: %s}){
				Results{
					RepoName Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						Size
						Platform {Os Arch}
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
					LastUpdated
					Size
					IsSigned
				}
			}
		}`, derivedImage, Flag2SortCriteria(config.SortBy))

	result := &common.DerivedImageListResponse{}
	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getReferrersGQL(ctx context.Context, config SearchConfig, username, password string,
	repo, digest string,
) (*common.ReferrersResp, error) {
	query := fmt.Sprintf(`
		{
			Referrers( repo: "%s", digest: "%s" ){
				ArtifactType,
				Digest,
				MediaType,
				Size,
				Annotations{
					Key
					Value
				}
			}
		}`, repo, digest)

	result := &common.ReferrersResp{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getCVEDiffListGQL(ctx context.Context, config SearchConfig, username, password string,
	minuend, subtrahend ImageIdentifier,
) (*cveDiffListResp, error) {
	minuendInput := getImageInput(minuend)
	subtrahendInput := getImageInput(subtrahend)
	query := fmt.Sprintf(`
		{
			CVEDiffListForImages( minuend: %s, subtrahend: %s ) {
				Minuend {Repo Tag}
				Subtrahend {Repo Tag}
				CVEList {
					Id Title Description Severity Reference 
					PackageList {Name InstalledVersion FixedVersion}
				} 
				Summary {
					Count UnknownCount LowCount MediumCount HighCount CriticalCount
				} 
				Page {TotalCount ItemCount}
			}
		}`, minuendInput, subtrahendInput)

	result := &cveDiffListResp{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func getImageInput(img ImageIdentifier) string {
	platform := ""
	if img.Platform != nil {
		platform = fmt.Sprintf(`, Platform: {Os: "%s", Arch: "%s"}`, img.Platform.Os, img.Platform.Arch)
	}

	return fmt.Sprintf(`{Repo: "%s", Tag: "%s", Digest: "%s"%s}`, img.Repo, img.Tag, img.Digest, platform)
}

func (service searchService) globalSearchGQL(ctx context.Context, config SearchConfig, username, password string,
	query string,
) (*common.GlobalSearch, error) {
	GQLQuery := fmt.Sprintf(`
		{
			GlobalSearch(query:"%s", requestedPage: {sortBy: %s}){
				Images {
					RepoName
					Tag
					MediaType
					Digest
					Size
					IsSigned
					LastUpdated
					Manifests {
						Digest
						ConfigDigest
						Platform {Os Arch}
						Size
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
				}
				Repos {
					Name
					Platforms { Os Arch }
					LastUpdated
					Size
					DownloadCount
					StarCount
				}
			}
		}`, query, Flag2SortCriteria(config.SortBy))

	result := &common.GlobalSearchResultResp{}

	err := service.makeGraphQLQuery(ctx, config, username, password, GQLQuery, result)
	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return &result.GlobalSearch, nil
}

func (service searchService) getBaseImageListGQL(ctx context.Context, config SearchConfig, username, password string,
	baseImage string,
) (*common.BaseImageListResponse, error) {
	query := fmt.Sprintf(`
		{
			BaseImageList(image:"%s", requestedPage: {sortBy: %s}){
				Results{
					RepoName Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						Size
						Platform {Os Arch}
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
					LastUpdated
					Size
					IsSigned
				}
			}
		}`, baseImage, Flag2SortCriteria(config.SortBy))

	result := &common.BaseImageListResponse{}
	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImagesGQL(ctx context.Context, config SearchConfig, username, password string,
	imageName string,
) (*common.ImageListResponse, error) {
	query := fmt.Sprintf(`
	{
		ImageList(repo: "%s", requestedPage: {sortBy: %s}) {
			Results {
				RepoName Tag
				Digest
				MediaType
				Manifests {
					Digest
					ConfigDigest
					Size
					Platform {Os Arch}
					IsSigned
					Layers {Size Digest}
					LastUpdated
				}
				LastUpdated
				Size
				IsSigned
			}
		}
	}`, imageName, Flag2SortCriteria(config.SortBy))
	result := &common.ImageListResponse{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImagesForDigestGQL(ctx context.Context, config SearchConfig, username, password string,
	digest string,
) (*common.ImagesForDigest, error) {
	query := fmt.Sprintf(`
	{
		ImageListForDigest(id: "%s", requestedPage: {sortBy: %s}) {
			Results {
				RepoName Tag
				Digest
				MediaType
				Manifests {
					Digest
					ConfigDigest
					Size
					Platform {Os Arch}
					IsSigned
					Layers {Size Digest}
					LastUpdated
				}
				LastUpdated
				Size
				IsSigned
			}
		}
	}`, digest, Flag2SortCriteria(config.SortBy))
	result := &common.ImagesForDigest{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getCveByImageGQL(ctx context.Context, config SearchConfig, username, password,
	imageName, searchedCVE string,
) (*cveResult, error) {
	query := fmt.Sprintf(`
	{
		CVEListForImage (image:"%s", searchedCVE:"%s", requestedPage: {sortBy: %s}) {
			Tag
			CVEList {
				Id Title Severity Description
				PackageList {Name PackagePath InstalledVersion FixedVersion}
			}
			Summary {
				Count UnknownCount LowCount MediumCount HighCount CriticalCount MaxSeverity
			}
		}
	}`, imageName, searchedCVE, Flag2SortCriteria(config.SortBy))
	result := &cveResult{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getTagsForCVEGQL(ctx context.Context, config SearchConfig,
	username, password, repo, cveID string,
) (*common.ImagesForCve, error) {
	query := fmt.Sprintf(`
		{
			ImageListForCVE(id: "%s", requestedPage: {sortBy: %s}) {
				Results {
					RepoName Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						Size
						Platform {Os Arch}
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
					LastUpdated
					Size
					IsSigned
				}
			}
		}`,
		cveID, Flag2SortCriteria(config.SortBy))
	result := &common.ImagesForCve{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	if repo == "" {
		return result, nil
	}

	filteredResults := &common.ImagesForCve{}

	for _, image := range result.Results {
		if image.RepoName == repo {
			filteredResults.Results = append(filteredResults.Results, image)
		}
	}

	return filteredResults, nil
}

func (service searchService) getFixedTagsForCVEGQL(ctx context.Context, config SearchConfig,
	username, password, imageName, cveID string,
) (*common.ImageListWithCVEFixedResponse, error) {
	query := fmt.Sprintf(`
		{
			ImageListWithCVEFixed(id: "%s", image: "%s") {
				Results {
					RepoName Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						Size
						Platform {Os Arch}
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
					LastUpdated
					Size
					IsSigned
				}
			}
		}`,
		cveID, imageName)

	result := &common.ImageListWithCVEFixedResponse{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getReferrers(ctx context.Context, config SearchConfig, username, password string,
	repo, digest string,
) (referrersResult, error) {
	referrersEndpoint, err := combineServerAndEndpointURL(config.ServURL,
		fmt.Sprintf("/v2/%s/referrers/%s", repo, digest))
	if err != nil {
		if common.IsContextDone(ctx) {
			return referrersResult{}, nil
		}

		return referrersResult{}, err
	}

	referrerResp := &ispec.Index{}
	_, err = makeGETRequest(ctx, referrersEndpoint, username, password, config.VerifyTLS,
		config.Debug, &referrerResp, config.ResultWriter)

	if err != nil {
		if common.IsContextDone(ctx) {
			return referrersResult{}, nil
		}

		return referrersResult{}, err
	}

	referrersList := referrersResult{}

	for _, referrer := range referrerResp.Manifests {
		referrersList = append(referrersList, common.Referrer{
			ArtifactType: referrer.ArtifactType,
			Digest:       referrer.Digest.String(),
			Size:         int(referrer.Size),
		})
	}

	return referrersList, nil
}

func (service searchService) getImageByName(ctx context.Context, config SearchConfig,
	username, password, imageName string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	var localWg sync.WaitGroup
	rlim := newSmoothRateLimiter(&localWg, rch)

	localWg.Add(1)

	go rlim.startRateLimiter(ctx)
	localWg.Add(1)

	go getImage(ctx, config, username, password, imageName, rch, &localWg, rlim)

	localWg.Wait()
}

func (service searchService) getAllImages(ctx context.Context, config SearchConfig, username, password string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	catalog := &catalogResponse{}

	catalogEndPoint, err := combineServerAndEndpointURL(config.ServURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtCatalogPrefix))
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	_, err = makeGETRequest(ctx, catalogEndPoint, username, password, config.VerifyTLS,
		config.Debug, catalog, config.ResultWriter)
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)

	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, repo := range catalog.Repositories {
		localWg.Add(1)

		go getImage(ctx, config, username, password, repo, rch, &localWg, rlim)
	}

	localWg.Wait()
}

func getImage(ctx context.Context, config SearchConfig, username, password, imageName string,
	rch chan stringResult, wtgrp *sync.WaitGroup, pool *requestsPool,
) {
	defer wtgrp.Done()

	repo, imageTag := common.GetImageDirAndTag(imageName)

	tagListEndpoint, err := combineServerAndEndpointURL(config.ServURL, fmt.Sprintf("/v2/%s/tags/list", repo))
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	tagList := &tagListResp{}
	_, err = makeGETRequest(ctx, tagListEndpoint, username, password, config.VerifyTLS,
		config.Debug, &tagList, config.ResultWriter)

	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	for _, tag := range tagList.Tags {
		hasTagPrefix := strings.HasPrefix(tag, "sha256-")
		hasTagSuffix := strings.HasSuffix(tag, ".sig")

		// check if it's an image or a signature
		// we don't want to show signatures in cli responses
		if hasTagPrefix && hasTagSuffix {
			continue
		}

		shouldMatchTag := imageTag != ""
		matchesTag := tag == imageTag

		// when the tag is empty we match everything
		if shouldMatchTag && !matchesTag {
			continue
		}

		wtgrp.Add(1)

		go addManifestCallToPool(ctx, config, pool, username, password, repo, tag, rch, wtgrp)
	}
}

func (service searchService) getImagesByDigest(ctx context.Context, config SearchConfig, username,
	password string, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(
		`{
			ImageListForDigest(id: "%s") {
				Results {
					RepoName Tag
					Digest
					MediaType
					Manifests {
						Digest
						ConfigDigest
						Size
						Platform {Os Arch}
						IsSigned
						Layers {Size Digest}
						LastUpdated
					}
					LastUpdated
					Size
					IsSigned
				}
			}
		}`,
		digest)

	result := &common.ImagesForDigest{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	if result.Errors != nil {
		var errBuilder strings.Builder

		for _, err := range result.Errors {
			fmt.Fprintln(&errBuilder, err.Message)
		}

		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)
	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, image := range result.Results {
		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, image.RepoName, image.Tag, rch, &localWg)
	}

	localWg.Wait()
}

// Query using GQL, the query string is passed as a parameter
// errors are returned in the stringResult channel, the unmarshalled payload is in resultPtr.
func (service searchService) makeGraphQLQuery(ctx context.Context,
	config SearchConfig, username, password, query string,
	resultPtr interface{},
) error {
	endPoint, err := combineServerAndEndpointURL(config.ServURL, constants.FullSearchPrefix)
	if err != nil {
		return err
	}

	err = makeGraphQLRequest(ctx, endPoint, query, username, password, config.VerifyTLS,
		config.Debug, resultPtr, config.ResultWriter)
	if err != nil {
		return err
	}

	return nil
}

func checkResultGraphQLQuery(ctx context.Context, err error, resultErrors []common.ErrorGQL,
) error {
	if err != nil {
		if common.IsContextDone(ctx) {
			return nil //nolint:nilnil
		}

		return err
	}

	if resultErrors != nil {
		var errBuilder strings.Builder

		for _, error := range resultErrors {
			fmt.Fprintln(&errBuilder, error.Message)
		}

		if common.IsContextDone(ctx) {
			return nil
		}

		//nolint: goerr113
		return errors.New(errBuilder.String())
	}

	return nil
}

func addManifestCallToPool(ctx context.Context, config SearchConfig, pool *requestsPool,
	username, password, imageName, tagName string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()

	manifestEndpoint, err := combineServerAndEndpointURL(config.ServURL,
		fmt.Sprintf("/v2/%s/manifests/%s", imageName, tagName))
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}
	}

	job := httpJob{
		url:       manifestEndpoint,
		username:  username,
		imageName: imageName,
		password:  password,
		tagName:   tagName,
		config:    config,
	}

	wtgrp.Add(1)
	pool.submitJob(&job)
}

type cveResult struct {
	Errors []common.ErrorGQL `json:"errors"`
	Data   cveData           `json:"data"`
}

type tagListResp struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

//nolint:tagliatelle // graphQL schema
type packageList struct {
	Name             string `json:"Name"`
	PackagePath      string `json:"PackagePath"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

//nolint:tagliatelle // graphQL schema
type cve struct {
	ID          string        `json:"Id"`
	Severity    string        `json:"Severity"`
	Title       string        `json:"Title"`
	Description string        `json:"Description"`
	PackageList []packageList `json:"PackageList"`
}

type cveDiffListResp struct {
	Data   cveDiffResultsForImages `json:"data"`
	Errors []common.ErrorGQL       `json:"errors"`
}

type cveDiffResultsForImages struct {
	CveDiffResult cveDiffResult `json:"cveDiffListForImages"`
}

type cveDiffResult struct {
	Minuend    ImageIdentifier                  `json:"minuend"`
	Subtrahend ImageIdentifier                  `json:"subtrahend"`
	CVEList    []cve                            `json:"cveList"`
	Summary    common.ImageVulnerabilitySummary `json:"summary"`
}

//nolint:tagliatelle // graphQL schema
type cveListForImage struct {
	Tag     string                           `json:"Tag"`
	CVEList []cve                            `json:"CVEList"`
	Summary common.ImageVulnerabilitySummary `json:"Summary"`
}

//nolint:tagliatelle // graphQL schema
type cveData struct {
	CVEListForImage cveListForImage `json:"cveListForImage"`
}

func (cve cveResult) string(format string, verbose bool) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutputFormat:
		{
			var out string
			if verbose {
				out = cve.stringPlainTextDetailed()
			} else {
				out = cve.stringPlainText()
			}

			return out, nil
		}
	case jsonFormat:
		return cve.stringJSON()
	case ymlFormat, yamlFormat:
		return cve.stringYAML()
	default:
		return "", zerr.ErrInvalidOutputFormat
	}
}

func (cve cveResult) stringPlainTextDetailed() string {
	var builder strings.Builder

	for _, cveListItem := range cve.Data.CVEListForImage.CVEList {
		cveDesc := strings.TrimSpace(cveListItem.Description)
		if len(cveDesc) == 0 {
			cveDesc = "Not Specified"
		}
		cveMetaData := fmt.Sprintf(
			"%s\nSeverity: %s\nTitle: %s\nDescription:\n%s\n\n",
			cveListItem.ID, cveListItem.Severity, cveListItem.Title, cveDesc,
		)
		fmt.Fprint(&builder, cveMetaData)
		fmt.Fprint(&builder, "Vulnerable Packages:\n")

		for _, pkg := range cveListItem.PackageList {
			pkgMetaData := fmt.Sprintf(
				" Package Name: %s\n Package Path: %s\n Installed Version: %s\n Fixed Version: %s\n\n",
				pkg.Name, pkg.PackagePath, pkg.InstalledVersion, pkg.FixedVersion,
			)
			fmt.Fprint(&builder, pkgMetaData)
		}

		if len(cveListItem.PackageList) == 0 {
			fmt.Fprintf(&builder, "No Vulnerable Packages\n\n")
		}

		fmt.Fprint(&builder, "\n")
	}

	return builder.String()
}

func (cve cveResult) stringPlainText() string {
	var builder strings.Builder

	table := getCVETableWriter(&builder)

	for _, cveListItem := range cve.Data.CVEListForImage.CVEList {
		id := ellipsize(cveListItem.ID, cveIDWidth, ellipsis)
		title := ellipsize(cveListItem.Title, cveTitleWidth, ellipsis)
		severity := ellipsize(cveListItem.Severity, cveSeverityWidth, ellipsis)
		row := make([]string, 3) //nolint:gomnd
		row[colCVEIDIndex] = id
		row[colCVESeverityIndex] = severity
		row[colCVETitleIndex] = title

		table.Append(row)

		for _, pkg := range cveListItem.PackageList {
			pkgRow := generateTableRowForVulnerablePackage(pkg)
			table.Append(pkgRow)
		}
	}

	table.Render()

	return builder.String()
}

func generateTableRowForVulnerablePackage(pkg packageList) []string {
	row := make([]string, cveColTotalCount)
	pkgName := ellipsize(pkg.Name, cveVulnPkgNameWidth, ellipsis)
	pkgPath := "-"

	if pkg.PackagePath != "" {
		pkgPath = ellipsize(pkg.PackagePath, cveVulnPkgPathWidth, ellipsis)
	}
	pkgInstalledVer := ellipsize(pkg.InstalledVersion, cveVulnPkgInstalledVerWidth, ellipsis)
	pkgFixedVer := ellipsize(pkg.FixedVersion, cveVulnPkgFixedVerWidth, ellipsis)

	row[colCVEVulnPkgNameIndex] = pkgName
	row[colCVEVulnPkgPathIndex] = pkgPath
	row[colCVEVulnPkgInstalledVerIndex] = pkgInstalledVer
	row[colCVEVulnPkgFixedVerIndex] = pkgFixedVer

	return row
}

func (cve cveResult) stringJSON() (string, error) {
	// Output is in json lines format - do not indent, append new line after json
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(cve.Data.CVEListForImage)
	if err != nil {
		return "", err
	}

	return string(body) + "\n", nil
}

func (cve cveResult) stringYAML() (string, error) {
	// Output will be a multidoc yaml - use triple-dash to indicate a new document
	body, err := yaml.Marshal(&cve.Data.CVEListForImage)
	if err != nil {
		return "", err
	}

	return "---\n" + string(body), nil
}

type referrersResult []common.Referrer

func (ref referrersResult) string(format string, maxArtifactTypeLen int) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutputFormat:
		return ref.stringPlainText(maxArtifactTypeLen)
	case jsonFormat:
		return ref.stringJSON()
	case ymlFormat, yamlFormat:
		return ref.stringYAML()
	default:
		return "", zerr.ErrInvalidOutputFormat
	}
}

func (ref referrersResult) stringPlainText(maxArtifactTypeLen int) (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)

	table.SetColMinWidth(refArtifactTypeIndex, maxArtifactTypeLen)
	table.SetColMinWidth(refDigestIndex, digestWidth)
	table.SetColMinWidth(refSizeIndex, sizeWidth)

	for _, referrer := range ref {
		artifactType := ellipsize(referrer.ArtifactType, maxArtifactTypeLen, ellipsis)
		// digest := ellipsize(godigest.Digest(referrer.Digest).Encoded(), digestWidth, "")
		size := ellipsize(humanize.Bytes(uint64(referrer.Size)), sizeWidth, ellipsis)

		row := make([]string, refRowWidth)
		row[refArtifactTypeIndex] = artifactType
		row[refDigestIndex] = referrer.Digest
		row[refSizeIndex] = size

		table.Append(row)
	}

	table.Render()

	return builder.String(), nil
}

func (ref referrersResult) stringJSON() (string, error) {
	// Output is in json lines format - do not indent, append new line after json
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(ref)
	if err != nil {
		return "", err
	}

	return string(body) + "\n", nil
}

func (ref referrersResult) stringYAML() (string, error) {
	// Output will be a multidoc yaml - use triple-dash to indicate a new document
	body, err := yaml.Marshal(ref)
	if err != nil {
		return "", err
	}

	return "---\n" + string(body), nil
}

type repoStruct common.RepoSummary

func (repo repoStruct) string(format string, maxImgNameLen, maxTimeLen int, verbose bool) (string, error) { //nolint: lll
	switch strings.ToLower(format) {
	case "", defaultOutputFormat:
		return repo.stringPlainText(maxImgNameLen, maxTimeLen, verbose)
	case jsonFormat:
		return repo.stringJSON()
	case ymlFormat, yamlFormat:
		return repo.stringYAML()
	default:
		return "", zerr.ErrInvalidOutputFormat
	}
}

func (repo repoStruct) stringPlainText(repoMaxLen, maxTimeLen int, verbose bool) (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)

	table.SetColMinWidth(repoNameIndex, repoMaxLen)
	table.SetColMinWidth(repoSizeIndex, sizeWidth)
	table.SetColMinWidth(repoLastUpdatedIndex, maxTimeLen)
	table.SetColMinWidth(repoDownloadsIndex, downloadsWidth)
	table.SetColMinWidth(repoStarsIndex, signedWidth)

	if verbose {
		table.SetColMinWidth(repoPlatformsIndex, platformWidth)
	}

	repoSize, err := strconv.Atoi(repo.Size)
	if err != nil {
		return "", err
	}

	repoName := repo.Name
	repoLastUpdated := repo.LastUpdated
	repoDownloads := repo.DownloadCount
	repoStars := repo.StarCount
	repoPlatforms := repo.Platforms

	row := make([]string, repoRowWidth)
	row[repoNameIndex] = repoName
	row[repoSizeIndex] = ellipsize(strings.ReplaceAll(humanize.Bytes(uint64(repoSize)), " ", ""), sizeWidth, ellipsis)
	row[repoLastUpdatedIndex] = repoLastUpdated.String()
	row[repoDownloadsIndex] = strconv.Itoa(repoDownloads)
	row[repoStarsIndex] = strconv.Itoa(repoStars)

	if verbose && len(repoPlatforms) > 0 {
		row[repoPlatformsIndex] = getPlatformStr(repoPlatforms[0])
		repoPlatforms = repoPlatforms[1:]
	}

	table.Append(row)

	if verbose {
		for _, platform := range repoPlatforms {
			row := make([]string, repoRowWidth)

			row[repoPlatformsIndex] = getPlatformStr(platform)

			table.Append(row)
		}
	}

	table.Render()

	return builder.String(), nil
}

func (repo repoStruct) stringJSON() (string, error) {
	// Output is in json lines format - do not indent, append new line after json
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(repo)
	if err != nil {
		return "", err
	}

	return string(body) + "\n", nil
}

func (repo repoStruct) stringYAML() (string, error) {
	// Output will be a multidoc yaml - use triple-dash to indicate a new document
	body, err := yaml.Marshal(&repo)
	if err != nil {
		return "", err
	}

	return "---\n" + string(body), nil
}

type imageStruct common.ImageSummary

func (img imageStruct) string(format string, maxImgNameLen, maxTagLen, maxPlatformLen int, verbose bool) (string, error) { //nolint: lll
	switch strings.ToLower(format) {
	case "", defaultOutputFormat:
		return img.stringPlainText(maxImgNameLen, maxTagLen, maxPlatformLen, verbose)
	case jsonFormat:
		return img.stringJSON()
	case ymlFormat, yamlFormat:
		return img.stringYAML()
	default:
		return "", zerr.ErrInvalidOutputFormat
	}
}

func (img imageStruct) stringPlainText(maxImgNameLen, maxTagLen, maxPlatformLen int, verbose bool) (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)

	table.SetColMinWidth(colImageNameIndex, maxImgNameLen)
	table.SetColMinWidth(colTagIndex, maxTagLen)
	table.SetColMinWidth(colPlatformIndex, platformWidth)
	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)
	table.SetColMinWidth(colIsSignedIndex, isSignedWidth)

	if verbose {
		table.SetColMinWidth(colConfigIndex, configWidth)
		table.SetColMinWidth(colLayersIndex, layersWidth)
	}

	var imageName, tagName string

	imageName = img.RepoName
	tagName = img.Tag

	if imageNameWidth > maxImgNameLen {
		maxImgNameLen = imageNameWidth
	}

	if tagWidth > maxTagLen {
		maxTagLen = tagWidth
	}

	// adding spaces so that image name and tag columns are aligned
	// in case the name/tag are fully shown and too long
	var offset string
	if maxImgNameLen > len(imageName) {
		offset = strings.Repeat(" ", maxImgNameLen-len(imageName))
		imageName += offset
	}

	if maxTagLen > len(tagName) {
		offset = strings.Repeat(" ", maxTagLen-len(tagName))
		tagName += offset
	}

	err := addImageToTable(table, &img, maxPlatformLen, imageName, tagName, verbose)
	if err != nil {
		return "", err
	}

	table.Render()

	return builder.String(), nil
}

func addImageToTable(table *tablewriter.Table, img *imageStruct, maxPlatformLen int,
	imageName, tagName string, verbose bool,
) error {
	switch img.MediaType {
	case ispec.MediaTypeImageManifest:
		return addManifestToTable(table, imageName, tagName, &img.Manifests[0], maxPlatformLen, verbose)
	case ispec.MediaTypeImageIndex:
		return addImageIndexToTable(table, img, maxPlatformLen, imageName, tagName, verbose)
	}

	return nil
}

func addImageIndexToTable(table *tablewriter.Table, img *imageStruct, maxPlatformLen int,
	imageName, tagName string, verbose bool,
) error {
	indexDigest, err := godigest.Parse(img.Digest)
	if err != nil {
		return fmt.Errorf("error parsing index digest %s: %w", indexDigest, err)
	}
	row := make([]string, rowWidth)
	row[colImageNameIndex] = imageName
	row[colTagIndex] = tagName
	row[colDigestIndex] = ellipsize(indexDigest.Encoded(), digestWidth, "")
	row[colPlatformIndex] = "*"

	imgSize, _ := strconv.ParseUint(img.Size, 10, 64)
	row[colSizeIndex] = ellipsize(strings.ReplaceAll(humanize.Bytes(imgSize), " ", ""), sizeWidth, ellipsis)
	row[colIsSignedIndex] = strconv.FormatBool(img.IsSigned)

	if verbose {
		row[colConfigIndex] = ""
		row[colLayersIndex] = ""
	}

	table.Append(row)

	for i := range img.Manifests {
		err := addManifestToTable(table, "", "", &img.Manifests[i], maxPlatformLen, verbose)
		if err != nil {
			return err
		}
	}

	return nil
}

func addManifestToTable(table *tablewriter.Table, imageName, tagName string, manifest *common.ManifestSummary,
	maxPlatformLen int, verbose bool,
) error {
	manifestDigest, err := godigest.Parse(manifest.Digest)
	if err != nil {
		return fmt.Errorf("error parsing manifest digest %s: %w", manifest.Digest, err)
	}

	configDigest, err := godigest.Parse(manifest.ConfigDigest)
	if err != nil {
		return fmt.Errorf("error parsing config digest %s: %w", manifest.ConfigDigest, err)
	}

	platform := getPlatformStr(manifest.Platform)

	if maxPlatformLen > len(platform) {
		offset := strings.Repeat(" ", maxPlatformLen-len(platform))
		platform += offset
	}

	manifestDigestStr := ellipsize(manifestDigest.Encoded(), digestWidth, "")
	configDigestStr := ellipsize(configDigest.Encoded(), configWidth, "")
	imgSize, _ := strconv.ParseUint(manifest.Size, 10, 64)
	size := ellipsize(strings.ReplaceAll(humanize.Bytes(imgSize), " ", ""), sizeWidth, ellipsis)
	isSigned := manifest.IsSigned
	row := make([]string, 8) //nolint:gomnd

	row[colImageNameIndex] = imageName
	row[colTagIndex] = tagName
	row[colDigestIndex] = manifestDigestStr
	row[colPlatformIndex] = platform
	row[colSizeIndex] = size
	row[colIsSignedIndex] = strconv.FormatBool(isSigned)

	if verbose {
		row[colConfigIndex] = configDigestStr
		row[colLayersIndex] = ""
	}

	table.Append(row)

	if verbose {
		for _, entry := range manifest.Layers {
			layerSize, _ := strconv.ParseUint(entry.Size, 10, 64)
			size := ellipsize(strings.ReplaceAll(humanize.Bytes(layerSize), " ", ""), sizeWidth, ellipsis)

			layerDigest, err := godigest.Parse(entry.Digest)
			if err != nil {
				return fmt.Errorf("error parsing layer digest %s: %w", entry.Digest, err)
			}

			layerDigestStr := ellipsize(layerDigest.Encoded(), digestWidth, "")

			layerRow := make([]string, 8) //nolint:gomnd
			layerRow[colImageNameIndex] = ""
			layerRow[colTagIndex] = ""
			layerRow[colDigestIndex] = ""
			layerRow[colPlatformIndex] = ""
			layerRow[colSizeIndex] = size
			layerRow[colConfigIndex] = ""
			layerRow[colLayersIndex] = layerDigestStr

			table.Append(layerRow)
		}
	}

	return nil
}

func getPlatformStr(platform common.Platform) string {
	if platform.Arch == "" && platform.Os == "" {
		return ""
	}

	fullPlatform := platform.Os

	if platform.Arch != "" {
		fullPlatform = fullPlatform + "/" + platform.Arch
		fullPlatform = strings.Trim(fullPlatform, "/")

		if platform.Variant != "" {
			fullPlatform = fullPlatform + "/" + platform.Variant
		}
	}

	return fullPlatform
}

func (img imageStruct) stringJSON() (string, error) {
	// Output is in json lines format - do not indent, append new line after json
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(img)
	if err != nil {
		return "", err
	}

	return string(body) + "\n", nil
}

func (img imageStruct) stringYAML() (string, error) {
	// Output will be a multidoc yaml - use triple-dash to indicate a new document
	body, err := yaml.Marshal(&img)
	if err != nil {
		return "", err
	}

	return "---\n" + string(body), nil
}

type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

func combineServerAndEndpointURL(serverURL, endPoint string) (string, error) {
	if err := validateURL(serverURL); err != nil {
		return "", err
	}

	newURL, err := url.Parse(serverURL)
	if err != nil {
		return "", zerr.ErrInvalidURL
	}

	newURL, _ = newURL.Parse(endPoint)

	return newURL.String(), nil
}

func ellipsize(text string, max int, trailing string) string {
	text = strings.TrimSpace(text)
	if len(text) <= max {
		return text
	}

	chopLength := len(trailing)

	return text[:max-chopLength] + trailing
}

func getImageTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	return table
}

func getCVETableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	table.SetColMinWidth(colCVEIDIndex, cveIDWidth)
	table.SetColMinWidth(colCVESeverityIndex, cveSeverityWidth)
	table.SetColMinWidth(colCVETitleIndex, cveTitleWidth)
	table.SetColMinWidth(colCVEVulnPkgNameIndex, cveVulnPkgNameWidth)
	table.SetColMinWidth(colCVEVulnPkgPathIndex, cveVulnPkgPathWidth)
	table.SetColMinWidth(colCVEVulnPkgInstalledVerIndex, cveVulnPkgInstalledVerWidth)
	table.SetColMinWidth(colCVEVulnPkgFixedVerIndex, cveVulnPkgFixedVerWidth)

	return table
}

func getReferrersTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	return table
}

func getRepoTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	return table
}

func (service searchService) getRepos(ctx context.Context, config SearchConfig, username, password string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	catalog := &catalogResponse{}

	catalogEndPoint, err := combineServerAndEndpointURL(config.ServURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtCatalogPrefix))
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	_, err = makeGETRequest(ctx, catalogEndPoint, username, password, config.VerifyTLS,
		config.Debug, catalog, config.ResultWriter)
	if err != nil {
		if common.IsContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	fmt.Fprintln(config.ResultWriter, "\nREPOSITORY NAME")

	if config.SortBy == SortByAlphabeticAsc {
		for i := 0; i < len(catalog.Repositories); i++ {
			fmt.Fprintln(config.ResultWriter, catalog.Repositories[i])
		}
	} else {
		for i := len(catalog.Repositories) - 1; i >= 0; i-- {
			fmt.Fprintln(config.ResultWriter, catalog.Repositories[i])
		}
	}
}

const (
	imageNameWidth   = 10
	tagWidth         = 8
	digestWidth      = 8
	platformWidth    = 14
	sizeWidth        = 10
	isSignedWidth    = 8
	downloadsWidth   = 10
	signedWidth      = 10
	lastUpdatedWidth = 14
	configWidth      = 8
	layersWidth      = 8
	ellipsis         = "..."

	cveIDWidth                  = 16
	cveSeverityWidth            = 8
	cveTitleWidth               = 48
	cveVulnPkgNameWidth         = 35
	cveVulnPkgPathWidth         = 30
	cveVulnPkgInstalledVerWidth = 20
	cveVulnPkgFixedVerWidth     = 20

	colCVEIDIndex                  = 0
	colCVESeverityIndex            = 1
	colCVETitleIndex               = 2
	colCVEVulnPkgNameIndex         = 3
	colCVEVulnPkgPathIndex         = 4
	colCVEVulnPkgInstalledVerIndex = 5
	colCVEVulnPkgFixedVerIndex     = 6

	cveColTotalCount = 7

	defaultOutputFormat = "text"
)

const (
	colImageNameIndex = iota
	colTagIndex
	colPlatformIndex
	colDigestIndex
	colConfigIndex
	colIsSignedIndex
	colLayersIndex
	colSizeIndex

	rowWidth
)

const (
	repoNameIndex = iota
	repoSizeIndex
	repoLastUpdatedIndex
	repoDownloadsIndex
	repoStarsIndex
	repoPlatformsIndex

	repoRowWidth
)

const (
	refArtifactTypeIndex = iota
	refSizeIndex
	refDigestIndex

	refRowWidth
)
