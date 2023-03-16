//go:build search
// +build search

package cli

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
	"gopkg.in/yaml.v2"

	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/constants"
)

type SearchService interface { //nolint:interfacebloat
	getImagesGQL(ctx context.Context, config searchConfig, username, password string,
		imageName string) (*imageListStructGQL, error)
	getImagesByDigestGQL(ctx context.Context, config searchConfig, username, password string,
		digest string) (*imageListStructForDigestGQL, error)
	getCveByImageGQL(ctx context.Context, config searchConfig, username, password,
		imageName string, searchedCVE string) (*cveResult, error)
	getImagesByCveIDGQL(ctx context.Context, config searchConfig, username, password string,
		digest string) (*imagesForCve, error)
	getTagsForCVEGQL(ctx context.Context, config searchConfig, username, password, imageName,
		cveID string) (*imagesForCve, error)
	getFixedTagsForCVEGQL(ctx context.Context, config searchConfig, username, password, imageName,
		cveID string) (*fixedTags, error)
	getDerivedImageListGQL(ctx context.Context, config searchConfig, username, password string,
		derivedImage string) (*imageListStructForDerivedImagesGQL, error)
	getBaseImageListGQL(ctx context.Context, config searchConfig, username, password string,
		baseImage string) (*imageListStructForBaseImagesGQL, error)

	getAllImages(ctx context.Context, config searchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getCveByImage(ctx context.Context, config searchConfig, username, password, imageName, searchedCVE string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImagesByCveID(ctx context.Context, config searchConfig, username, password, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImagesByDigest(ctx context.Context, config searchConfig, username, password, digest string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getFixedTagsForCVE(ctx context.Context, config searchConfig, username, password, imageName, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getRepos(ctx context.Context, config searchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImageByName(ctx context.Context, config searchConfig, username, password, imageName string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImageByNameAndCVEID(ctx context.Context, config searchConfig, username, password, imageName, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
}

type searchService struct{}

func NewSearchService() SearchService {
	return searchService{}
}

func (service searchService) getDerivedImageListGQL(ctx context.Context, config searchConfig, username, password string,
	derivedImage string,
) (*imageListStructForDerivedImagesGQL, error) {
	query := fmt.Sprintf(`
		{
			DerivedImageList(image:"%s"){
				Results{
					RepoName,
					Tag,
					Manifests {
						Digest,
						ConfigDigest,
						Layers {Size Digest},
						LastUpdated,
						Size
					},
					LastUpdated,
					IsSigned,
					Size
				}
			}
		}`, derivedImage)

	result := &imageListStructForDerivedImagesGQL{}
	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getBaseImageListGQL(ctx context.Context, config searchConfig, username, password string,
	baseImage string,
) (*imageListStructForBaseImagesGQL, error) {
	query := fmt.Sprintf(`
		{
			BaseImageList(image:"%s"){
				Results{
					RepoName,
					Tag,
					Manifests {
						Digest,
						ConfigDigest,
						Layers {Size Digest},
						LastUpdated,
						Size
					},
					LastUpdated,
					IsSigned,
					Size
				}
			}
		}`, baseImage)

	result := &imageListStructForBaseImagesGQL{}
	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImagesGQL(ctx context.Context, config searchConfig, username, password string,
	imageName string,
) (*imageListStructGQL, error) {
	query := fmt.Sprintf(`
	{
		ImageList(repo: "%s") {
			Results {
				RepoName Tag 
				Manifests {
					Digest 
					ConfigDigest
					Size
					Platform {Os Arch}
					Layers {Size Digest}
				} 
				Size 
				IsSigned
			}
		}
	}`,
		imageName)
	result := &imageListStructGQL{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImagesByDigestGQL(ctx context.Context, config searchConfig, username, password string,
	digest string,
) (*imageListStructForDigestGQL, error) {
	query := fmt.Sprintf(`
	{
		ImageListForDigest(id: "%s") {
			Results {
				RepoName Tag 
				Manifests {
					Digest 
					ConfigDigest
					Size
					Layers {Size Digest}
					} 
				Size 
				IsSigned
			}
		}
	}`,
		digest)
	result := &imageListStructForDigestGQL{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImagesByCveIDGQL(ctx context.Context, config searchConfig, username,
	password, cveID string,
) (*imagesForCve, error) {
	query := fmt.Sprintf(`
	{
		ImageListForCVE(id: "%s") {
			Results {
				RepoName Tag 
				Manifests {
					Digest 
					ConfigDigest
					Size
					Layers {Size Digest}
					} 
				Size 
				IsSigned
			}
		}
	}`,
		cveID)
	result := &imagesForCve{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getCveByImageGQL(ctx context.Context, config searchConfig, username, password,
	imageName, searchedCVE string,
) (*cveResult, error) {
	query := fmt.Sprintf(`{ CVEListForImage (image:"%s", searchedCVE:"%s")`+
		` { Tag CVEList { Id Title Severity Description `+
		`PackageList {Name InstalledVersion FixedVersion}} } }`, imageName, searchedCVE)
	result := &cveResult{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	result.Data.CVEListForImage.CVEList = groupCVEsBySeverity(result.Data.CVEListForImage.CVEList)

	return result, nil
}

func (service searchService) getTagsForCVEGQL(ctx context.Context, config searchConfig,
	username, password, imageName, cveID string,
) (*imagesForCve, error) {
	query := fmt.Sprintf(`
		{
			ImageListForCVE(id: "%s") {
				Results {
					RepoName Tag
					Manifests {
						Digest 
						ConfigDigest
						Size
						Layers {Size Digest}
					} 
					Size
				}
			}
		}`,
		cveID)
	result := &imagesForCve{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getFixedTagsForCVEGQL(ctx context.Context, config searchConfig,
	username, password, imageName, cveID string,
) (*fixedTags, error) {
	query := fmt.Sprintf(`
		{
			ImageListWithCVEFixed(id: "%s", image: "%s") {
				Results {
					RepoName Tag 
					Manifests {
						Digest 
						ConfigDigest
						Size
						Layers {Size Digest}
						} 
					Size 
				}
			}
		}`,
		cveID, imageName)

	result := &fixedTags{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)

	if errResult := checkResultGraphQLQuery(ctx, err, result.Errors); errResult != nil {
		return nil, errResult
	}

	return result, nil
}

func (service searchService) getImageByName(ctx context.Context, config searchConfig,
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

func (service searchService) getAllImages(ctx context.Context, config searchConfig, username, password string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	catalog := &catalogResponse{}

	catalogEndPoint, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtCatalogPrefix))
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	_, err = makeGETRequest(ctx, catalogEndPoint, username, password, *config.verifyTLS,
		*config.debug, catalog, config.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
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

func getImage(ctx context.Context, config searchConfig, username, password, imageName string,
	rch chan stringResult, wtgrp *sync.WaitGroup, pool *requestsPool,
) {
	defer wtgrp.Done()

	tagListEndpoint, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("/v2/%s/tags/list", imageName))
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	tagList := &tagListResp{}
	_, err = makeGETRequest(ctx, tagListEndpoint, username, password, *config.verifyTLS,
		*config.debug, &tagList, config.resultWriter)

	if err != nil {
		if isContextDone(ctx) {
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

		wtgrp.Add(1)

		go addManifestCallToPool(ctx, config, pool, username, password, imageName, tag, rch, wtgrp)
	}
}

func (service searchService) getImagesByCveID(ctx context.Context, config searchConfig, username,
	password, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(
		`{
			ImageListForCVE(id: "%s") {
				Results {
					RepoName Tag 
					Manifests {
						Digest 
						ConfigDigest
						Size
						Layers {Size Digest}
						} 
					Size 
				}
			}
		}`,
		cvid)

	result := &imagesForCve{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	if result.Errors != nil || err != nil {
		var errBuilder strings.Builder

		for _, err := range result.Errors {
			fmt.Fprintln(&errBuilder, err.Message)
		}

		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)
	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, image := range result.Data.Results {
		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, image.RepoName, image.Tag, rch, &localWg)
	}

	localWg.Wait()
}

func (service searchService) getImagesByDigest(ctx context.Context, config searchConfig, username,
	password string, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(
		`{
			ImageListForDigest(id: "%s") {
				Results {
					RepoName Tag 
					Manifests {
						Digest 
						ConfigDigest
						Size
						Layers {Size Digest}
						} 
					Size 
				}
			}
		}`,
		digest)

	result := &imagesForDigest{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if isContextDone(ctx) {
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

		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)
	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, image := range result.Data.Results {
		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, image.RepoName, image.Tag, rch, &localWg)
	}

	localWg.Wait()
}

func (service searchService) getImageByNameAndCVEID(ctx context.Context, config searchConfig, username,
	password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(
		`{
			ImageListForCVE(id: "%s") {
				Results {
					RepoName Tag 
					Manifests {
						Digest 
						ConfigDigest
						Size
						Layers {Size Digest}
						} 
					Size 
				}
			}
		}`,
		cvid)

	result := &imagesForCve{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if isContextDone(ctx) {
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

		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)
	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, image := range result.Data.Results {
		if !strings.EqualFold(imageName, image.RepoName) {
			continue
		}

		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, image.RepoName, image.Tag, rch, &localWg)
	}

	localWg.Wait()
}

func (service searchService) getCveByImage(ctx context.Context, config searchConfig, username, password,
	imageName, searchedCVE string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ CVEListForImage (image:"%s", searchedCVE:"%s")`+
		` { Tag CVEList { Id Title Severity Description `+
		`PackageList {Name InstalledVersion FixedVersion}} } }`, imageName, searchedCVE)
	result := &cveResult{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if isContextDone(ctx) {
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

		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	result.Data.CVEListForImage.CVEList = groupCVEsBySeverity(result.Data.CVEListForImage.CVEList)

	str, err := result.string(*config.outputFormat)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	if isContextDone(ctx) {
		return
	}
	rch <- stringResult{str, nil}
}

func (service searchService) getFixedTagsForCVE(ctx context.Context, config searchConfig,
	username, password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`
	{
		ImageListWithCVEFixed (id: "%s", image: "%s") {
			Results {
				RepoName Tag 
				Manifests {
					Digest 
					ConfigDigest
					Size
					Layers {Size Digest}
					} 
				Size 
			}
		}
	}`, cvid, imageName)

	result := &fixedTags{}

	err := service.makeGraphQLQuery(ctx, config, username, password, query, result)
	if err != nil {
		if isContextDone(ctx) {
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

		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", errors.New(errBuilder.String())} //nolint: goerr113

		return
	}

	var localWg sync.WaitGroup

	rlim := newSmoothRateLimiter(&localWg, rch)
	localWg.Add(1)

	go rlim.startRateLimiter(ctx)

	for _, img := range result.Data.Results {
		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, imageName, img.Tag, rch, &localWg)
	}

	localWg.Wait()
}

func groupCVEsBySeverity(cveList []cve) []cve {
	var (
		unknown  = make([]cve, 0)
		none     = make([]cve, 0)
		high     = make([]cve, 0)
		med      = make([]cve, 0)
		low      = make([]cve, 0)
		critical = make([]cve, 0)
	)

	for _, cve := range cveList {
		switch cve.Severity {
		case "NONE":
			none = append(none, cve)

		case "LOW":
			low = append(low, cve)

		case "MEDIUM":
			med = append(med, cve)

		case "HIGH":
			high = append(high, cve)

		case "CRITICAL":
			critical = append(critical, cve)

		default:
			unknown = append(unknown, cve)
		}
	}
	vulnsCount := len(unknown) + len(none) + len(high) + len(med) + len(low) + len(critical)
	vulns := make([]cve, 0, vulnsCount)

	vulns = append(vulns, critical...)
	vulns = append(vulns, high...)
	vulns = append(vulns, med...)
	vulns = append(vulns, low...)
	vulns = append(vulns, none...)
	vulns = append(vulns, unknown...)

	return vulns
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// Query using JQL, the query string is passed as a parameter
// errors are returned in the stringResult channel, the unmarshalled payload is in resultPtr.
func (service searchService) makeGraphQLQuery(ctx context.Context,
	config searchConfig, username, password, query string,
	resultPtr interface{},
) error {
	endPoint, err := combineServerAndEndpointURL(*config.servURL, constants.FullSearchPrefix)
	if err != nil {
		return err
	}

	err = makeGraphQLRequest(ctx, endPoint, query, username, password, *config.verifyTLS,
		*config.debug, resultPtr, config.resultWriter)
	if err != nil {
		return err
	}

	return nil
}

func checkResultGraphQLQuery(ctx context.Context, err error, resultErrors []errorGraphQL,
) error {
	if err != nil {
		if isContextDone(ctx) {
			return nil //nolint:nilnil
		}

		return err
	}

	if resultErrors != nil {
		var errBuilder strings.Builder

		for _, error := range resultErrors {
			fmt.Fprintln(&errBuilder, error.Message)
		}

		if isContextDone(ctx) {
			return nil
		}

		//nolint: goerr113
		return errors.New(errBuilder.String())
	}

	return nil
}

func addManifestCallToPool(ctx context.Context, config searchConfig, pool *requestsPool,
	username, password, imageName, tagName string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()

	manifestEndpoint, err := combineServerAndEndpointURL(*config.servURL,
		fmt.Sprintf("/v2/%s/manifests/%s", imageName, tagName))
	if err != nil {
		if isContextDone(ctx) {
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
	Errors []errorGraphQL `json:"errors"`
	Data   cveData        `json:"data"`
}

type errorGraphQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type tagListResp struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

//nolint:tagliatelle // graphQL schema
type packageList struct {
	Name             string `json:"Name"`
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

//nolint:tagliatelle // graphQL schema
type cveListForImage struct {
	Tag     string `json:"Tag"`
	CVEList []cve  `json:"CVEList"`
}

//nolint:tagliatelle // graphQL schema
type cveData struct {
	CVEListForImage cveListForImage `json:"CVEListForImage"`
}

func (cve cveResult) string(format string) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutoutFormat:
		return cve.stringPlainText()
	case "json":
		return cve.stringJSON()
	case "yml", "yaml":
		return cve.stringYAML()
	default:
		return "", ErrInvalidOutputFormat
	}
}

func (cve cveResult) stringPlainText() (string, error) {
	var builder strings.Builder

	table := getCVETableWriter(&builder)

	for _, c := range cve.Data.CVEListForImage.CVEList {
		id := ellipsize(c.ID, cveIDWidth, ellipsis)
		title := ellipsize(c.Title, cveTitleWidth, ellipsis)
		severity := ellipsize(c.Severity, cveSeverityWidth, ellipsis)
		row := make([]string, 3) //nolint:gomnd
		row[colCVEIDIndex] = id
		row[colCVESeverityIndex] = severity
		row[colCVETitleIndex] = title

		table.Append(row)
	}

	table.Render()

	return builder.String(), nil
}

func (cve cveResult) stringJSON() (string, error) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.MarshalIndent(cve.Data.CVEListForImage, "", "  ")
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (cve cveResult) stringYAML() (string, error) {
	body, err := yaml.Marshal(&cve.Data.CVEListForImage)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

type fixedTags struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type imagesForCve struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type PaginatedImagesResult struct {
	Results []imageStruct `json:"results"`
}

type imageStruct struct {
	RepoName  string `json:"repoName"`
	Tag       string `json:"tag"`
	Manifests []manifestStruct
	Size      string `json:"size"`
	verbose   bool
	IsSigned  bool `json:"isSigned"`
}

type manifestStruct struct {
	ConfigDigest string   `json:"configDigest"`
	Digest       string   `json:"digest"`
	Layers       []layer  `json:"layers"`
	Platform     platform `json:"platform"`
	Size         string   `json:"size"`
	IsSigned     bool     `json:"isSigned"`
}

type platform struct {
	Os      string `json:"os"`
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
}

type DerivedImageList struct {
	Results []imageStruct `json:"results"`
}
type BaseImageList struct {
	Results []imageStruct `json:"results"`
}

type imageListStructGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"ImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForDigestGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"ImageListForDigest"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForDerivedImagesGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"DerivedImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForBaseImagesGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"BaseImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imagesForDigest struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		PaginatedImagesResult `json:"ImageListForDigest"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type layer struct {
	Size   int64  `json:"size,string"`
	Digest string `json:"digest"`
}

func (img imageStruct) string(format string, maxImgNameLen, maxTagLen, maxPlatformLen int) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutoutFormat:
		return img.stringPlainText(maxImgNameLen, maxTagLen, maxPlatformLen)
	case "json":
		return img.stringJSON()
	case "yml", "yaml":
		return img.stringYAML()
	default:
		return "", ErrInvalidOutputFormat
	}
}

func (img imageStruct) stringPlainText(maxImgNameLen, maxTagLen, maxPlatformLen int) (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)

	table.SetColMinWidth(colImageNameIndex, maxImgNameLen)
	table.SetColMinWidth(colTagIndex, maxTagLen)
	table.SetColMinWidth(colPlatformIndex, platformWidth)
	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)
	table.SetColMinWidth(colIsSignedIndex, isSignedWidth)

	if img.verbose {
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

	for i := range img.Manifests {
		manifestDigest, err := godigest.Parse(img.Manifests[i].Digest)
		if err != nil {
			return "", fmt.Errorf("error parsing manifest digest %s: %w", img.Manifests[i].Digest, err)
		}

		configDigest, err := godigest.Parse(img.Manifests[i].ConfigDigest)
		if err != nil {
			return "", fmt.Errorf("error parsing config digest %s: %w", img.Manifests[i].ConfigDigest, err)
		}

		platform := getPlatformStr(img.Manifests[i].Platform)

		if maxPlatformLen > len(platform) {
			offset = strings.Repeat(" ", maxPlatformLen-len(platform))
			platform += offset
		}

		minifestDigestStr := ellipsize(manifestDigest.Encoded(), digestWidth, "")
		configDigestStr := ellipsize(configDigest.Encoded(), configWidth, "")
		imgSize, _ := strconv.ParseUint(img.Manifests[i].Size, 10, 64)
		size := ellipsize(strings.ReplaceAll(humanize.Bytes(imgSize), " ", ""), sizeWidth, ellipsis)
		isSigned := img.IsSigned
		row := make([]string, 8) //nolint:gomnd

		row[colImageNameIndex] = imageName
		row[colTagIndex] = tagName
		row[colDigestIndex] = minifestDigestStr
		row[colPlatformIndex] = platform
		row[colSizeIndex] = size
		row[colIsSignedIndex] = strconv.FormatBool(isSigned)

		if img.verbose {
			row[colConfigIndex] = configDigestStr
			row[colLayersIndex] = ""
		}

		table.Append(row)

		if img.verbose {
			for _, entry := range img.Manifests[i].Layers {
				layerSize := entry.Size
				size := ellipsize(strings.ReplaceAll(humanize.Bytes(uint64(layerSize)), " ", ""), sizeWidth, ellipsis)

				layerDigest, err := godigest.Parse(entry.Digest)
				if err != nil {
					return "", fmt.Errorf("error parsing layer digest %s: %w", entry.Digest, err)
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
	}

	table.Render()

	return builder.String(), nil
}

func getPlatformStr(platf platform) string {
	if platf.Arch == "" && platf.Os == "" {
		return "N/A"
	}

	platform := platf.Os

	if platf.Arch != "" {
		platform = platform + "/" + platf.Arch
		platform = strings.Trim(platform, "/")

		if platf.Variant != "" {
			platform = platform + "/" + platf.Variant
		}
	}

	return platform
}

func (img imageStruct) stringJSON() (string, error) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.MarshalIndent(img, "", "  ")
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (img imageStruct) stringYAML() (string, error) {
	body, err := yaml.Marshal(&img)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

func combineServerAndEndpointURL(serverURL, endPoint string) (string, error) {
	if !isURL(serverURL) {
		return "", zotErrors.ErrInvalidURL
	}

	newURL, err := url.Parse(serverURL)
	if err != nil {
		return "", zotErrors.ErrInvalidURL
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

	return table
}

func (service searchService) getRepos(ctx context.Context, config searchConfig, username, password string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	catalog := &catalogResponse{}

	catalogEndPoint, err := combineServerAndEndpointURL(*config.servURL, fmt.Sprintf("%s%s",
		constants.RoutePrefix, constants.ExtCatalogPrefix))
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	_, err = makeGETRequest(ctx, catalogEndPoint, username, password, *config.verifyTLS,
		*config.debug, catalog, config.resultWriter)
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	fmt.Fprintln(config.resultWriter, "\n\nREPOSITORY NAME")

	for _, repo := range catalog.Repositories {
		fmt.Fprintln(config.resultWriter, repo)
	}
}

const (
	imageNameWidth = 10
	tagWidth       = 8
	digestWidth    = 8
	platformWidth  = 14
	sizeWidth      = 8
	isSignedWidth  = 8
	configWidth    = 8
	layersWidth    = 8
	ellipsis       = "..."

	colImageNameIndex = 0
	colTagIndex       = 1
	colDigestIndex    = 2
	colConfigIndex    = 3
	colPlatformIndex  = 4
	colIsSignedIndex  = 5
	colLayersIndex    = 6
	colSizeIndex      = 7

	cveIDWidth       = 16
	cveSeverityWidth = 8
	cveTitleWidth    = 48

	colCVEIDIndex       = 0
	colCVESeverityIndex = 1
	colCVETitleIndex    = 2

	defaultOutoutFormat = "text"
)
