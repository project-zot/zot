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
		imageName string) (*cveResult, error)
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
	getCveByImage(ctx context.Context, config searchConfig, username, password, imageName string,
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
				RepoName,
				Tag,
				Digest,
				ConfigDigest,
				LastUpdated,
				IsSigned,
				Size
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
				RepoName,
				Tag,
				Digest,
				ConfigDigest,
				LastUpdated,
				IsSigned,
				Size
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
	query := fmt.Sprintf(`{ImageList(repo: "%s") {`+`
									RepoName Tag Digest ConfigDigest Size Layers {Size Digest}}
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
	query := fmt.Sprintf(`{ImageListForDigest(id: "%s") {`+`
									RepoName Tag Digest ConfigDigest Size Layers {Size Digest}}
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
	query := fmt.Sprintf(`{ImageListForCVE(id: "%s") {`+`
								RepoName Tag Digest Size}
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
	imageName string,
) (*cveResult, error) {
	query := fmt.Sprintf(`{ CVEListForImage (image:"%s")`+
		` { Tag CVEList { Id Title Severity Description `+
		`PackageList {Name InstalledVersion FixedVersion}} } }`, imageName)
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
	query := fmt.Sprintf(`{ImageListForCVE(id: "%s") {`+`
							RepoName Tag Digest Size}
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
	query := fmt.Sprintf(`{ImageListWithCVEFixed(id: "%s", image: "%s") {`+`
							RepoName Tag Digest Size}
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
		wtgrp.Add(1)

		go addManifestCallToPool(ctx, config, pool, username, password, imageName, tag, rch, wtgrp)
	}
}

func (service searchService) getImagesByCveID(ctx context.Context, config searchConfig, username,
	password, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ImageListForCVE(id: "%s") {`+`
								RepoName Tag Digest Size}
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

	for _, image := range result.Data.ImageList {
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

	query := fmt.Sprintf(`{ImageListForDigest(id: "%s") {`+`
								RepoName Tag Digest ConfigDigest Size Layers {Size Digest}}
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

	for _, image := range result.Data.ImageList {
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

	query := fmt.Sprintf(`{ImageListForCVE(id: "%s") {`+`
							RepoName Tag Digest ConfigDigest Size Layers {Size Digest}}
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

	for _, image := range result.Data.ImageList {
		if !strings.EqualFold(imageName, image.RepoName) {
			continue
		}

		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, image.RepoName, image.Tag, rch, &localWg)
	}

	localWg.Wait()
}

func (service searchService) getCveByImage(ctx context.Context, config searchConfig, username, password,
	imageName string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ CVEListForImage (image:"%s")`+
		` { Tag CVEList { Id Title Severity Description `+
		`PackageList {Name InstalledVersion FixedVersion}} } }`, imageName)
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

	query := fmt.Sprintf(`{ImageListWithCVEFixed (id: "%s", image: "%s") {`+`
							RepoName Tag Digest Size}
							  }`,
		cvid, imageName)
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

	for _, img := range result.Data.ImageList {
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
	endPoint, err := combineServerAndEndpointURL(*config.servURL, constants.ExtSearchPrefix)
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

	resultManifest := manifestResponse{}

	manifestEndpoint, err := combineServerAndEndpointURL(*config.servURL,
		fmt.Sprintf("/v2/%s/manifests/%s", imageName, tagName))
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}
	}

	job := manifestJob{
		url:          manifestEndpoint,
		username:     username,
		imageName:    imageName,
		password:     password,
		tagName:      tagName,
		manifestResp: resultManifest,
		config:       config,
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
		ImageList []imageStruct `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type imagesForCve struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type imageStruct struct {
	RepoName     string  `json:"repoName"`
	Tag          string  `json:"tag"`
	ConfigDigest string  `json:"configDigest"`
	Digest       string  `json:"digest"`
	Layers       []layer `json:"layers"`
	Size         string  `json:"size"`
	verbose      bool
}

type imageListStructGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"ImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForDigestGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"ImageListForDigest"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForDerivedImagesGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"DerivedImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imageListStructForBaseImagesGQL struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"BaseImageList"` //nolint:tagliatelle
	} `json:"data"`
}

type imagesForDigest struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageList []imageStruct `json:"ImageListForDigest"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type layer struct {
	Size   uint64 `json:"size,string"`
	Digest string `json:"digest"`
}

func (img imageStruct) string(format string, maxImgNameLen, maxTagLen int) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutoutFormat:
		return img.stringPlainText(maxImgNameLen, maxTagLen)
	case "json":
		return img.stringJSON()
	case "yml", "yaml":
		return img.stringYAML()
	default:
		return "", ErrInvalidOutputFormat
	}
}

func (img imageStruct) stringPlainText(maxImgNameLen, maxTagLen int) (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)

	table.SetColMinWidth(colImageNameIndex, maxImgNameLen)
	table.SetColMinWidth(colTagIndex, maxTagLen)

	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)

	if img.verbose {
		table.SetColMinWidth(colConfigIndex, configWidth)
		table.SetColMinWidth(colLayersIndex, layersWidth)
	}

	var imageName, tagName string

	imageName = img.RepoName
	tagName = img.Tag
	digest := ellipsize(img.Digest, digestWidth, "")
	imgSize, _ := strconv.ParseUint(img.Size, 10, 64)
	size := ellipsize(strings.ReplaceAll(humanize.Bytes(imgSize), " ", ""), sizeWidth, ellipsis)
	config := ellipsize(img.ConfigDigest, configWidth, "")
	row := make([]string, 6) //nolint:gomnd

	row[colImageNameIndex] = imageName
	row[colTagIndex] = tagName
	row[colDigestIndex] = digest
	row[colSizeIndex] = size

	if img.verbose {
		row[colConfigIndex] = config
		row[colLayersIndex] = ""
	}

	table.Append(row)

	if img.verbose {
		for _, entry := range img.Layers {
			layerSize := entry.Size
			size := ellipsize(strings.ReplaceAll(humanize.Bytes(layerSize), " ", ""), sizeWidth, ellipsis)
			layerDigest := ellipsize(entry.Digest, digestWidth, "")

			layerRow := make([]string, 6) //nolint:gomnd
			layerRow[colImageNameIndex] = ""
			layerRow[colTagIndex] = ""
			layerRow[colDigestIndex] = ""
			layerRow[colSizeIndex] = size
			layerRow[colConfigIndex] = ""
			layerRow[colLayersIndex] = layerDigest

			table.Append(layerRow)
		}
	}

	table.Render()

	return builder.String(), nil
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

//nolint:tagliatelle
type manifestResponse struct {
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      uint64 `json:"size"`
	} `json:"layers"`
	Annotations struct {
		WsTychoStackerStackerYaml string `json:"ws.tycho.stacker.stacker_yaml"`
		WsTychoStackerGitVersion  string `json:"ws.tycho.stacker.git_version"`
	} `json:"annotations"`
	Config struct {
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
	} `json:"config"`
	SchemaVersion int `json:"schemaVersion"`
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
	imageNameWidth = 32
	tagWidth       = 24
	digestWidth    = 8
	sizeWidth      = 8
	configWidth    = 8
	layersWidth    = 8
	ellipsis       = "..."

	colImageNameIndex = 0
	colTagIndex       = 1
	colDigestIndex    = 2
	colConfigIndex    = 3
	colLayersIndex    = 4
	colSizeIndex      = 5

	cveIDWidth       = 16
	cveSeverityWidth = 8
	cveTitleWidth    = 48

	colCVEIDIndex       = 0
	colCVESeverityIndex = 1
	colCVETitleIndex    = 2

	defaultOutoutFormat = "text"
)
