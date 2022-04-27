// +build ui_base extended search

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	jsoniter "github.com/json-iterator/go"
	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v2"
	zotErrors "zotregistry.io/zot/errors"
)

type SearchService interface {
	getAllImages(ctx context.Context, config searchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImageByName(ctx context.Context, config searchConfig, username, password, imageName string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getCveByImage(ctx context.Context, config searchConfig, username, password, imageName string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImagesByCveID(ctx context.Context, config searchConfig, username, password, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImagesByDigest(ctx context.Context, config searchConfig, username, password, digest string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getImageByNameAndCVEID(ctx context.Context, config searchConfig, username, password, imageName, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
	getFixedTagsForCVE(ctx context.Context, config searchConfig, username, password, imageName, cvid string,
		channel chan stringResult, wtgrp *sync.WaitGroup)
}

type searchService struct{}

func NewSearchService() SearchService {
	return searchService{}
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

	catalogEndPoint, err := combineServerAndEndpointURL(*config.servURL, "/v2/_catalog")
	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	_, err = makeGETRequest(ctx, catalogEndPoint, username, password, *config.verifyTLS, catalog)
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

	tagsList := &tagListResp{}
	_, err = makeGETRequest(ctx, tagListEndpoint, username, password, *config.verifyTLS, &tagsList)

	if err != nil {
		if isContextDone(ctx) {
			return
		}
		rch <- stringResult{"", err}

		return
	}

	for _, tag := range tagsList.Tags {
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
								Name Tags }
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

	for _, image := range result.Data.ImageListForCVE {
		for _, tag := range image.Tags {
			localWg.Add(1)

			go addManifestCallToPool(ctx, config, rlim, username, password, image.Name, tag, rch, &localWg)
		}
	}

	localWg.Wait()
}

func (service searchService) getImagesByDigest(ctx context.Context, config searchConfig, username,
	password string, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ImageListForDigest(id: "%s") {`+`
									Name Tags }
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

	for _, image := range result.Data.ImageListForDigest {
		for _, tag := range image.Tags {
			localWg.Add(1)

			go addManifestCallToPool(ctx, config, rlim, username, password, image.Name, tag, rch, &localWg)
		}
	}

	localWg.Wait()
}

func (service searchService) getImageByNameAndCVEID(ctx context.Context, config searchConfig, username,
	password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ImageListForCVE(id: "%s") {`+`
									Name Tags }
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

	for _, image := range result.Data.ImageListForCVE {
		if !strings.EqualFold(imageName, image.Name) {
			continue
		}

		for _, tag := range image.Tags {
			localWg.Add(1)

			go addManifestCallToPool(ctx, config, rlim, username, password, image.Name, tag, rch, &localWg)
		}
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

func groupCVEsBySeverity(cveList []cve) []cve {
	high := make([]cve, 0)
	med := make([]cve, 0)
	low := make([]cve, 0)

	for _, cve := range cveList {
		switch cve.Severity {
		case "LOW":
			low = append(low, cve)

		case "MEDIUM":
			med = append(med, cve)

		case "HIGH":
			high = append(high, cve)
		}
	}

	return append(append(high, med...), low...)
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (service searchService) getFixedTagsForCVE(ctx context.Context, config searchConfig,
	username, password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	query := fmt.Sprintf(`{ImageListWithCVEFixed (id: "%s", image: "%s") {`+`
								 Tags {Name Timestamp} }
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

	for _, imgTag := range result.Data.ImageListWithCVEFixed.Tags {
		localWg.Add(1)

		go addManifestCallToPool(ctx, config, rlim, username, password, imageName, imgTag.Name, rch, &localWg)
	}

	localWg.Wait()
}

// Query using JQL, the query string is passed as a parameter
// errors are returned in the stringResult channel, the unmarshalled payload is in resultPtr.
func (service searchService) makeGraphQLQuery(ctx context.Context, config searchConfig,
	username, password, query string,
	resultPtr interface{},
) error {
	endPoint, err := combineServerAndEndpointURL(*config.servURL, "/query")
	if err != nil {
		return err
	}

	err = makeGraphQLRequest(ctx, endPoint, query, username, password, *config.verifyTLS, resultPtr)
	if err != nil {
		return err
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
		id := ellipsize(c.ID, cvidWidth, ellipsis)
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
		//nolint:tagliatelle // graphQL schema
		ImageListWithCVEFixed struct {
			Tags []struct {
				Name      string    `json:"Name"`
				Timestamp time.Time `json:"Timestamp"`
			} `json:"Tags"`
		} `json:"ImageListWithCVEFixed"`
	} `json:"data"`
}

type imagesForCve struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageListForCVE []tagListResp `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type imagesForDigest struct {
	Errors []errorGraphQL `json:"errors"`
	Data   struct {
		ImageListForDigest []tagListResp `json:"ImageListForDigest"` //nolint:tagliatelle // graphQL schema
	} `json:"data"`
}

type tagListResp struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type imageStruct struct {
	Name    string `json:"name"`
	Tags    []tags `json:"tags"`
	verbose bool
}

type tags struct {
	Name         string  `json:"name"`
	Size         uint64  `json:"size"`
	Digest       string  `json:"digest"`
	ConfigDigest string  `json:"configDigest"`
	Layers       []layer `json:"layerDigests"`
}

type layer struct {
	Size   uint64 `json:"size"`
	Digest string `json:"digest"`
}

func (img imageStruct) string(format string) (string, error) {
	switch strings.ToLower(format) {
	case "", defaultOutoutFormat:
		return img.stringPlainText()
	case "json":
		return img.stringJSON()
	case "yml", "yaml":
		return img.stringYAML()
	default:
		return "", ErrInvalidOutputFormat
	}
}

func (img imageStruct) stringPlainText() (string, error) {
	var builder strings.Builder

	table := getImageTableWriter(&builder)
	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colDigestIndex, digestWidth)
	table.SetColMinWidth(colSizeIndex, sizeWidth)

	if img.verbose {
		table.SetColMinWidth(colConfigIndex, configWidth)
		table.SetColMinWidth(colLayersIndex, layersWidth)
	}

	for _, tag := range img.Tags {
		imageName := ellipsize(img.Name, imageNameWidth, ellipsis)
		tagName := ellipsize(tag.Name, tagWidth, ellipsis)
		digest := ellipsize(tag.Digest, digestWidth, "")
		size := ellipsize(strings.ReplaceAll(humanize.Bytes(tag.Size), " ", ""), sizeWidth, ellipsis)
		config := ellipsize(tag.ConfigDigest, configWidth, "")
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
			for _, entry := range tag.Layers {
				layerSize := ellipsize(strings.ReplaceAll(humanize.Bytes(entry.Size), " ", ""), sizeWidth, ellipsis)
				layerDigest := ellipsize(entry.Digest, digestWidth, "")

				layerRow := make([]string, 6) //nolint:gomnd
				layerRow[colImageNameIndex] = ""
				layerRow[colTagIndex] = ""
				layerRow[colDigestIndex] = ""
				layerRow[colSizeIndex] = layerSize
				layerRow[colConfigIndex] = ""
				layerRow[colLayersIndex] = layerDigest

				table.Append(layerRow)
			}
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

type manifestResponse struct {
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      uint64 `json:"size"`
	} `json:"layers"`
	Annotations struct {
		WsTychoStackerStackerYaml string `json:"ws.tycho.stacker.stacker_yaml"` //nolint:tagliatelle // custom annotation
		WsTychoStackerGitVersion  string `json:"ws.tycho.stacker.git_version"`  //nolint:tagliatelle // custom annotation
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
	table.SetColMinWidth(colCVEIDIndex, cvidWidth)
	table.SetColMinWidth(colCVESeverityIndex, cveSeverityWidth)
	table.SetColMinWidth(colCVETitleIndex, cveTitleWidth)

	return table
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

	cvidWidth        = 16
	cveSeverityWidth = 8
	cveTitleWidth    = 48

	colCVEIDIndex       = 0
	colCVESeverityIndex = 1
	colCVETitleIndex    = 2

	defaultOutoutFormat = "text"
)
