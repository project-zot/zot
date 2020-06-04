package cli

import (
	"context"
	"net/url"
	"strings"

	zotErrors "github.com/anuvu/zot/errors"

	"github.com/machinebox/graphql"
	"github.com/olekukonko/tablewriter"
)

type CveSearchService interface {
	findCveByImageName(imageName string, serverUrl string) (CVEListForImageStruct, error)
	findImagesByCveId(cveID string, serverUrl string) (ImageListForCVEStruct, error)
}
type searchService struct{}

func NewCveSearchService() CveSearchService {
	return new(searchService)
}

func makeGraphQLRequest(serverUrl string, query string, params map[string]string, resultStructReference interface{}) error {
	newUrl, err := createEndpointUrl(serverUrl)
	if err != nil {
		return err
	}
	client := graphql.NewClient(newUrl)
	req := graphql.NewRequest(query)

	for key, value := range params {
		req.Var(key, value)
	}

	req.Header.Set("Cache-Control", "no-cache")
	ctx := context.Background()
	if err := client.Run(ctx, req, resultStructReference); err != nil {
		return err
	}
	return nil
}
func (service searchService) findCveByImageName(imageName string, serverUrl string) (CVEListForImageStruct, error) {
	query := "query ($imageName: String!) {CVEListForImage (repo: $imageName) {Tag CVEList {Id Description Severity}}}"
	result := &CVEListForImageStruct{}
	params := make(map[string]string)
	params["imageName"] = imageName

	if err := makeGraphQLRequest(serverUrl, query, params, result); err != nil {
		return CVEListForImageStruct{}, err
	}
	return *result, nil
}

type CVEListForImageStruct struct {
	CVEListForImage []struct {
		Tag     string
		CVEList []struct {
			Id          string
			Description string
			Severity    string
		}
	}
}

func (c CVEListForImageStruct) String() string {
	stringBuilder := &strings.Builder{}
	for _, image := range c.CVEListForImage {
		stringBuilder.WriteString("Tag:" + image.Tag + "\n")
		stringBuilder.WriteString("CVE List:\n")

		table := tablewriter.NewWriter(stringBuilder)
		table.SetHeader([]string{"ID", "Description", "Severity"})
		table.SetRowLine(true)
		for _, cve := range image.CVEList {
			row := []string{cve.Id, cve.Severity, cve.Description}
			table.Append(row)
		}
		table.Render()
		stringBuilder.WriteString("\n")
	}
	return stringBuilder.String()
}

func (service searchService) findImagesByCveId(cveID string, serverUrl string) (ImageListForCVEStruct, error) {
	query := "query ($cveID: String!) {ImageListForCVE (text: $cveID) {Tags Name}}"
	result := &ImageListForCVEStruct{}
	params := make(map[string]string)
	params["cveID"] = cveID

	if err := makeGraphQLRequest(serverUrl, query, params, result); err != nil {
		return ImageListForCVEStruct{}, err
	}
	return *result, nil
}

func (c ImageListForCVEStruct) String() string {
	stringBuilder := &strings.Builder{}
	for _, image := range c.ImageListForCVE {
		stringBuilder.WriteString("Images List:\n")
		stringBuilder.WriteString("Name:" + image.Name + "\n")

		table := tablewriter.NewWriter(stringBuilder)
		table.SetHeader([]string{"Tag"})
		table.SetRowLine(true)
		for _, tag := range image.Tags {
			row := []string{tag}
			table.Append(row)
		}
		table.Render()
		stringBuilder.WriteString("\n")
	}
	return stringBuilder.String()
}

type ImageListForCVEStruct struct {
	ImageListForCVE []struct {
		Name string
		Tags []string
	}
}

func createEndpointUrl(rawUrl string) (string, error) {
	if !isUrl(rawUrl) {
		return "", zotErrors.ErrInvalidURL
	}
	newUrl, err := url.Parse(rawUrl)
	if err != nil {
		return "", zotErrors.ErrInvalidURL
	}
	newUrl, _ = newUrl.Parse("/query")
	return newUrl.String(), nil
}

func isUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
} // copied from https://stackoverflow.com/a/55551215
