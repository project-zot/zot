package cli

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	zotErrors "github.com/anuvu/zot/errors"
	resty "github.com/go-resty/resty/v2"
	"github.com/olekukonko/tablewriter"
)

type CveSearchService interface {
	findCveByImageName(imageName, serverUrl, username, password string) (CVEListForImageStruct, error)
	findImagesByCveId(cveID, serverUrl, username, password string) (ImageListForCVEStruct, error)
}
type searchService struct{}

func NewCveSearchService() CveSearchService {
	return new(searchService)
}

func makeGraphQLRequestNoAuth(serverUrl, query string, params map[string]string, resultStructPointer interface{}) error {
	newUrl, err := createEndpointUrl(serverUrl)
	if err != nil {
		return err
	}
	client := resty.New().
		SetDisableWarn(true).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //temp

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(query).
		Post(newUrl)

	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.New(resp.String())
	}
	err = client.JSONUnmarshal(resp.Body(), resultStructPointer)
	if err != nil {
		return err
	}
	return nil
}

func makeGraphQLRequestBasicAuth(serverUrl, query, username, password string, params map[string]string, resultStructPointer interface{}) error {
	newUrl, err := createEndpointUrl(serverUrl)
	if err != nil {
		return err
	}
	client := resty.New().
		SetDisableWarn(true).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //temp

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(query).
		SetBasicAuth(username, password).
		Post(newUrl)

	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.New(resp.String())
	}
	err = client.JSONUnmarshal(resp.Body(), resultStructPointer)
	if err != nil {
		return err
	}
	return nil
}

func (service searchService) findCveByImageName(imageName, serverUrl, username, password string) (CVEListForImageStruct, error) {
	query := fmt.Sprintf(`{ "query": "{ CVEListForImage (repo:\"%s\" ) { Tag CVEList { Id Description Severity } } }" }`, imageName)
	result := &CVEListForImageStruct{}
	params := make(map[string]string)
	params["imageName"] = imageName
	if username != "" && password != "" {
		if err := makeGraphQLRequestBasicAuth(serverUrl, query, username, password, params, result); err != nil {
			return CVEListForImageStruct{}, err
		}
	} else {
		if err := makeGraphQLRequestNoAuth(serverUrl, query, params, result); err != nil {
			return CVEListForImageStruct{}, err
		}
	}
	return *result, nil
}

type CVEListForImageStruct struct {
	Data struct {
		CVEListForImage []struct {
			Tag     string `json:"Tag"`
			CVEList []struct {
				ID          string `json:"Id"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
			} `json:"CVEList"`
		} `json:"CVEListForImage"`
	} `json:"data"`
}

func (c CVEListForImageStruct) String() string {
	stringBuilder := &strings.Builder{}
	for _, image := range c.Data.CVEListForImage {
		stringBuilder.WriteString("Tag:" + image.Tag + "\n")
		stringBuilder.WriteString("CVE List:\n")

		table := tablewriter.NewWriter(stringBuilder)
		table.SetHeader([]string{"ID", "Description", "Severity"})
		table.SetRowLine(true)
		for _, cve := range image.CVEList {
			row := []string{cve.ID, cve.Severity, cve.Description}
			table.Append(row)
		}
		table.Render()
		stringBuilder.WriteString("\n")
	}
	return stringBuilder.String()
}

func (service searchService) findImagesByCveId(cveID, serverUrl, username, password string) (ImageListForCVEStruct, error) {
	query := fmt.Sprintf(`{ "query": "{ ImageListForCVE (text:\"%s\" ) { Name Tags } }" }`, cveID)
	result := &ImageListForCVEStruct{}
	params := make(map[string]string)
	params["cveID"] = cveID
	if username != "" && password != "" {
		if err := makeGraphQLRequestBasicAuth(serverUrl, query, username, password, params, result); err != nil {
			return ImageListForCVEStruct{}, err
		}
	} else {
		if err := makeGraphQLRequestNoAuth(serverUrl, query, params, result); err != nil {
			return ImageListForCVEStruct{}, err
		}
	}

	return *result, nil
}

func (c ImageListForCVEStruct) String() string {
	stringBuilder := &strings.Builder{}
	for _, image := range c.Data.ImageListForCVE {
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
	Data struct {
		ImageListForCVE []struct {
			Name string   `json:"Name"`
			Tags []string `json:"Tags"`
		} `json:"ImageListForCVE"`
	} `json:"data"`
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
