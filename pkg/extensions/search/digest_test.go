//go:build search
// +build search

package search_test

import (
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	. "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
)

type ImgResponseForDigest struct {
	ImgListForDigest ImgListForDigest  `json:"data"`
	Errors           []common.ErrorGQL `json:"errors"`
}

//nolint:tagliatelle // graphQL schema
type ImgListForDigest struct {
	PaginatedImagesResultForDigest `json:"ImageListForDigest"`
}

//nolint:tagliatelle // graphQL schema
type ImgInfo struct {
	RepoName     string `json:"RepoName"`
	Tag          string `json:"Tag"`
	ConfigDigest string `json:"ConfigDigest"`
	Digest       string `json:"Digest"`
	Size         string `json:"Size"`
}

type PaginatedImagesResultForDigest struct {
	Results []ImgInfo       `json:"results"`
	Page    common.PageInfo `json:"page"`
}

func TestDigestSearchHTTP(t *testing.T) {
	Convey("Test image search by digest scanning", t, func() {
		rootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)
		ctrlManager := NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// shut down server
		defer ctrlManager.StopServer()

		createdTime1 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		layers1 := [][]byte{
			{3, 2, 2},
		}

		image1 := CreateImageWith().
			LayerBlobs(layers1).
			ImageConfig(ispec.Image{
				Created: &createdTime1,
				History: []ispec.History{
					{
						Created: &createdTime1,
					},
				},
			}).Build()

		const ver001 = "0.0.1"

		err := UploadImage(image1, baseURL, "zot-cve-test", ver001)
		So(err, ShouldBeNil)

		createdTime2 := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)

		image2 := CreateImageWith().
			LayerBlobs([][]byte{{0, 0, 2}}).
			ImageConfig(ispec.Image{
				History: []ispec.History{{Created: &createdTime2}},
				Platform: ispec.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			}).Build()

		manifestDigest := image2.Digest()

		err = UploadImage(image2, baseURL, "zot-test", ver001)
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(image2.Config)
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		// "sha" should match all digests in all images
		query := `{
			ImageListForDigest(id:"sha") {
				Results {
					RepoName Tag 
					Manifests {
						Digest ConfigDigest Size 
						Layers { Digest }
					}
					Size
				}
			}
		}`
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + "?query=" + url.QueryEscape(query),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponseForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Results), ShouldEqual, 2)
		So(responseStruct.ImgListForDigest.Results[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tags":["0.0.1"]}]}}
		// GetTestBlobDigest("zot-test", "manifest").Encoded() should match the manifest of 1 image

		gqlQuery := url.QueryEscape(`{ImageListForDigest(id:"` + manifestDigest.Encoded() + `")
			{Results{RepoName Tag Manifests {Digest ConfigDigest Size Layers { Digest }}}}}`)
		targetURL := baseURL + constants.FullSearchPrefix + `?query=` + gqlQuery

		resp, err = resty.R().Get(targetURL)
		So(string(resp.Body()), ShouldNotBeNil)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Results), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Results[0].RepoName, ShouldEqual, "zot-test")
		So(responseStruct.ImgListForDigest.Results[0].Tag, ShouldEqual, "0.0.1")

		gqlQuery = url.QueryEscape(`{ImageListForDigest(id:"` + configDigest.Encoded() + `")
		{Results{RepoName Tag Manifests {Digest ConfigDigest Size Layers { Digest }}}}}`)

		targetURL = baseURL + constants.FullSearchPrefix + `?query=` + gqlQuery
		resp, err = resty.R().Get(targetURL)

		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Results), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Results[0].RepoName, ShouldEqual, "zot-test")
		So(responseStruct.ImgListForDigest.Results[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-cve-test","Tags":["0.0.1"]}]}}
		// GetTestBlobDigest("zot-cve-test", "layer").Encoded() should match the layer of 1 image
		layerDigest1 := godigest.FromBytes((layers1[0]))
		gqlQuery = url.QueryEscape(`{ImageListForDigest(id:"` + layerDigest1.Encoded() + `")
		{Results{RepoName Tag Manifests {Digest ConfigDigest Size Layers { Digest }}}}}`)
		targetURL = baseURL + constants.FullSearchPrefix + `?query=` + gqlQuery

		resp, err = resty.R().Get(
			targetURL,
		)

		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		var responseStruct2 ImgResponseForDigest

		err = json.Unmarshal(resp.Body(), &responseStruct2)
		So(err, ShouldBeNil)
		So(len(responseStruct2.Errors), ShouldEqual, 0)
		So(len(responseStruct2.ImgListForDigest.Results), ShouldEqual, 1)
		So(responseStruct2.ImgListForDigest.Results[0].RepoName, ShouldEqual, "zot-cve-test")
		So(responseStruct2.ImgListForDigest.Results[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[]}}
		// "1111111" should match 0 images
		query = `
		{
			ImageListForDigest(id:"1111111") {
				Results {				
					RepoName Tag 
					Manifests {
						Digest ConfigDigest Size 
						Layers { Digest }
					}
				}
			}
		}`
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + "?query=" + url.QueryEscape(query),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Results), ShouldEqual, 0)

		// Call should return {"errors": [{....}]", data":null}}
		query = `{
			ImageListForDigest(id:"1111111") {
				Results {
					RepoName Tag343s
				}
			}`
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + "?query=" + url.QueryEscape(query),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 1)
	})
}

func TestDigestSearchHTTPSubPaths(t *testing.T) {
	Convey("Test image search by digest scanning using storage subpaths", t, func() {
		subRootDir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		globalDir := t.TempDir()
		defer os.RemoveAll(globalDir)

		ctlr.Config.Storage.RootDirectory = globalDir

		subPathMap := make(map[string]config.StorageConfig)

		subPathMap["/a"] = config.StorageConfig{RootDirectory: subRootDir}

		ctlr.Config.Storage.SubPaths = subPathMap
		ctrlManager := NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// shut down server
		defer ctrlManager.StopServer()

		image := CreateDefaultImage()

		err := UploadImage(image, baseURL, "a/zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image, baseURL, "a/zot-test", "0.0.1")
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := `{
			ImageListForDigest(id:"sha") {
				Results {
					RepoName Tag 
					Manifests {
						Digest ConfigDigest Size 
						Layers { Digest }
						}
					}
				}
			}`
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + "?query=" + url.QueryEscape(query),
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponseForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Results), ShouldEqual, 2)
	})
}

func TestDigestSearchDisabled(t *testing.T) {
	Convey("Test disabling image search", t, func() {
		var disabled bool
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &disabled}},
		}

		ctlr := api.NewController(conf)
		ctrlManager := NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		// shut down server
		defer ctrlManager.StopServer()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}
