//go:build search
// +build search

//nolint:gochecknoinits
package digestinfo_test

import (
	"encoding/json"
	"net/url"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	digestinfo "zotregistry.io/zot/pkg/extensions/search/digest"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test"
)

type ImgResponseForDigest struct {
	ImgListForDigest ImgListForDigest `json:"data"`
	Errors           []ErrorGQL       `json:"errors"`
}

//nolint:tagliatelle // graphQL schema
type ImgListForDigest struct {
	Images []ImgInfo `json:"ImageListForDigest"`
}

//nolint:tagliatelle // graphQL schema
type ImgInfo struct {
	RepoName     string `json:"RepoName"`
	Tag          string `json:"Tag"`
	ConfigDigest string `json:"ConfigDigest"`
	Digest       string `json:"Digest"`
	Size         string `json:"Size"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

func testSetup(t *testing.T) (string, string, *digestinfo.DigestInfo) {
	t.Helper()
	dir := t.TempDir()
	subDir := t.TempDir()

	rootDir := dir

	subRootDir := subDir

	// Test images used/copied:
	// IMAGE NAME    TAG                       DIGEST    CONFIG    LAYERS    SIZE
	// zot-test      0.0.1                     2bacca16  adf3bb6c            76MB
	//                                                             2d473b07  76MB
	// zot-cve-test  0.0.1                     63a795ca  8dd57e17            75MB
	//                                                             7a0437f0  75MB

	err := os.Mkdir(subDir+"/a", 0o700)
	if err != nil {
		panic(err)
	}

	CopyTestFiles("../../../../test/data", rootDir)

	CopyTestFiles("../../../../test/data", subDir+"/a/")

	log := log.NewLogger("debug", "")
	metrics := monitoring.NewMetricsServer(false, log)
	storeController := storage.StoreController{
		DefaultStore: local.NewImageStore(rootDir, false, storage.DefaultGCDelay, false, false, log, metrics, nil, nil),
	}

	digestInfo := digestinfo.NewDigestInfo(storeController, log)

	return rootDir, subRootDir, digestInfo
}

func TestDigestInfo(t *testing.T) {
	Convey("Test image tag", t, func() {
		_, _, digestInfo := testSetup(t)

		// Search by manifest digest
		imageTags, err := digestInfo.GetImageTagsByDigest("zot-cve-test",
			GetTestBlobDigest("zot-cve-test", "manifest").Encoded())
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(imageTags[0].Tag, ShouldEqual, "0.0.1")

		// Search by config digest
		imageTags, err = digestInfo.GetImageTagsByDigest("zot-test", GetTestBlobDigest("zot-test", "config").Encoded())
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(imageTags[0].Tag, ShouldEqual, "0.0.1")

		// Search by layer digest
		imageTags, err = digestInfo.GetImageTagsByDigest("zot-cve-test", GetTestBlobDigest("zot-cve-test", "layer").Encoded())
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(imageTags[0].Tag, ShouldEqual, "0.0.1")

		// Search by non-existent image
		imageTags, err = digestInfo.GetImageTagsByDigest("zot-tes", GetTestBlobDigest("zot-test", "manifest").Encoded())
		So(err, ShouldNotBeNil)
		So(len(imageTags), ShouldEqual, 0)

		// Search by non-existent digest
		imageTags, err = digestInfo.GetImageTagsByDigest("zot-test", "111")
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 0)
	})
}

func TestDigestSearchHTTP(t *testing.T) {
	Convey("Test image search by digest scanning", t, func() {
		rootDir, _, _ := testSetup(t)

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

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		// "sha" should match all digests in all images
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + `?query={ImageListForDigest(id:"sha")` +
				`{RepoName%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}`,
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponseForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 2)
		So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tags":["0.0.1"]}]}}
		// GetTestBlobDigest("zot-test", "manifest").Encoded() should match the manifest of 1 image

		gqlQuery := url.QueryEscape(`{ImageListForDigest(id:"` + GetTestBlobDigest("zot-test", "manifest").Encoded() + `")
			{RepoName Tag Digest ConfigDigest Size Layers { Digest }}}`)
		targetURL := baseURL + constants.FullSearchPrefix + `?query=` + gqlQuery

		resp, err = resty.R().Get(targetURL)
		So(string(resp.Body()), ShouldNotBeNil)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].RepoName, ShouldEqual, "zot-test")
		So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

		// GetTestBlobDigest("zot-test", "config").Encoded() should match the config of 1 image.
		gqlQuery = url.QueryEscape(`{ImageListForDigest(id:"` + GetTestBlobDigest("zot-test", "config").Encoded() + `")
			{RepoName Tag Digest ConfigDigest Size Layers { Digest }}}`)

		targetURL = baseURL + constants.FullSearchPrefix + `?query=` + gqlQuery
		resp, err = resty.R().Get(targetURL)

		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].RepoName, ShouldEqual, "zot-test")
		So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-cve-test","Tags":["0.0.1"]}]}}
		// GetTestBlobDigest("zot-cve-test", "layer").Encoded() should match the layer of 1 image
		gqlQuery = url.QueryEscape(`{ImageListForDigest(id:"` + GetTestBlobDigest("zot-cve-test", "layer").Encoded() + `")
			{RepoName Tag Digest ConfigDigest Size Layers { Digest }}}`)
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
		So(len(responseStruct2.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct2.ImgListForDigest.Images[0].RepoName, ShouldEqual, "zot-cve-test")
		So(responseStruct2.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[]}}
		// "1111111" should match 0 images
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + `?query={ImageListForDigest(id:"1111111")` +
				`{RepoName%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}`,
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 0)

		// Call should return {"errors": [{....}]", data":null}}
		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + `?query={ImageListForDigest(id:"1111111")` +
				`{RepoName%20Tag343s}}`,
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
		_, subRootDir, _ := testSetup(t)

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

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, err = resty.R().Get(
			baseURL + constants.FullSearchPrefix + `?query={ImageListForDigest(id:"sha")` +
				`{RepoName%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}`,
		)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponseForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 2)
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
