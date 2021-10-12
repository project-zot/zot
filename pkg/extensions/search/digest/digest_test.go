// +build extended

// nolint: gochecknoinits
package digestinfo_test

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	ext "github.com/anuvu/zot/pkg/extensions"
	digestinfo "github.com/anuvu/zot/pkg/extensions/search/digest"
	"github.com/anuvu/zot/pkg/log"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

// nolint:gochecknoglobals
var (
	digestInfo *digestinfo.DigestInfo
	rootDir    string
)

const (
	BaseURL1 = "http://127.0.0.1:8085"
	Port1    = "8085"
)

type ImgResponseForDigest struct {
	ImgListForDigest ImgListForDigest `json:"data"`
	Errors           []ErrorGQL       `json:"errors"`
}

type ImgListForDigest struct {
	Images []ImgInfo `json:"ImageListForDigest"`
}

type ImgInfo struct {
	Name string   `json:"Name"`
	Tags []string `json:"Tags"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

func init() {
	err := testSetup()
	if err != nil {
		panic(err)
	}
}

func testSetup() error {
	dir, err := ioutil.TempDir("", "digest_test")
	if err != nil {
		return err
	}

	rootDir = dir

	// Test images used/copied:
	// IMAGE NAME    TAG                       DIGEST    CONFIG    LAYERS    SIZE
	// zot-test      0.0.1                     2bacca16  adf3bb6c            76MB
	//                                                             2d473b07  76MB
	// zot-cve-test  0.0.1                     63a795ca  8dd57e17            75MB
	//                                                             7a0437f0  75MB

	err = copyFiles("../../../../test/data", rootDir)
	if err != nil {
		return err
	}

	log := log.NewLogger("debug", "")

	digestInfo = digestinfo.NewDigestInfo(log)

	return nil
}

func copyFiles(sourceDir string, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	files, err := ioutil.ReadDir(sourceDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if err = copyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return err
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return err
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return err
			}
		}
	}

	return nil
}

func TestDigestInfo(t *testing.T) {
	Convey("Test image tag", t, func() {
		// Search by manifest digest
		imageTags, err := digestInfo.GetImageTagsByDigest(path.Join(rootDir, "zot-cve-test"), "63a795ca")
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(*imageTags[0], ShouldEqual, "0.0.1")

		// Search by config digest
		imageTags, err = digestInfo.GetImageTagsByDigest(path.Join(rootDir, "zot-test"), "adf3bb6c")
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(*imageTags[0], ShouldEqual, "0.0.1")

		// Search by layer digest
		imageTags, err = digestInfo.GetImageTagsByDigest(path.Join(rootDir, "zot-cve-test"), "7a0437f0")
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 1)
		So(*imageTags[0], ShouldEqual, "0.0.1")

		// Search by non-existent image
		imageTags, err = digestInfo.GetImageTagsByDigest(path.Join(rootDir, "zot-tes"), "63a795ca")
		So(err, ShouldNotBeNil)
		So(len(imageTags), ShouldEqual, 0)

		// Search by non-existent digest
		imageTags, err = digestInfo.GetImageTagsByDigest(path.Join(rootDir, "zot-test"), "111")
		So(err, ShouldBeNil)
		So(len(imageTags), ShouldEqual, 0)
	})
}

func TestDigestSearchHTTP(t *testing.T) {
	Convey("Test image search by digest scanning", t, func() {
		config := api.NewConfig()
		config.HTTP.Port = Port1
		config.Storage.RootDirectory = rootDir
		config.Extensions = &ext.ExtensionConfig{
			Search: &ext.SearchConfig{Enable: true},
		}

		c := api.NewController(config)

		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// shut down server
		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(BaseURL1 + "/query")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// "sha" should match all digests in all images
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"sha\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponseForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 2)
		So(len(responseStruct.ImgListForDigest.Images[0].Tags), ShouldEqual, 1)
		So(len(responseStruct.ImgListForDigest.Images[0].Tags), ShouldEqual, 1)

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tags":["0.0.1"]}]}}
		// "2bacca16" should match the manifest of 1 image
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"2bacca16\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-test")
		So(len(responseStruct.ImgListForDigest.Images[0].Tags), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Tags[0], ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tags":["0.0.1"]}]}}
		// "adf3bb6c" should match the config of 1 image
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"adf3bb6c\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-test")
		So(len(responseStruct.ImgListForDigest.Images[0].Tags), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Tags[0], ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-cve-test","Tags":["0.0.1"]}]}}
		// "7a0437f0" should match the layer of 1 image
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"7a0437f0\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-cve-test")
		So(len(responseStruct.ImgListForDigest.Images[0].Tags), ShouldEqual, 1)
		So(responseStruct.ImgListForDigest.Images[0].Tags[0], ShouldEqual, "0.0.1")

		// Call should return {"data":{"ImageListForDigest":[]}}
		// "1111111" should match 0 images
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"1111111\"){Name%20Tags}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 0)
		So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 0)

		// Call should return {"errors": [{....}]", data":null}}
		resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(id:\"1111111\"){Name%20Tag343s}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Errors), ShouldEqual, 1)
	})
}

func TestDigestSearchDisabled(t *testing.T) {
	Convey("Test disabling image search", t, func() {
		dir, err := ioutil.TempDir("", "digest_test")
		So(err, ShouldBeNil)
		config := api.NewConfig()
		config.HTTP.Port = Port1
		config.Storage.RootDirectory = dir
		config.Extensions = &ext.ExtensionConfig{
			Search: &ext.SearchConfig{Enable: false},
		}

		c := api.NewController(config)

		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// shut down server
		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(BaseURL1 + "/query")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)
	})
}
