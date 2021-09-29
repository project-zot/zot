// nolint: gochecknoinits
package digestinfo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/storage"
	storageDriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
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
	Name         string `json:"Name"`
	Tag          string `json:"Tag"`
	ConfigDigest string `json:"ConfigDigest"`
	Digest       string `json:"Digest"`
	Size         string `json:"Size"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

var testCases = []struct {
	testCaseName    string
	storageType     string
	setupSuccess    bool
	controller      *api.Controller
	storeController storage.StoreController
}{
	{
		testCaseName: "FileSystemAPIs",
		storageType:  "fs",
		setupSuccess: false,
	},
	{
		testCaseName: "S3APIs",
		storageType:  "s3",
		setupSuccess: false,
	},
}

// used as a reference to the s3 bucket for later cleanup
var s3StorageDriver storageDriver.StorageDriver

func init() {
	err := testFileSystemSetup()
	if err != nil {
		panic(err)
	}

	err = testS3Setup()
	if err != nil {
		panic(err)
	}

	logger := log.NewLogger("debug", "")
	digestInfo = digestinfo.NewDigestInfo(logger)
}

func testFileSystemSetup() error {
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

	err = copyFileSystemFiles("../../../../test/data", rootDir)
	if err != nil {
		return err
	}

	logger := log.NewLogger("debug", "")

	imageStore := storage.NewImageStoreFS(rootDir, false, false, logger)
	fileSystemStoreController := storage.StoreController{DefaultStore: imageStore}

	testCases[0].storeController = fileSystemStoreController

	// create controller for TestDigestSearchHTTP
	config := api.NewConfig()
	config.HTTP.Port = Port1
	config.Storage.RootDirectory = rootDir
	config.Extensions = &ext.ExtensionConfig{
		Search: &ext.SearchConfig{Enable: true},
	}

	testCases[0].controller = api.NewController(config)

	testCases[0].setupSuccess = true

	return nil
}

func testS3Setup() error {

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		return nil
	}

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	bucket := "zot-digest-test"
	endpoint := os.Getenv("S3MOCK_ENDPOINT")
	objectsStoreParams := map[string]interface{}{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         "us-east-2",
		"bucket":         bucket,
		"regionendpoint": endpoint,
		"secure":         false,
		"skipverify":     false,
	}

	s3StoreController := createObjectsStore(testDir, objectsStoreParams)

	err = s3StoreController.DefaultStore.InitRepo("zot-cve-test")
	if err != nil {
		return err
	}
	err = copyS3Files("zot-cve-test", "../../../../test/data/zot-cve-test", s3StoreController.DefaultStore)
	if err != nil {
		return err
	}

	err = s3StoreController.DefaultStore.InitRepo("zot-test")
	if err != nil {
		return err
	}
	err = copyS3Files("zot-test", "../../../../test/data/zot-test", s3StoreController.DefaultStore)
	if err != nil {
		return err
	}

	testCases[1].storeController = s3StoreController

	// create controller for TestDigestSearchHTTP
	config := api.NewConfig()
	config.HTTP.Port = Port1
	config.Storage.RootDirectory = testDir
	config.Storage.ObjectStoreParams = objectsStoreParams
	config.Extensions = &ext.ExtensionConfig{
		Search: &ext.SearchConfig{Enable: true},
	}

	testCases[1].controller = api.NewController(config)

	testCases[1].setupSuccess = true

	return nil
}

func createObjectsStore(rootDir string, objectsStoreParams map[string]interface{}) storage.StoreController {
	// create bucket if it doesn't exists
	_, err := resty.R().Put(
		"http://" +
			fmt.Sprintf("%v", objectsStoreParams["regionendpoint"]) +
			"/" +
			fmt.Sprintf("%v", objectsStoreParams["bucket"]),
	)
	if err != nil {
		panic(err)
	}

	// get a reference to the s3 bucket for cleanup after tests
	s3StorageDriver, _ = factory.Create("s3", objectsStoreParams)

	imageStore := storage.NewObjectStorage(rootDir, false, false, log.Logger{Logger: zerolog.New(os.Stdout)}, s3StorageDriver)
	s3StoreController := storage.StoreController{DefaultStore: imageStore}

	return s3StoreController
}

func cleanupStorage(store storageDriver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func copyFileSystemFiles(sourceDir string, destDir string) error {
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
			if err = copyFileSystemFiles(sourceFilePath, destFilePath); err != nil {
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

func copyS3Files(repo string, sourceDir string, imageStore storage.ImageStore) error {
	// copy blobs
	err := filepath.Walk(path.Join(sourceDir, "/blobs/sha256"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			blobReader, err := os.Open(path)
			if err != nil {
				return err
			}

			_, _, err = imageStore.FullBlobUpload(repo, blobReader, fmt.Sprintf("sha256:%s", info.Name()))
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	// copy manifests for each tag
	// read index.json to get the manifest list
	buf, err := ioutil.ReadFile(path.Join(sourceDir, "index.json"))
	if err != nil {
		return errors.ErrBadIndex
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		return errors.ErrBadIndex
	}

	for _, manifest := range index.Manifests {

		blobReader, err := os.Open(path.Join(sourceDir, fmt.Sprintf("/blobs/sha256/%s", manifest.Digest.Hex())))
		if err != nil {
			return err
		}

		buf := new(bytes.Buffer)

		_, err = buf.ReadFrom(blobReader)
		if err != nil {
			return err
		}

		_, err = imageStore.PutImageManifest(repo, manifest.Annotations[ispec.AnnotationRefName], ispec.MediaTypeImageManifest, buf.Bytes())
		if err != nil {
			return err
		}
	}

	return err
}

func TestDigestInfo(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		if testcase.setupSuccess == false {
			t.Skip(fmt.Sprintf("Skipping testing %s", testcase.testCaseName))
		}

		t.Run(testcase.testCaseName, func(t *testing.T) {
			Convey("Test image tag", t, func() {
				// Search by manifest digest
				imageInfoByDigest, err := digestInfo.GetRepoInfoByDigest(testcase.storeController, "zot-cve-test", "63a795ca")
				So(err, ShouldBeNil)
				So(len(imageInfoByDigest), ShouldEqual, 1)
				So(imageInfoByDigest[0].TagName, ShouldEqual, "0.0.1")

				// Search by config digest
				imageInfoByDigest, err = digestInfo.GetRepoInfoByDigest(testcase.storeController, "zot-test", "adf3bb6c")
				So(err, ShouldBeNil)
				So(len(imageInfoByDigest), ShouldEqual, 1)
				So(imageInfoByDigest[0].TagName, ShouldEqual, "0.0.1")

				// Search by layer digest
				imageInfoByDigest, err = digestInfo.GetRepoInfoByDigest(testcase.storeController, "zot-cve-test", "7a0437f0")
				So(err, ShouldBeNil)
				So(len(imageInfoByDigest), ShouldEqual, 1)
				So(imageInfoByDigest[0].TagName, ShouldEqual, "0.0.1")

				// Search by non-existent image
				imageInfoByDigest, err = digestInfo.GetRepoInfoByDigest(testcase.storeController, "zot-tes", "63a795ca")
				So(err, ShouldNotBeNil)
				So(len(imageInfoByDigest), ShouldEqual, 0)

				// Search by non-existent digest
				imageInfoByDigest, err = digestInfo.GetRepoInfoByDigest(testcase.storeController, "zot-test", "111")
				So(err, ShouldBeNil)
				So(len(imageInfoByDigest), ShouldEqual, 0)
			})
		})
	}
}

func TestDigestSearchHTTP(t *testing.T) {
	defer cleanupStorage(s3StorageDriver, "/oci-repo-test")
	for _, testcase := range testCases {
		testcase := testcase
		if testcase.setupSuccess == false {
			t.Skip(fmt.Sprintf("Skipping testing %s", testcase.testCaseName))
		}

		t.Run(testcase.testCaseName, func(t *testing.T) {
			Convey("Test image search by digest scanning", t, func() {
				go func() {
					// this blocks
					if err := testcase.controller.Run(); err != nil {
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
					_ = testcase.controller.Server.Shutdown(ctx)
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
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"sha\"){Name%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				var responseStruct ImgResponseForDigest
				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 0)
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 2)
				So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

				// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tag":"0.0.1"}]}}
				// "2bacca16" should match the manifest of 1 image
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"2bacca16\"){Name%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 0)
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-test")
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

				// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-test","Tag":"0.0.1"}]}}
				// "adf3bb6c" should match the config of 1 image
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"adf3bb6c\"){Name%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 0)
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-test")
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

				// Call should return {"data":{"ImageListForDigest":[{"Name":"zot-cve-test","Tag":"0.0.1"}]}}
				// "7a0437f0" should match the layer of 1 image
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"7a0437f0\"){Name%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 0)
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Name, ShouldEqual, "zot-cve-test")
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 1)
				So(responseStruct.ImgListForDigest.Images[0].Tag, ShouldEqual, "0.0.1")

				// Call should return {"data":{"ImageListForDigest":[]}}
				// "1111111" should match 0 images
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"1111111\"){Name%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 0)
				So(len(responseStruct.ImgListForDigest.Images), ShouldEqual, 0)

				// Call should return {"errors": [{....}]", data":null}}
				resp, err = resty.R().Get(BaseURL1 + "/query?query={ImageListForDigest(digest:\"1111111\"){UnknownField%20Tag%20Digest%20ConfigDigest%20Size%20Layers%20{%20Digest}}}")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 422)

				err = json.Unmarshal(resp.Body(), &responseStruct)
				So(err, ShouldBeNil)
				So(len(responseStruct.Errors), ShouldEqual, 1)
			})
		})
	}
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
