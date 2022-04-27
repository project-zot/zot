// +build extended search

package common_test

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	. "zotregistry.io/zot/pkg/test"
)

// nolint:gochecknoglobals
var (
	rootDir    string
	subRootDir string
)

type ImgResponsWithLatestTag struct {
	ImgListWithLatestTag ImgListWithLatestTag `json:"data"`
	Errors               []ErrorGQL           `json:"errors"`
}

type ExpandedRepoInfoResp struct {
	ExpandedRepoInfo ExpandedRepoInfo `json:"data"`
	Errors           []ErrorGQL       `json:"errors"`
}

type ExpandedRepoInfo struct {
	RepoInfo common.RepoInfo `json:"expandedRepoInfo"`
}

//nolint:tagliatelle // graphQL schema
type ImgListWithLatestTag struct {
	Images []ImageInfo `json:"ImageListWithLatestTag"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type ImageInfo struct {
	Name        string
	Latest      string
	LastUpdated time.Time
	Description string
	Licenses    string
	Vendor      string
	Size        string
	Labels      string
}

func testSetup(t *testing.T) error {
	t.Helper()
	dir := t.TempDir()

	subDir := t.TempDir()

	rootDir = dir

	subRootDir = subDir

	err := CopyFiles("../../../../test/data", rootDir)
	if err != nil {
		return err
	}

	err = CopyFiles("../../../../test/data", subDir)
	if err != nil {
		return err
	}

	return nil
}

func getTags() ([]common.TagInfo, []common.TagInfo) {
	tags := make([]common.TagInfo, 0)

	firstTag := common.TagInfo{
		Name:      "1.0.0",
		Digest:    "sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb",
		Timestamp: time.Now(),
	}
	secondTag := common.TagInfo{
		Name:      "1.0.1",
		Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
		Timestamp: time.Now(),
	}
	thirdTag := common.TagInfo{
		Name:      "1.0.2",
		Digest:    "sha256:eca04f027f414362596f2632746d8a170362170b9ac9af772011fedcc3877ebb",
		Timestamp: time.Now(),
	}
	fourthTag := common.TagInfo{
		Name:      "1.0.3",
		Digest:    "sha256:eca04f027f414362596f2632746d8a171362170b9ac9af772011fedcc3877ebb",
		Timestamp: time.Now(),
	}

	tags = append(tags, firstTag, secondTag, thirdTag, fourthTag)

	infectedTags := make([]common.TagInfo, 0)
	infectedTags = append(infectedTags, secondTag)

	return tags, infectedTags
}

func TestImageFormat(t *testing.T) {
	Convey("Test valid image", t, func() {
		log := log.NewLogger("debug", "")
		dbDir := "../../../../test/data"

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := storage.NewImageStore(dbDir, false, storage.DefaultGCDelay, false, false, log, metrics)
		storeController := storage.StoreController{DefaultStore: defaultStore}
		olu := common.NewOciLayoutUtils(storeController, log)

		isValidImage, err := olu.IsValidImageFormat("zot-test")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = olu.IsValidImageFormat("zot-test:0.0.1")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, true)

		isValidImage, err = olu.IsValidImageFormat("zot-test:0.0.")
		So(err, ShouldBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-noindex-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot--tet")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-noindex-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-squashfs-noblobs")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-squashfs-invalid-index")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-squashfs-invalid-blob")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-squashfs-test:0.3.22-squashfs")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)

		isValidImage, err = olu.IsValidImageFormat("zot-nonreadable-test")
		So(err, ShouldNotBeNil)
		So(isValidImage, ShouldEqual, false)
	})
}

func TestLatestTagSearchHTTP(t *testing.T) {
	Convey("Test latest image search by timestamp", t, func() {
		err := testSetup(t)
		if err != nil {
			panic(err)
		}
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths["/a"] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// shut down server
		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + "/query")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct ImgResponsWithLatestTag
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImgListWithLatestTag.Images), ShouldEqual, 4)

		images := responseStruct.ImgListWithLatestTag.Images
		So(images[0].Latest, ShouldEqual, "0.0.1")

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod(rootDir, 0o000)
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImgListWithLatestTag.Images), ShouldEqual, 0)

		err = os.Chmod(rootDir, 0o755)
		if err != nil {
			panic(err)
		}

		// Delete config blob and try.
		err = os.Remove(path.Join(subRootDir, "zot-test/blobs/sha256",
			"adf3bb6cc81f8bd6a9d5233be5f0c1a4f1e3ed1cf5bbdfad7708cc8d4099b741"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(subRootDir, "zot-test/blobs/sha256",
			"2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256",
			"adf3bb6cc81f8bd6a9d5233be5f0c1a4f1e3ed1cf5bbdfad7708cc8d4099b741"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Delete manifest blob also and try
		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256",
			"2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + "/query?query={ImageListWithLatestTag(){Name%20Latest}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestExpandedRepoInfo(t *testing.T) {
	Convey("Test expanded repo info", t, func() {
		err := testSetup(t)
		if err != nil {
			panic(err)
		}
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths["/a"] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		// shut down server
		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + "/query")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		query := "{ExpandedRepoInfo(repo:\"zot-test\"){Manifests%20{Digest%20IsSigned%20Tag%20Layers%20{Size%20Digest}}}}"

		resp, err = resty.R().Get(baseURL + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Manifests), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Manifests[0].Layers), ShouldNotEqual, 0)

		query = "{ExpandedRepoInfo(repo:\"\"){Manifests%20{Digest%20Tag%20IsSigned%20Layers%20{Size%20Digest}}}}"

		resp, err = resty.R().Get(baseURL + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		query = "{ExpandedRepoInfo(repo:\"a/zot-test\"){Manifests%20{Digest%20Tag%20IsSigned%20%Layers%20{Size%20Digest}}}}"
		resp, err = resty.R().Get(baseURL + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Manifests), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Manifests[0].Layers), ShouldNotEqual, 0)

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256",
			"2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396"))
		if err != nil {
			panic(err)
		}

		query = "{ExpandedRepoInfo(repo:\"zot-test\"){Manifests%20{Digest%20Tag%20IsSigned%20%Layers%20{Size%20Digest}}}}"

		resp, err = resty.R().Get(baseURL + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
	})
}

func TestUtilsMethod(t *testing.T) {
	Convey("Test utils", t, func() {
		// Test GetRepo method
		repo := common.GetRepo("test")
		So(repo, ShouldEqual, "test")

		repo = common.GetRepo(":")
		So(repo, ShouldEqual, "")

		repo = common.GetRepo("")
		So(repo, ShouldEqual, "")

		repo = common.GetRepo("test:123")
		So(repo, ShouldEqual, "test")

		repo = common.GetRepo("a/test:123")
		So(repo, ShouldEqual, "a/test")

		repo = common.GetRepo("a/test:123:456")
		So(repo, ShouldEqual, "a/test")

		// Test various labels
		labels := make(map[string]string)

		desc := common.GetDescription(labels)
		So(desc, ShouldEqual, "")

		license := common.GetLicense(labels)
		So(license, ShouldEqual, "")

		vendor := common.GetVendor(labels)
		So(vendor, ShouldEqual, "")

		categories := common.GetCategories(labels)
		So(categories, ShouldEqual, "")

		labels[ispec.AnnotationVendor] = "zot"
		labels[ispec.AnnotationDescription] = "zot-desc"
		labels[ispec.AnnotationLicenses] = "zot-license"
		labels[common.AnnotationLabels] = "zot-labels"

		desc = common.GetDescription(labels)
		So(desc, ShouldEqual, "zot-desc")

		license = common.GetLicense(labels)
		So(license, ShouldEqual, "zot-license")

		vendor = common.GetVendor(labels)
		So(vendor, ShouldEqual, "zot")

		categories = common.GetCategories(labels)
		So(categories, ShouldEqual, "zot-labels")

		labels = make(map[string]string)

		// Use diff key
		labels[common.LabelAnnotationVendor] = "zot-vendor"
		labels[common.LabelAnnotationDescription] = "zot-label-desc"
		labels[common.LabelAnnotationLicenses] = "zot-label-license"

		desc = common.GetDescription(labels)
		So(desc, ShouldEqual, "zot-label-desc")

		license = common.GetLicense(labels)
		So(license, ShouldEqual, "zot-label-license")

		vendor = common.GetVendor(labels)
		So(vendor, ShouldEqual, "zot-vendor")

		routePrefix := common.GetRoutePrefix("test:latest")
		So(routePrefix, ShouldEqual, "/")

		routePrefix = common.GetRoutePrefix("a/test:latest")
		So(routePrefix, ShouldEqual, "/a")

		routePrefix = common.GetRoutePrefix("a/b/test:latest")
		So(routePrefix, ShouldEqual, "/a")

		allTags, infectedTags := getTags()

		latestTag := common.GetLatestTag(allTags)
		So(latestTag.Name, ShouldEqual, "1.0.3")

		fixedTags := common.GetFixedTags(allTags, infectedTags)
		So(len(fixedTags), ShouldEqual, 2)

		log := log.NewLogger("debug", "")

		rootDir := t.TempDir()

		subRootDir := t.TempDir()

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := storage.NewImageStore(rootDir, false, storage.DefaultGCDelay, false, false, log, metrics)

		subStore := storage.NewImageStore(subRootDir, false, storage.DefaultGCDelay, false, false, log, metrics)

		subStoreMap := make(map[string]storage.ImageStore)

		subStoreMap["/b"] = subStore

		storeController := storage.StoreController{DefaultStore: defaultStore, SubStore: subStoreMap}

		dir := common.GetRootDir("a/zot-cve-test", storeController)

		So(dir, ShouldEqual, rootDir)

		dir = common.GetRootDir("b/zot-cve-test", storeController)

		So(dir, ShouldEqual, subRootDir)
	})
}
