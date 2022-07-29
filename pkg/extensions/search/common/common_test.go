//go:build search
// +build search

package common_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/glob"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	graphqlQueryPrefix = constants.ExtSearchPrefix
	DBFileName         = "repo.db"
)

var (
	ErrTestError   = errors.New("test error")
	ErrPutManifest = errors.New("can't put manifest")
)

// nolint:gochecknoglobals
var (
	rootDir    string
	subRootDir string
)

type RepoWithNewestImageResponse struct {
	RepoListWithNewestImage RepoListWithNewestImage `json:"data"`
	Errors                  []ErrorGQL              `json:"errors"`
}

type ExpandedRepoInfoResp struct {
	ExpandedRepoInfo ExpandedRepoInfo `json:"data"`
	Errors           []ErrorGQL       `json:"errors"`
}

type GlobalSearchResultResp struct {
	GlobalSearchResult GlobalSearchResult `json:"data"`
	Errors             []ErrorGQL         `json:"errors"`
}

type GlobalSearchResult struct {
	GlobalSearch GlobalSearch `json:"globalSearch"`
}
type GlobalSearch struct {
	Images []ImageSummary `json:"images"`
	Repos  []RepoSummary  `json:"repos"`
	Layers []LayerSummary `json:"layers"`
}

type ImageSummary struct {
	RepoName      string    `json:"repoName"`
	Tag           string    `json:"tag"`
	LastUpdated   time.Time `json:"lastUpdated"`
	Size          string    `json:"size"`
	Platform      OsArch    `json:"platform"`
	Vendor        string    `json:"vendor"`
	Score         int       `json:"score"`
	IsSigned      bool      `json:"isSigned"`
	DownloadCount int       `json:"downloadCount"`
}

type RepoSummary struct {
	Name        string       `json:"name"`
	LastUpdated time.Time    `json:"lastUpdated"`
	Size        string       `json:"size"`
	Platforms   []OsArch     `json:"platforms"`
	Vendors     []string     `json:"vendors"`
	Score       int          `json:"score"`
	NewestImage ImageSummary `json:"newestImage"`
}

type LayerSummary struct {
	Size   string `json:"size"`
	Digest string `json:"digest"`
	Score  int    `json:"score"`
}

type OsArch struct {
	Os   string `json:"os"`
	Arch string `json:"arch"`
}

type ExpandedRepoInfo struct {
	RepoInfo common.RepoInfo `json:"expandedRepoInfo"`
}

//nolint:tagliatelle // graphQL schema
type RepoListWithNewestImage struct {
	Repos []RepoSummary `json:"RepoListWithNewestImage"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type ImageInfo struct {
	RepoName    string
	Tag         string
	LastUpdated time.Time
	Description string
	Licenses    string
	Vendor      string
	Size        string
	Labels      string
}

func testSetup(t *testing.T, subpath string) error {
	t.Helper()
	dir := t.TempDir()

	subDir := t.TempDir()

	rootDir = dir

	subRootDir = path.Join(subDir, subpath)

	err := CopyFiles("../../../../test/data", rootDir)
	if err != nil {
		return err
	}

	return CopyFiles("../../../../test/data", subRootDir)
}

// triggerUploadForTestImages is paired with testSetup and is supposed to trigger events when pushing an image
// by pushing just the manifest.
func triggerUploadForTestImages(port, baseURL string) error {
	log := log.NewLogger("debug", "")
	metrics := monitoring.NewMetricsServer(false, log)
	storage := storage.NewImageStore("../../../../test/data", false, storage.DefaultGCDelay,
		false, false, log, metrics, nil)

	repos, err := storage.GetRepositories()
	if err != nil {
		return err
	}

	for _, repo := range repos {
		indexBlob, err := storage.GetIndexContent(repo)
		if err != nil {
			return err
		}

		var indexJSON ispec.Index

		err = json.Unmarshal(indexBlob, &indexJSON)
		if err != nil {
			return err
		}

		for _, manifest := range indexJSON.Manifests {
			tag := manifest.Annotations[ispec.AnnotationRefName]

			manifestBlob, _, _, err := storage.GetImageManifest(repo, tag)
			if err != nil {
				return err
			}

			_, err = resty.R().
				SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(manifestBlob).
				Put(baseURL + "/v2/" + repo + "/manifests/" + tag)
			if err != nil {
				return err
			}
		}
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

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := storage.NewImageStore(dbDir, false, storage.DefaultGCDelay,
			false, false, log, metrics, nil)
		storeController := storage.StoreController{DefaultStore: defaultStore}
		olu := common.NewBaseOciLayoutUtils(storeController, log)

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

func TestRepoListWithNewestImage(t *testing.T) {
	Convey("Test repoListWithNewestImage AddError", t, func() {
		subpath := "/a"
		err := testSetup(t, subpath)
		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(path.Join(rootDir, "zot-cve-test"))
		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(path.Join(rootDir, subpath))
		if err != nil {
			panic(err)
		}

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(rootDir,
			"zot-test/blobs/sha256/2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		errmsg := fmt.Sprint(zerr.ErrBlobNotFound)
		body := string(resp.Body())
		So(body, ShouldContainSubstring, errmsg)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = CopyFiles("../../../../test/data/zot-test", path.Join(rootDir, "zot-test"))
		if err != nil {
			panic(err)
		}

		err = os.Remove(path.Join(rootDir,
			"zot-test/blobs/sha256/adf3bb6cc81f8bd6a9d5233be5f0c1a4f1e3ed1cf5bbdfad7708cc8d4099b741"))
		if err != nil {
			panic(err)
		}

		err = os.Remove(path.Join(rootDir,
			"zot-test/blobs/sha256/2d473b07cdd5f0912cd6f1a703352c82b512407db6b05b43f2553732b55df3bc"))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		errmsg = fmt.Sprint(zerr.ErrBlobNotFound)
		body = string(resp.Body())
		So(body, ShouldContainSubstring, errmsg)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = CopyFiles("../../../../test/data/zot-test", path.Join(rootDir, "zot-test"))
		if err != nil {
			panic(err)
		}

		err = os.Remove(path.Join(rootDir, "zot-test/index.json"))
		if err != nil {
			panic(err)
		}
		//nolint: lll
		manifestNoAnnotations := "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396\",\"size\":350}]}"
		err = os.WriteFile(path.Join(rootDir, "zot-test/index.json"), []byte(manifestNoAnnotations), 0o600)
		if err != nil {
			panic(err)
		}
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		body = string(resp.Body())
		So(body, ShouldContainSubstring, "reference not found for this manifest")
		So(resp.StatusCode(), ShouldEqual, 200)
	})

	Convey("Test repoListWithNewestImage by tag with HTTP", t, func() {
		subpath := "/a"
		err := testSetup(t, subpath)
		if err != nil {
			panic(err)
		}
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		err = triggerUploadForTestImages(port, GetBaseURL(port))
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct RepoWithNewestImageResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.RepoListWithNewestImage.Repos), ShouldEqual, 4)

		images := responseStruct.RepoListWithNewestImage.Repos
		So(images[0].NewestImage.Tag, ShouldEqual, "0.0.1")

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod(rootDir, 0o000)
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.Errors, ShouldNotBeNil)

		err = os.Chmod(rootDir, 0o755)
		if err != nil {
			panic(err)
		}

		var manifestDigest digest.Digest
		var configDigest digest.Digest
		manifestDigest, configDigest, _ = GetOciLayoutDigests("../../../../test/data/zot-test")

		// Delete config blob and try.
		err = os.Remove(path.Join(subRootDir, "zot-test/blobs/sha256", configDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(subRootDir, "zot-test/blobs/sha256",
			manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", configDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// Delete manifest blob also and try
		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestExpandedRepoInfo(t *testing.T) {
	Convey("Filter out manifests with no tag", t, func() {
		tagToBeRemoved := "3.0"
		repo1 := "test1"
		tempDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		config, layers, manifest, err := GetImageComponents(1000)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "1.0",
			},
			baseURL,
			repo1)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "2.0",
			},
			baseURL,
			repo1)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      tagToBeRemoved,
			},
			baseURL,
			repo1)
		So(err, ShouldBeNil)

		indexPath := path.Join(tempDir, repo1, "index.json")
		indexFile, err := os.Open(indexPath)
		So(err, ShouldBeNil)
		buf, err := io.ReadAll(indexFile)
		So(err, ShouldBeNil)

		var index ispec.Index
		if err = json.Unmarshal(buf, &index); err == nil {
			for _, manifest := range index.Manifests {
				if val, ok := manifest.Annotations[ispec.AnnotationRefName]; ok && val == tagToBeRemoved {
					delete(manifest.Annotations, ispec.AnnotationRefName)

					break
				}
			}
		}
		buf, err = json.Marshal(index)
		So(err, ShouldBeNil)

		err = os.WriteFile(indexPath, buf, 0o600)
		So(err, ShouldBeNil)

		query := "{ExpandedRepoInfo(repo:\"test1\"){Summary%20{Name%20LastUpdated%20Size%20Platforms%20{Os%20Arch}%20Vendors%20Score}%20Images%20{Digest%20IsSigned%20Tag%20Layers%20{Size%20Digest}}}}" // nolint: lll

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.ExpandedRepoInfo.RepoInfo.Summary, ShouldNotBeEmpty)
		So(responseStruct.ExpandedRepoInfo.RepoInfo.Summary.Name, ShouldEqual, "test1")
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldEqual, 2)
	})

	Convey("Test expanded repo info", t, func() {
		subpath := "/a"
		err := testSetup(t, subpath)
		if err != nil {
			panic(err)
		}
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = rootDir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
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

		err = triggerUploadForTestImages(port, GetBaseURL(port))
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		testStorage := storage.NewImageStore("../../../../test/data", false, storage.DefaultGCDelay,
			false, false, log, metrics, nil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := "{ExpandedRepoInfo(repo:\"zot-cve-test\"){Summary%20{Name%20LastUpdated%20Size%20Platforms%20{Os%20Arch}%20Vendors%20Score}}}" // nolint: lll

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.ExpandedRepoInfo.RepoInfo.Summary, ShouldNotBeEmpty)
		So(responseStruct.ExpandedRepoInfo.RepoInfo.Summary.Name, ShouldEqual, "zot-cve-test")
		So(responseStruct.ExpandedRepoInfo.RepoInfo.Summary.Score, ShouldEqual, -1)

		query = "{ExpandedRepoInfo(repo:\"zot-cve-test\"){Images%20{Digest%20IsSigned%20Tag%20Layers%20{Size%20Digest}}}}"

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err := testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err := digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found := false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == testManifestDigest.Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, false)
			}
		}
		So(found, ShouldEqual, true)

		err = SignImageUsingCosign("zot-cve-test:0.0.1", port)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == testManifestDigest.Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, true)
			}
		}
		So(found, ShouldEqual, true)

		query = "{ExpandedRepoInfo(repo:\"\"){Images%20{Digest%20Tag%20IsSigned%20Layers%20{Size%20Digest}}}}"

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		query = "{ExpandedRepoInfo(repo:\"zot-test\"){Images%20{Digest%20Tag%20IsSigned%20Layers%20{Size%20Digest}}}}"
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == testManifestDigest.Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, false)
			}
		}
		So(found, ShouldEqual, true)

		err = SignImageUsingCosign("zot-test:0.0.1", port)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == testManifestDigest.Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, true)
			}
		}
		So(found, ShouldEqual, true)

		var manifestDigest digest.Digest
		manifestDigest, _, _ = GetOciLayoutDigests("../../../../test/data/zot-test")

		err = os.Remove(path.Join(rootDir, "zot-test/blobs/sha256", manifestDigest.Encoded()))
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
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

		license := common.GetLicenses(labels)
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

		license = common.GetLicenses(labels)
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

		license = common.GetLicenses(labels)
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

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		metrics := monitoring.NewMetricsServer(false, log)
		defaultStore := storage.NewImageStore(rootDir, false,
			storage.DefaultGCDelay, false, false, log, metrics, nil)

		subStore := storage.NewImageStore(subRootDir, false,
			storage.DefaultGCDelay, false, false, log, metrics, nil)

		subStoreMap := make(map[string]storage.ImageStore)

		subStoreMap["/b"] = subStore

		storeController := storage.StoreController{DefaultStore: defaultStore, SubStore: subStoreMap}

		dir := common.GetRootDir("a/zot-cve-test", storeController)

		So(dir, ShouldEqual, rootDir)

		dir = common.GetRootDir("b/zot-cve-test", storeController)

		So(dir, ShouldEqual, subRootDir)
	})
}

func TestGetImageManifest(t *testing.T) {
	Convey("Test inexistent image", t, func() {
		mockImageStore := mocks.MockedImageStore{}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
		}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetImageManifest("inexistent-repo", "latest")
		So(err, ShouldNotBeNil)
	})

	Convey("Test inexistent image", t, func() {
		mockImageStore := mocks.MockedImageStore{
			GetImageManifestFn: func(repo string, reference string) ([]byte, string, string, error) {
				return []byte{}, "", "", ErrTestError
			},
		}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
		}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetImageManifest("test-repo", "latest")
		So(err, ShouldNotBeNil)
	})
}

func TestDerivedImageList(t *testing.T) {
	subpath := "/a"

	err := testSetup(t, subpath)
	if err != nil {
		panic(err)
	}

	port := GetFreePort()
	baseURL := GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = rootDir
	conf.Storage.SubPaths = make(map[string]config.StorageConfig)
	conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
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

	Convey("Test dependency list for image working", t, func() {
		// create test images
		config := ispec.Image{
			Architecture: "amd64",
			OS:           "linux",
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []digest.Digest{},
			},
			Author: "ZotUser",
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := digest.FromBytes(configBlob)

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 11},
		}

		manifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		}

		repoName := "test-repo"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "latest",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		// create image with the same layers
		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		}

		repoName = "same-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "latest",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		// create image with missing layer
		layers = [][]byte{
			{10, 11, 10, 11},
			{10, 10, 10, 11},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		repoName = "missing-layer"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "latest",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		// create image with more layers than the original
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
			{10, 10, 10, 10},
			{10, 10, 10, 11},
			{11, 11, 10, 10},
		}

		manifest = ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[4]),
					Size:      int64(len(layers[4])),
				},
			},
		}

		repoName = "more-layers"

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "latest",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		query := `
						{
							DerivedImageList(image:"test-repo"){
								RepoName,
								Tag,
								Digest,
								ConfigDigest,
								LastUpdated,
								IsSigned,
								Size
							}
						}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeTrue)
		So(strings.Contains(string(resp.Body()), "missing-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeTrue)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})

	Convey("Inexistent repository", t, func() {
		query := `
					{
						DerivedImageList(image:"inexistent-image"){
							RepoName,
							Tag,
							Digest,
							ConfigDigest,
							LastUpdated,
							IsSigned,
							Size
						}
					}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(strings.Contains(string(resp.Body()), "repository: not found"), ShouldBeTrue)
		So(err, ShouldBeNil)
	})

	Convey("Failed to get manifest", t, func() {
		err := os.Mkdir(path.Join(rootDir, "fail-image"), 0o000)
		So(err, ShouldBeNil)

		query := `
				{
					DerivedImageList(image:"fail-image"){
						RepoName,
						Tag,
						Digest,
						ConfigDigest,
						LastUpdated,
						IsSigned,
						Size
					}
				}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(strings.Contains(string(resp.Body()), "permission denied"), ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestDerivedImageListNoRepos(t *testing.T) {
	Convey("No repositories found", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()
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

		query := `
				{
					DerivedImageList(image:"test-image"){
						RepoName,
						Tag,
						Digest,
						ConfigDigest,
						LastUpdated,
						IsSigned,
						Size
					}
				}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(strings.Contains(string(resp.Body()), "{\"data\":{\"DerivedImageList\":[]}}"), ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestGetRepositories(t *testing.T) {
	Convey("Test getting the repositories list", t, func() {
		mockImageStore := mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{}, ErrTestError
			},
		}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
			SubStore:     map[string]storage.ImageStore{"test": mockImageStore},
		}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		repoList, err := olu.GetRepositories()
		So(repoList, ShouldBeEmpty)
		So(err, ShouldNotBeNil)

		storeController = storage.StoreController{
			DefaultStore: mocks.MockedImageStore{},
			SubStore:     map[string]storage.ImageStore{"test": mockImageStore},
		}
		olu = common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		repoList, err = olu.GetRepositories()
		So(repoList, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
	})
}

func TestGlobalSearch(t *testing.T) {
	Convey("Test searching for repos", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subDir := t.TempDir()

		subRootDir = path.Join(subDir, subpath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
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

		// push test images to repo 1 image 1
		config1, layers1, manifest1, err := GetImageComponents(100)
		So(err, ShouldBeNil)
		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		config1.History = append(config1.History, ispec.History{Created: &createdTime})
		manifest1, err = updateManifestConfig(manifest1, config1)
		So(err, ShouldBeNil)

		layersSize1 := 0
		for _, l := range layers1 {
			layersSize1 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest1,
				Config:   config1,
				Layers:   layers1,
				Tag:      "1.0.1",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		// push test images to repo 1 image 2
		config2, layers2, manifest2, err := GetImageComponents(200)
		So(err, ShouldBeNil)
		createdTime2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		config2.History = append(config2.History, ispec.History{Created: &createdTime2})
		manifest2, err = updateManifestConfig(manifest2, config2)
		So(err, ShouldBeNil)

		layersSize2 := 0
		for _, l := range layers2 {
			layersSize2 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest2,
				Config:   config2,
				Layers:   layers2,
				Tag:      "1.0.2",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		// push test images to repo 2 image 1
		config3, layers3, manifest3, err := GetImageComponents(300)
		So(err, ShouldBeNil)
		createdTime3 := time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC)
		config3.History = append(config3.History, ispec.History{Created: &createdTime3})
		manifest3, err = updateManifestConfig(manifest3, config3)
		So(err, ShouldBeNil)

		layersSize3 := 0
		for _, l := range layers3 {
			layersSize3 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest3,
				Config:   config3,
				Layers:   layers3,
				Tag:      "1.0.0",
			},
			baseURL,
			"repo2",
		)
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"repo"){
					Images {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
					}
					Repos {
						Name LastUpdated Size
      					Platforms { Os Arch }
      					Vendors Score
						NewestImage {
							RepoName Tag LastUpdated Size IsSigned Vendor Score
							Platform {
								Os
								Arch
							}
						}
					}
					Layers {
						Digest
						Size
					}
				}
			}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		// Make sure the repo/image counts match before comparing actual content
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeNil)
		t.Logf("returned images: %v", responseStruct.GlobalSearchResult.GlobalSearch.Images)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldBeEmpty)
		t.Logf("returned repos: %v", responseStruct.GlobalSearchResult.GlobalSearch.Repos)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Repos), ShouldEqual, 2)
		t.Logf("returned layers: %v", responseStruct.GlobalSearchResult.GlobalSearch.Layers)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Layers, ShouldBeEmpty)

		newestImageMap := make(map[string]ImageSummary)
		for _, repo := range responseStruct.GlobalSearchResult.GlobalSearch.Repos {
			newestImageMap[repo.Name] = repo.NewestImage
		}

		So(newestImageMap["repo1"].Tag, ShouldEqual, "1.0.2")
		So(newestImageMap["repo1"].LastUpdated, ShouldEqual, time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC))

		So(newestImageMap["repo2"].Tag, ShouldEqual, "1.0.0")
		So(newestImageMap["repo2"].LastUpdated, ShouldEqual, time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC))

		query = `
		{
			GlobalSearch(query:"repo1:1.0.1"){
				Images {
					RepoName Tag LastUpdated Size IsSigned Vendor Score
					Platform { Os Arch }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors Score
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform {
							Os
							Arch
						}
					}
				}
				Layers {
					Digest
					Size
				}
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeEmpty)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Repos, ShouldBeEmpty)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Layers, ShouldBeEmpty)

		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 1)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].Tag, ShouldEqual, "1.0.1")

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeEmpty)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Repos, ShouldBeEmpty)
		So(responseStruct.GlobalSearchResult.GlobalSearch.Layers, ShouldBeEmpty)

		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 1)
	})
}

func TestRepoDBWhenSigningImages(t *testing.T) {
	Convey("SigningImages", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subDir := t.TempDir()

		subRootDir = path.Join(subDir, subpath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// push test images to repo 1 image 1
		config1, layers1, manifest1, err := GetImageComponents(100)
		So(err, ShouldBeNil)
		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		config1.History = append(config1.History, ispec.History{Created: &createdTime})
		manifest1, err = updateManifestConfig(manifest1, config1)
		So(err, ShouldBeNil)

		layersSize1 := 0
		for _, l := range layers1 {
			layersSize1 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest1,
				Config:   config1,
				Layers:   layers1,
				Tag:      "1.0.1",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		query := `
		{
			GlobalSearch(query:"repo1:1.0"){
				Images {
					RepoName Tag LastUpdated Size IsSigned Vendor Score
					Platform { Os Arch }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors Score
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform {
							Os
							Arch
						}
					}
				}
				Layers {
					Digest
					Size
				}
			}
		}`

		Convey("Sign with cosign", func() {
			err = SignImageUsingCosign("repo1:1.0.1", port)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeTrue)
		})

		Convey("Cover errors when signing with cosign", func() {
			Convey("imageIsSignature fails", func() {
				// make image store ignore the wrong format of the input
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", nil
					},
					DeleteImageManifestFn: func(repo, reference string) error {
						return ErrTestError
					},
				}

				// push bad manifest blob
				resp, err := resty.R().
					SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
					SetBody([]byte("unmashable manifest blob")).
					Put(baseURL + "/v2/" + "repo" + "/manifests/" + "tag")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, AddManifestSignature fails", func() {
				ctlr.RepoDB = mocks.RepoDBMock{
					AddManifestSignatureFn: func(manifestDigest string, sm repodb.SignatureMetadata) error {
						return ErrTestError
					},
				}

				err := SignImageUsingCosign("repo1:1.0.1", port)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Sign with notation", func() {
			err = SignImageUsingNotary("repo1:1.0.1", port)
			So(err, ShouldBeNil)

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeTrue)
		})
	})
}

func TestRepoDBWhenPushingImages(t *testing.T) {
	Convey("Cover errors when pushing", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		Convey("SetManifestMeta fails", func() {
			ctlr.RepoDB = mocks.RepoDBMock{
				SetManifestMetaFn: func(manifestDigest string, mm repodb.ManifestMetadata) error {
					return ErrTestError
				},
			}
			config1, layers1, manifest1, err := GetImageComponents(100)
			So(err, ShouldBeNil)

			configBlob, err := json.Marshal(config1)
			So(err, ShouldBeNil)

			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
				PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
				GetBlobContentFn: func(repo, digest string) ([]byte, error) {
					return configBlob, nil
				},
				DeleteImageManifestFn: func(repo, reference string) error {
					return ErrTestError
				},
			}

			err = UploadImage(
				Image{
					Manifest: manifest1,
					Config:   config1,
					Layers:   layers1,
					Tag:      "1.0.1",
				},
				baseURL,
				"repo1",
			)
			So(err, ShouldBeNil)
		})

		Convey("SetManifestMeta succeeds but SetRepoTag fails", func() {
			ctlr.RepoDB = mocks.RepoDBMock{
				SetRepoTagFn: func(repo, tag, manifestDigest string) error {
					return ErrTestError
				},
			}

			config1, layers1, manifest1, err := GetImageComponents(100)
			So(err, ShouldBeNil)

			configBlob, err := json.Marshal(config1)
			So(err, ShouldBeNil)

			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
				PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
				GetBlobContentFn: func(repo, digest string) ([]byte, error) {
					return configBlob, nil
				},
			}

			err = UploadImage(
				Image{
					Manifest: manifest1,
					Config:   config1,
					Layers:   layers1,
					Tag:      "1.0.1",
				},
				baseURL,
				"repo1",
			)
			So(err, ShouldBeNil)
		})
	})
}

func TestRepoDBWhenReadingImages(t *testing.T) {
	Convey("Push test image", t, func() {
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		config1, layers1, manifest1, err := GetImageComponents(100)
		So(err, ShouldBeNil)

		err = UploadImage(
			Image{
				Manifest: manifest1,
				Config:   config1,
				Layers:   layers1,
				Tag:      "1.0.1",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		Convey("Download 3 times", func() {
			resp, err := resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			query := `
			{
				GlobalSearch(query:"repo1:1.0"){
					Images {
						RepoName Tag DownloadCount
					}
				}
			}`

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)
			So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeEmpty)
			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].DownloadCount, ShouldEqual, 3)
		})

		Convey("Error when incrementing", func() {
			ctlr.RepoDB = mocks.RepoDBMock{
				IncrementManifestDownloadsFn: func(manifestDigest string) error {
					return ErrTestError
				},
			}

			resp, err := resty.R().Get(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestRepoDBWhenDeletingImages(t *testing.T) {
	Convey("Setting up zot repo with test images", t, func() {
		subpath := "/a"

		dir := t.TempDir()
		subDir := t.TempDir()

		subRootDir = path.Join(subDir, subpath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.Storage.SubPaths = make(map[string]config.StorageConfig)
		conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// push test images to repo 1 image 1
		config1, layers1, manifest1, err := GetImageComponents(100)
		So(err, ShouldBeNil)

		layersSize1 := 0
		for _, l := range layers1 {
			layersSize1 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest1,
				Config:   config1,
				Layers:   layers1,
				Tag:      "1.0.1",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		// push test images to repo 1 image 2
		config2, layers2, manifest2, err := GetImageComponents(200)
		So(err, ShouldBeNil)
		createdTime2 := time.Date(2009, 1, 1, 12, 0, 0, 0, time.UTC)
		config2.History = append(config2.History, ispec.History{Created: &createdTime2})
		manifest2, err = updateManifestConfig(manifest2, config2)
		So(err, ShouldBeNil)

		layersSize2 := 0
		for _, l := range layers2 {
			layersSize2 += len(l)
		}

		err = UploadImage(
			Image{
				Manifest: manifest2,
				Config:   config2,
				Layers:   layers2,
				Tag:      "1.0.2",
			},
			baseURL,
			"repo1",
		)
		So(err, ShouldBeNil)

		query := `
		{
			GlobalSearch(query:"repo1:1.0"){
				Images {
					RepoName Tag LastUpdated Size IsSigned Vendor Score
					Platform { Os Arch }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors Score
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform {
							Os
							Arch
						}
					}
				}
				Layers {
					Digest
					Size
				}
			}
		}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := &GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 2)

		Convey("Delete a normal tag", func() {
			resp, err := resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "1.0.1")
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 1)
			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].Tag, ShouldEqual, "1.0.2")
		})

		Convey("Delete a cosign signature", func() {
			repo := "repo1"
			err := SignImageUsingCosign("repo1:1.0.1", port)
			So(err, ShouldBeNil)

			query := `
			{
				GlobalSearch(query:"repo1:1.0.1"){
					Images {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
					}
				}
			}`

			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeTrue)

			// get signatur digest
			log := log.NewLogger("debug", "")
			metrics := monitoring.NewMetricsServer(false, log)
			storage := storage.NewImageStore(dir, false, storage.DefaultGCDelay,
				false, false, log, metrics, nil)

			indexBlob, err := storage.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var indexContent ispec.Index

			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			signatureTag := ""

			for _, manifest := range indexContent.Manifests {
				tag := manifest.Annotations[ispec.AnnotationRefName]

				cosignTagRule := glob.MustCompile("sha256-*.sig")

				if cosignTagRule.Match(tag) {
					signatureTag = tag
				}
			}

			// delete the signature using the digest
			resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + signatureTag)
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// verify isSigned again and it should be false
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeFalse)
		})

		Convey("Delete a notary signature", func() {
			repo := "repo1"
			err := SignImageUsingNotary("repo1:1.0.1", port)
			So(err, ShouldBeNil)

			query := `
			{
				GlobalSearch(query:"repo1:1.0.1"){
					Images {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
					}
				}
			}`

			// test if it's signed
			resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeTrue)

			// get signatur digest
			log := log.NewLogger("debug", "")
			metrics := monitoring.NewMetricsServer(false, log)
			storage := storage.NewImageStore(dir, false, storage.DefaultGCDelay,
				false, false, log, metrics, nil)

			indexBlob, err := storage.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var indexContent ispec.Index

			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			signatureRefference := ""

			var sigManifestContent artifactspec.Manifest

			for _, manifest := range indexContent.Manifests {
				if manifest.MediaType == artifactspec.MediaTypeArtifactManifest {
					signatureRefference = manifest.Digest.String()
					manifestBlob, _, _, err := storage.GetImageManifest(repo, signatureRefference)
					So(err, ShouldBeNil)
					err = json.Unmarshal(manifestBlob, &sigManifestContent)
					So(err, ShouldBeNil)
				}
			}

			So(sigManifestContent, ShouldNotBeZeroValue)
			// check notation signature
			manifest1Blob, err := json.Marshal(manifest1)
			So(err, ShouldBeNil)
			manifest1Digest := digest.FromBytes(manifest1Blob)
			So(sigManifestContent.Subject, ShouldNotBeNil)
			So(sigManifestContent.Subject.Digest.String(), ShouldEqual, manifest1Digest.String())

			// delete the signature using the digest
			resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + signatureRefference)
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// verify isSigned again and it should be false
			resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
			So(resp, ShouldNotBeNil)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = &GlobalSearchResultResp{}

			err = json.Unmarshal(resp.Body(), responseStruct)
			So(err, ShouldBeNil)

			So(responseStruct.GlobalSearchResult.GlobalSearch.Images[0].IsSigned, ShouldBeFalse)
		})

		Convey("Deleting causes errors", func() {
			Convey("error while backing up the manifest", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, string, string, error) {
						return []byte{}, "", "", zerr.ErrRepoNotFound
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureRefference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, string, string, error) {
						return []byte{}, "", "", zerr.ErrBadManifest
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureRefference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)

				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					GetImageManifestFn: func(repo, reference string) ([]byte, string, string, error) {
						return []byte{}, "", "", zerr.ErrRepoNotFound
					},
				}
				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureRefference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("imageIsSignature fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", nil
					},
					DeleteImageManifestFn: func(repo, reference string) error {
						return nil
					},
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" + "signatureRefference")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, DeleteSignature fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
					PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
					GetBlobContentFn: func(repo, digest string) ([]byte, error) {
						configBlob, err := json.Marshal(ispec.Image{})
						So(err, ShouldBeNil)

						return configBlob, nil
					},
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", nil
					},
					DeleteImageManifestFn: func(repo, reference string) error {
						return nil
					},
					GetImageManifestFn: func(repo, reference string) ([]byte, string, string, error) {
						return []byte("{}"), "1", "1", nil
					},
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" +
					"sha256-343ebab94a7674da181c6ea3da013aee4f8cbe357870f8dcaf6268d5343c3474.sig")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("image is a signature, PutImageManifest fails", func() {
				ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
					NewBlobUploadFn: ctlr.StoreController.DefaultStore.NewBlobUpload,
					PutBlobChunkFn:  ctlr.StoreController.DefaultStore.PutBlobChunk,
					GetBlobContentFn: func(repo, digest string) ([]byte, error) {
						configBlob, err := json.Marshal(ispec.Image{})
						So(err, ShouldBeNil)

						return configBlob, nil
					},
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (string, error) {
						return "", ErrTestError
					},
					DeleteImageManifestFn: func(repo, reference string) error {
						return nil
					},
					GetImageManifestFn: func(repo, reference string) ([]byte, string, string, error) {
						return []byte("{}"), "1", "1", nil
					},
				}

				ctlr.RepoDB = mocks.RepoDBMock{
					DeleteRepoTagFn: func(repo, tag string) error { return ErrTestError },
				}

				resp, err = resty.R().Delete(baseURL + "/v2/" + "repo1" + "/manifests/" +
					"343ebab94a7674da181c6ea3da013aee4f8cbe357870f8dcaf6268d5343c3474.sig")
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func updateManifestConfig(manifest ispec.Manifest, config ispec.Image) (ispec.Manifest, error) {
	configBlob, err := json.Marshal(config)

	configDigest := digest.FromBytes(configBlob)
	configSize := len(configBlob)

	manifest.Config.Digest = configDigest
	manifest.Config.Size = int64(configSize)

	return manifest, err
}

func TestBaseOciLayoutUtils(t *testing.T) {
	manifestDigest := "sha256:adf3bb6cc81f8bd6a9d5233be5f0c1a4f1e3ed1cf5bbdfad7708cc8d4099b741"

	Convey("GetImageManifestSize fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo, digest string) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageManifestSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetImageConfigSize: fail GetImageBlobManifest", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo, digest string) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageConfigSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetImageConfigSize: config GetBlobContent fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(_, digest string) ([]byte, error) {
				if digest == manifestDigest {
					return []byte{}, ErrTestError
				}

				return []byte(
					`
				{
					"schemaVersion": 2,
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"config": {
						"mediaType": "application/vnd.oci.image.config.v1+json",
						"digest": manifestDigest,
						"size": 1476
					},
					"layers": [
						{
							"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
							"digest": "sha256:2d473b07cdd5f0912cd6f1a703352c82b512407db6b05b43f2553732b55df3bc",
							"size": 76097157
						}
					]
				}`), nil
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageConfigSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetRepoLastUpdated: config GetBlobContent fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetRepoLastUpdated("")
		So(err, ShouldNotBeNil)
	})
}

func TestSearchSize(t *testing.T) {
	Convey("Repo sizes", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		tr := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &tr},
		}

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		repoName := "testrepo"
		config, layers, manifest, err := GetImageComponents(10000)
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)
		configSize := len(configBlob)

		layersSize := 0
		for _, l := range layers {
			layersSize += len(l)
		}

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		manifestSize := len(manifestBlob)

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "latest",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:"testrepo:"){
					Images { RepoName Tag LastUpdated Size Score }
					Repos { 
						Name LastUpdated Size Vendors Score
      					Platforms {
      						Os
      						Arch
      					}
					}
					Layers { Digest Size }
				}
			}`
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct := &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		image := responseStruct.GlobalSearchResult.GlobalSearch.Images[0]
		So(image.Tag, ShouldResemble, "latest")

		size, err := strconv.Atoi(image.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)

		query = `
		{
			GlobalSearch(query:"testrepo"){
				Images { RepoName Tag LastUpdated Size Score }
				Repos { 
					Name LastUpdated Size Vendors Score
						Platforms {
							Os
							Arch
						}
				}
				Layers { Digest Size }
			}
		}`
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		repo := responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)

		// add the same image with different tag
		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      "10.2.14",
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)

		// query for images
		query = `
		{
			GlobalSearch(query:"testrepo:"){
				Images { RepoName Tag LastUpdated Size Score }
				Repos { 
					Name LastUpdated Size Vendors Score
					  Platforms {
						Os
						Arch
					  }
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 2)
		// check that the repo size is the same
		// query for repos
		query = `
		{
			GlobalSearch(query:"testrepo"){
				Images { RepoName Tag LastUpdated Size Score }
				Repos { 
					Name LastUpdated Size Vendors Score
					  Platforms {
						Os
						Arch
					  }
				}
				Layers { Digest Size }
			}
		}`

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		repo = responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, configSize+layersSize+manifestSize)
	})
}

func startServer(c *api.Controller) {
	// this blocks
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
