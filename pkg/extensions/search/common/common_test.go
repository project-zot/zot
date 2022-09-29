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

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
	"zotregistry.io/zot/pkg/extensions/search"
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

type ImageListResponse struct {
	ImageList ImageList  `json:"data"`
	Errors    []ErrorGQL `json:"errors"`
}

type ImageList struct {
	SummaryList []ImageSummary `json:"imageList"`
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
	RepoName        string                    `json:"repoName"`
	Tag             string                    `json:"tag"`
	LastUpdated     time.Time                 `json:"lastUpdated"`
	Size            string                    `json:"size"`
	Platform        OsArch                    `json:"platform"`
	Vendor          string                    `json:"vendor"`
	Score           int                       `json:"score"`
	IsSigned        bool                      `json:"isSigned"`
	DownloadCount   int                       `json:"downloadCount"`
	History         []LayerHistory            `json:"history"`
	Layers          []LayerSummary            `json:"layers"`
	Vulnerabilities ImageVulnerabilitySummary `json:"vulnerabilities"`
}

type LayerHistory struct {
	Layer              LayerSummary       `json:"layer"`
	HistoryDescription HistoryDescription `json:"historyDescription"`
}

type HistoryDescription struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"createdBy"`
	Author     string    `json:"author"`
	Comment    string    `json:"comment"`
	EmptyLayer bool      `json:"emptyLayer"`
}

type ImageVulnerabilitySummary struct {
	MaxSeverity string `json:"maxSeverity"`
	Count       int    `json:"count"`
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

	vulnerableTags := make([]common.TagInfo, 0)
	vulnerableTags = append(vulnerableTags, secondTag)

	return tags, vulnerableTags
}

func readFileAndSearchString(filePath string, stringToMatch string, timeout time.Duration) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(filePath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
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
		body := string(resp.Body())
		So(body, ShouldContainSubstring, "can't get last updated manifest for repo:")
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
		body = string(resp.Body())
		So(body, ShouldContainSubstring, "can't get last updated manifest for repo")
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
		So(body, ShouldContainSubstring, "reference not found for manifest")
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

		// Verify we don't return any vulnerabilities if CVE scanning is disabled
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag%20Vulnerabilities{MaxSeverity%20Count}}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.RepoListWithNewestImage.Repos), ShouldEqual, 4)

		images = responseStruct.RepoListWithNewestImage.Repos
		So(images[0].NewestImage.Tag, ShouldEqual, "0.0.1")
		So(images[0].NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
		So(images[0].NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "")

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

	Convey("Test repoListWithNewestImage with vulnerability scan enabled", t, func() {
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

		updateDuration, _ := time.ParseDuration("1h")
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
		}
		searchConfig := &extconf.SearchConfig{
			Enable: &defaultVal,
			CVE:    cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		So(err, ShouldBeNil)
		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

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

		substring := "{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true}"
		found, err := readFileAndSearchString(logPath, substring, 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "updating the CVE database", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "DB update completed, next update scheduled", 4*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := "?query={RepoListWithNewestImage{Name%20NewestImage{Tag%20Vulnerabilities{MaxSeverity%20Count}}}}"
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct RepoWithNewestImageResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.RepoListWithNewestImage.Repos), ShouldEqual, 4)

		repos := responseStruct.RepoListWithNewestImage.Repos
		So(repos[0].NewestImage.Tag, ShouldEqual, "0.0.1")

		for _, repo := range repos {
			vulnerabilities := repo.NewestImage.Vulnerabilities
			So(vulnerabilities, ShouldNotBeNil)
			t.Logf("Found vulnerability summary %v", vulnerabilities)
			// Depends on test data, but current tested images contain hundreds
			So(vulnerabilities.Count, ShouldBeGreaterThan, 1)
			So(
				dbTypes.CompareSeverityString(dbTypes.SeverityUnknown.String(), vulnerabilities.MaxSeverity),
				ShouldBeGreaterThan,
				0,
			)
			// This really depends on the test data, but with the current test images it's CRITICAL
			So(vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
		}
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldEqual, 2)
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err := testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err := digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found := false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)

		_, mdigest, _, err = testStorage.GetImageManifest("zot-test", "0.0.1")
		So(err, ShouldBeNil)
		testManifestDigest, err = digest.Parse(mdigest)
		So(err, ShouldBeNil)

		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
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
		labels[ispec.AnnotationLicenses] = "zot-label-license"

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

		allTags, vulnerableTags := getTags()

		latestTag := common.GetLatestTag(allTags)
		So(latestTag.Name, ShouldEqual, "1.0.3")

		fixedTags := common.GetFixedTags(allTags, vulnerableTags)
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

// nolint:dupl
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

func TestGetImageManifest(t *testing.T) {
	Convey("Test nonexistent image", t, func() {
		mockImageStore := mocks.MockedImageStore{}

		storeController := storage.StoreController{
			DefaultStore: mockImageStore,
		}
		olu := common.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetImageManifest("nonexistent-repo", "latest")
		So(err, ShouldNotBeNil)
	})

	Convey("Test nonexistent image", t, func() {
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

func TestBaseImageList(t *testing.T) {
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

	Convey("Test base image list for image working", t, func() {
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
			{10, 10, 10, 10},
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
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
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest.FromBytes(layers[3]),
					Size:      int64(len(layers[3])),
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

		// create image with less layers than the given image, but which are in the given image
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

		repoName = "less-layers"

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

		// create image with less layers than the given image, but one layer isn't in the given image
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 10, 10, 11},
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

		repoName = "less-layers-false"

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

		// create image with no shared layers with the given image
		layers = [][]byte{
			{12, 12, 12, 12},
			{12, 10, 10, 12},
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

		repoName = "diff-layers"

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
				BaseImageList(image:"test-repo"){
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
		So(strings.Contains(string(resp.Body()), "less-layers"), ShouldBeTrue)
		So(strings.Contains(string(resp.Body()), "less-layers-false"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "diff-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeTrue) // should not list given image
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})

	Convey("Nonexistent repository", t, func() {
		query := `
			{
				BaseImageList(image:"nonexistent-image"){
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
				BaseImageList(image:"fail-image"){
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

// nolint:dupl
func TestBaseImageListNoRepos(t *testing.T) {
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
				BaseImageList(image:"test-image"){
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
		So(strings.Contains(string(resp.Body()), "{\"data\":{\"BaseImageList\":[]}}"), ShouldBeTrue)
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

//nolint:dupl // duplicated test code
func TestGlobalSearch(t *testing.T) {
	Convey("Test searching for repos with vulnerabitity scanning disabled", t, func() {
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

		olu := common.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))

		// Initialize the objects containing the expected data
		repos, err := olu.GetRepositories()
		So(err, ShouldBeNil)

		allExpectedRepoInfoMap := make(map[string]common.RepoInfo)
		allExpectedImageSummaryMap := make(map[string]common.ImageSummary)
		for _, repo := range repos {
			repoInfo, err := olu.GetExpandedRepoInfo(repo)
			So(err, ShouldBeNil)
			allExpectedRepoInfoMap[repo] = repoInfo
			for _, image := range repoInfo.ImageSummaries {
				imageName := fmt.Sprintf("%s:%s", repo, image.Tag)
				allExpectedImageSummaryMap[imageName] = image
			}
		}

		query := `
			{
				GlobalSearch(query:"repo"){
					Images {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
						Vulnerabilities { Count MaxSeverity }
					}
					Repos {
						Name LastUpdated Size
      					Platforms { Os Arch }
      					Vendors Score
						NewestImage {
							RepoName Tag LastUpdated Size IsSigned Vendor Score
							Platform { Os Arch }
							Vulnerabilities { Count MaxSeverity }
						}
					}
					Layers { Digest Size }
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
		actualRepoMap := make(map[string]RepoSummary)
		for _, repo := range responseStruct.GlobalSearchResult.GlobalSearch.Repos {
			newestImageMap[repo.Name] = repo.NewestImage
			actualRepoMap[repo.Name] = repo
		}

		// Tag 1.0.2 has a history entry which is older compare to 1.0.1
		So(newestImageMap["repo1"].Tag, ShouldEqual, "1.0.1")
		So(newestImageMap["repo1"].LastUpdated, ShouldEqual, time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC))

		So(newestImageMap["repo2"].Tag, ShouldEqual, "1.0.0")
		So(newestImageMap["repo2"].LastUpdated, ShouldEqual, time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC))

		for repoName, repoSummary := range actualRepoMap {
			// Check if data in NewestImage is consistent with the data in RepoSummary
			So(repoName, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.Name, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.LastUpdated, ShouldEqual, repoSummary.NewestImage.LastUpdated)

			// The data in the RepoSummary returned from the request matches the data returned from the disk
			repoInfo := allExpectedRepoInfoMap[repoName]
			So(repoSummary.Name, ShouldEqual, repoInfo.Summary.Name)
			So(repoSummary.LastUpdated, ShouldEqual, repoInfo.Summary.LastUpdated)
			So(repoSummary.Size, ShouldEqual, repoInfo.Summary.Size)
			So(len(repoSummary.Vendors), ShouldEqual, len(repoInfo.Summary.Vendors))
			for index, vendor := range repoSummary.Vendors {
				So(vendor, ShouldEqual, repoInfo.Summary.Vendors[index])
			}
			So(len(repoSummary.Platforms), ShouldEqual, len(repoInfo.Summary.Platforms))
			for index, platform := range repoSummary.Platforms {
				So(platform.Os, ShouldEqual, repoInfo.Summary.Platforms[index].Os)
				So(platform.Arch, ShouldEqual, repoInfo.Summary.Platforms[index].Arch)
			}
			So(repoSummary.NewestImage.Tag, ShouldEqual, repoInfo.Summary.NewestImage.Tag)
			So(repoSummary.NewestImage.LastUpdated, ShouldEqual, repoInfo.Summary.NewestImage.LastUpdated)
			So(repoSummary.NewestImage.Size, ShouldEqual, repoInfo.Summary.NewestImage.Size)
			So(repoSummary.NewestImage.IsSigned, ShouldEqual, repoInfo.Summary.NewestImage.IsSigned)
			So(repoSummary.NewestImage.Vendor, ShouldEqual, repoInfo.Summary.NewestImage.Vendor)
			So(repoSummary.NewestImage.Platform.Os, ShouldEqual, repoInfo.Summary.NewestImage.Platform.Os)
			So(repoSummary.NewestImage.Platform.Arch, ShouldEqual, repoInfo.Summary.NewestImage.Platform.Arch)

			// RepoInfo object does not provide vulnerability information so we need to check differently
			// No vulnerabilities should be detected since trivy is disabled
			t.Logf("Found vulnerability summary %v", repoSummary.NewestImage.Vulnerabilities)
			So(repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
			So(repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "")
		}

		query = `
		{
			GlobalSearch(query:"repo1:1.0.1"){
				Images {
					RepoName Tag LastUpdated Size IsSigned Vendor Score
					Platform { Os Arch }
					Vulnerabilities { Count MaxSeverity }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors Score
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
						Vulnerabilities { Count MaxSeverity }
					}
				}
				Layers { Digest Size }
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
		actualImageSummary := responseStruct.GlobalSearchResult.GlobalSearch.Images[0]
		So(actualImageSummary.Tag, ShouldEqual, "1.0.1")

		expectedImageSummary, ok := allExpectedImageSummaryMap["repo1:1.0.1"]
		So(ok, ShouldEqual, true)
		So(actualImageSummary.Tag, ShouldEqual, expectedImageSummary.Tag)
		So(actualImageSummary.LastUpdated, ShouldEqual, expectedImageSummary.LastUpdated)
		So(actualImageSummary.Size, ShouldEqual, expectedImageSummary.Size)
		So(actualImageSummary.IsSigned, ShouldEqual, expectedImageSummary.IsSigned)
		So(actualImageSummary.Vendor, ShouldEqual, expectedImageSummary.Vendor)
		So(actualImageSummary.Platform.Os, ShouldEqual, expectedImageSummary.Platform.Os)
		So(actualImageSummary.Platform.Arch, ShouldEqual, expectedImageSummary.Platform.Arch)

		// RepoInfo object does not provide vulnerability information so we need to check differently
		// 0 vulnerabilities should be detected since trivy is disabled
		t.Logf("Found vulnerability summary %v", actualImageSummary.Vulnerabilities)
		So(actualImageSummary.Vulnerabilities.Count, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "")
	})

	Convey("Test global search with real images and vulnerabitity scanning enabled", t, func() {
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

		updateDuration, _ := time.ParseDuration("1h")
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
		}
		searchConfig := &extconf.SearchConfig{
			Enable: &defaultVal,
			CVE:    cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		// we won't use the logging config feature as we want logs in both
		// stdout and a file
		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		So(err, ShouldBeNil)
		logPath := logFile.Name()
		defer os.Remove(logPath)

		writers := io.MultiWriter(os.Stdout, logFile)

		ctlr := api.NewController(conf)
		ctlr.Log.Logger = ctlr.Log.Output(writers)

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

		// Wait for trivy db to download
		substring := "{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true}"
		found, err := readFileAndSearchString(logPath, substring, 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "updating the CVE database", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "DB update completed, next update scheduled", 4*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

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

		olu := common.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))

		// Initialize the objects containing the expected data
		repos, err := olu.GetRepositories()
		So(err, ShouldBeNil)

		allExpectedRepoInfoMap := make(map[string]common.RepoInfo)
		allExpectedImageSummaryMap := make(map[string]common.ImageSummary)
		for _, repo := range repos {
			repoInfo, err := olu.GetExpandedRepoInfo(repo)
			So(err, ShouldBeNil)
			allExpectedRepoInfoMap[repo] = repoInfo
			for _, image := range repoInfo.ImageSummaries {
				imageName := fmt.Sprintf("%s:%s", repo, image.Tag)
				allExpectedImageSummaryMap[imageName] = image
			}
		}

		query := `
			{
				GlobalSearch(query:"repo"){
					Images {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
						Vulnerabilities { Count MaxSeverity }
					}
					Repos {
						Name LastUpdated Size
      					Platforms { Os Arch }
      					Vendors Score
						NewestImage {
							RepoName Tag LastUpdated Size IsSigned Vendor Score
							Platform { Os Arch }
							Vulnerabilities { Count MaxSeverity }
						}
					}
					Layers { Digest Size }
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
		actualRepoMap := make(map[string]RepoSummary)
		for _, repo := range responseStruct.GlobalSearchResult.GlobalSearch.Repos {
			newestImageMap[repo.Name] = repo.NewestImage
			actualRepoMap[repo.Name] = repo
		}

		// Tag 1.0.2 has a history entry which is older compare to 1.0.1
		So(newestImageMap["repo1"].Tag, ShouldEqual, "1.0.1")
		So(newestImageMap["repo1"].LastUpdated, ShouldEqual, time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC))

		So(newestImageMap["repo2"].Tag, ShouldEqual, "1.0.0")
		So(newestImageMap["repo2"].LastUpdated, ShouldEqual, time.Date(2009, 2, 1, 12, 0, 0, 0, time.UTC))

		for repoName, repoSummary := range actualRepoMap {
			// Check if data in NewestImage is consistent with the data in RepoSummary
			So(repoName, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.Name, ShouldEqual, repoSummary.NewestImage.RepoName)
			So(repoSummary.LastUpdated, ShouldEqual, repoSummary.NewestImage.LastUpdated)

			// The data in the RepoSummary returned from the request matches the data returned from the disk
			repoInfo := allExpectedRepoInfoMap[repoName]
			So(repoSummary.Name, ShouldEqual, repoInfo.Summary.Name)
			So(repoSummary.LastUpdated, ShouldEqual, repoInfo.Summary.LastUpdated)
			So(repoSummary.Size, ShouldEqual, repoInfo.Summary.Size)
			So(len(repoSummary.Vendors), ShouldEqual, len(repoInfo.Summary.Vendors))
			for index, vendor := range repoSummary.Vendors {
				So(vendor, ShouldEqual, repoInfo.Summary.Vendors[index])
			}
			So(len(repoSummary.Platforms), ShouldEqual, len(repoInfo.Summary.Platforms))
			for index, platform := range repoSummary.Platforms {
				So(platform.Os, ShouldEqual, repoInfo.Summary.Platforms[index].Os)
				So(platform.Arch, ShouldEqual, repoInfo.Summary.Platforms[index].Arch)
			}
			So(repoSummary.NewestImage.Tag, ShouldEqual, repoInfo.Summary.NewestImage.Tag)
			So(repoSummary.NewestImage.LastUpdated, ShouldEqual, repoInfo.Summary.NewestImage.LastUpdated)
			So(repoSummary.NewestImage.Size, ShouldEqual, repoInfo.Summary.NewestImage.Size)
			So(repoSummary.NewestImage.IsSigned, ShouldEqual, repoInfo.Summary.NewestImage.IsSigned)
			So(repoSummary.NewestImage.Vendor, ShouldEqual, repoInfo.Summary.NewestImage.Vendor)
			So(repoSummary.NewestImage.Platform.Os, ShouldEqual, repoInfo.Summary.NewestImage.Platform.Os)
			So(repoSummary.NewestImage.Platform.Arch, ShouldEqual, repoInfo.Summary.NewestImage.Platform.Arch)

			// RepoInfo object does not provide vulnerability information so we need to check differently
			t.Logf("Found vulnerability summary %v", repoSummary.NewestImage.Vulnerabilities)
			So(repoSummary.NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
			// The score is UNKNOWN by default, as there are 0 vulnerabilities this data used in tests
			So(repoSummary.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "UNKNOWN")
		}

		query = `
		{
			GlobalSearch(query:"repo1:1.0.1"){
				Images {
					RepoName Tag LastUpdated Size IsSigned Vendor Score
					Platform { Os Arch }
					Vulnerabilities { Count MaxSeverity }
				}
				Repos {
					Name LastUpdated Size
					Platforms { Os Arch }
					Vendors Score
					NewestImage {
						RepoName Tag LastUpdated Size IsSigned Vendor Score
						Platform { Os Arch }
						Vulnerabilities { Count MaxSeverity }
					}
				}
				Layers { Digest Size }
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
		actualImageSummary := responseStruct.GlobalSearchResult.GlobalSearch.Images[0]
		So(actualImageSummary.Tag, ShouldEqual, "1.0.1")

		expectedImageSummary, ok := allExpectedImageSummaryMap["repo1:1.0.1"]
		So(ok, ShouldEqual, true)
		So(actualImageSummary.Tag, ShouldEqual, expectedImageSummary.Tag)
		So(actualImageSummary.LastUpdated, ShouldEqual, expectedImageSummary.LastUpdated)
		So(actualImageSummary.Size, ShouldEqual, expectedImageSummary.Size)
		So(actualImageSummary.IsSigned, ShouldEqual, expectedImageSummary.IsSigned)
		So(actualImageSummary.Vendor, ShouldEqual, expectedImageSummary.Vendor)
		So(actualImageSummary.Platform.Os, ShouldEqual, expectedImageSummary.Platform.Os)
		So(actualImageSummary.Platform.Arch, ShouldEqual, expectedImageSummary.Platform.Arch)

		// RepoInfo object does not provide vulnerability information so we need to check differently
		t.Logf("Found vulnerability summary %v", actualImageSummary.Vulnerabilities)
		// The score is UNKNOWN by default, as there are 0 vulnerabilities this data used in tests
		So(actualImageSummary.Vulnerabilities.Count, ShouldEqual, 0)
		So(actualImageSummary.Vulnerabilities.MaxSeverity, ShouldEqual, "UNKNOWN")
	})
}

func TestImageList(t *testing.T) {
	Convey("Test ImageList", t, func() {
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
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		imageStore := ctlr.StoreController.DefaultStore

		repos, err := imageStore.GetRepositories()
		So(err, ShouldBeNil)

		tags, err := imageStore.GetImageTags(repos[0])
		So(err, ShouldBeNil)

		buf, _, _, err := imageStore.GetImageManifest(repos[0], tags[0])
		So(err, ShouldBeNil)
		var imageManifest ispec.Manifest
		err = json.Unmarshal(buf, &imageManifest)
		So(err, ShouldBeNil)

		var imageConfigInfo ispec.Image
		imageConfigBuf, err := imageStore.GetBlobContent(repos[0], imageManifest.Config.Digest.String())
		So(err, ShouldBeNil)
		err = json.Unmarshal(imageConfigBuf, &imageConfigInfo)
		So(err, ShouldBeNil)

		query := fmt.Sprintf(`{
		ImageList(repo:"%s"){
			History{
				HistoryDescription{
					Author
					Comment
					Created
					CreatedBy
					EmptyLayer
				},
				Layer{
					Digest
					Size
				}
			}
		}
	}`, repos[0])

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp, ShouldNotBeNil)

		var responseStruct ImageListResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.ImageList.SummaryList[0].History), ShouldEqual, len(imageConfigInfo.History))
	})

	Convey("Test ImageSummary retuned by ImageList when getting tags timestamp info fails", t, func() {
		invalid := "test"
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

		config := ispec.Image{
			Architecture: "amd64",
			OS:           "linux",
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []digest.Digest{},
			},
			Author:  "ZotUser",
			History: []ispec.History{},
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := digest.FromBytes(configBlob)
		layerDigest := digest.FromString(invalid)
		layerblob := []byte(invalid)
		schemaVersion := 2
		ispecManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: schemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{ // just 1 layer in manifest
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerblob)),
				},
			},
			Annotations: map[string]string{
				ispec.AnnotationRefName: "1.0",
			},
		}

		err = UploadImage(
			Image{
				Manifest: ispecManifest,
				Config:   config,
				Layers: [][]byte{
					layerblob,
				},
				Tag: "0.0.1",
			},
			baseURL,
			invalid,
		)
		So(err, ShouldBeNil)

		configPath := path.Join(conf.Storage.RootDirectory, invalid, "blobs",
			configDigest.Algorithm().String(), configDigest.Encoded())

		err = os.Remove(configPath)
		So(err, ShouldBeNil)

		query := fmt.Sprintf(`{
		ImageList(repo:"%s"){
			History{
				HistoryDescription{
					Author
					Comment
					Created
					CreatedBy
					EmptyLayer
				},
				Layer{
					Digest
					Size
				}
			}
		}
	}`, invalid)

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp, ShouldNotBeNil)

		var responseStruct ImageListResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ImageList.SummaryList), ShouldBeZeroValue)
	})
}

func TestBuildImageInfo(t *testing.T) {
	Convey("Check image summary when layer count does not match history", t, func() {
		invalid := "invalid"

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		rootDir = t.TempDir()
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

		olu := &common.BaseOciLayoutUtils{
			StoreController: ctlr.StoreController,
			Log:             ctlr.Log,
		}

		config := ispec.Image{
			Architecture: "amd64",
			OS:           "linux",
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []digest.Digest{},
			},
			Author: "ZotUser",
			History: []ispec.History{ // should contain 3 elements, 2 of which corresponding to layers
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: true,
				},
			},
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := digest.FromBytes(configBlob)
		layerDigest := digest.FromString(invalid)
		layerblob := []byte(invalid)
		schemaVersion := 2
		ispecManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: schemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{ // just 1 layer in manifest
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerblob)),
				},
			},
		}
		manifestLayersSize := ispecManifest.Layers[0].Size
		manifestBlob, err := json.Marshal(ispecManifest)
		So(err, ShouldBeNil)
		manifestDigest := digest.FromBytes(manifestBlob)
		err = UploadImage(
			Image{
				Manifest: ispecManifest,
				Config:   config,
				Layers: [][]byte{
					layerblob,
				},
				Tag: "0.0.1",
			},
			baseURL,
			invalid,
		)
		So(err, ShouldBeNil)

		manifest, err := olu.GetImageBlobManifest(invalid, manifestDigest)
		So(err, ShouldBeNil)

		imageConfig, err := olu.GetImageConfigInfo(invalid, manifestDigest)
		So(err, ShouldBeNil)

		imageSummary := search.BuildImageInfo(invalid, invalid, manifestDigest, manifest, imageConfig)

		So(len(imageSummary.Layers), ShouldEqual, len(manifest.Layers))
		imageSummaryLayerSize, err := strconv.Atoi(*imageSummary.Size)
		So(err, ShouldBeNil)
		So(imageSummaryLayerSize, ShouldEqual, manifestLayersSize)
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
