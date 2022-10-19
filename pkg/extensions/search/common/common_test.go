//go:build search
// +build search

package common_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	graphqlQueryPrefix = constants.FullSearchPrefix
)

var (
	ErrTestError   = errors.New("test error")
	ErrPutManifest = errors.New("can't put manifest")
)

//nolint:gochecknoglobals
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
	SummaryList []common.ImageSummary `json:"imageList"`
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
	Images []common.ImageSummary `json:"images"`
	Repos  []common.RepoSummary  `json:"repos"`
	Layers []common.LayerSummary `json:"layers"`
}

type ExpandedRepoInfo struct {
	RepoInfo common.RepoInfo `json:"expandedRepoInfo"`
}

//nolint:tagliatelle // graphQL schema
type RepoListWithNewestImage struct {
	Repos []common.RepoSummary `json:"RepoListWithNewestImage"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type SingleImageSummary struct {
	ImageSummary common.ImageSummary `json:"Image"` //nolint:tagliatelle
}
type ImageSummaryResult struct {
	SingleImageSummary SingleImageSummary `json:"data"`
	Errors             []ErrorGQL         `json:"errors"`
}

func testSetup(t *testing.T, subpath string) error { //nolint:unparam
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

func signUsingCosign(port string) error {
	cwd, err := os.Getwd()
	So(err, ShouldBeNil)

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	digest := GetTestBlobDigest("zot-cve-test", "manifest").String()

	_ = os.Chdir(tdir)

	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s@%s", port, "zot-cve-test", digest)

	// sign the image
	return sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.RegistryOptions{AllowInsecure: true},
		map[string]interface{}{"tag": "1.0"},
		[]string{imageURL},
		"", "", true, "", "", "", false, false, "", true)
}

func signUsingNotary(port string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "notation")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	_, err = exec.LookPath("notation")
	if err != nil {
		return err
	}

	os.Setenv("XDG_CONFIG_HOME", tdir)

	// generate a keypair
	cmd := exec.Command("notation", "cert", "generate-test", "--trust", "notation-sign-test")

	err = cmd.Run()
	if err != nil {
		return err
	}

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s:%s", port, "zot-test", "0.0.1")

	cmd = exec.Command("notation", "sign", "--key", "notation-sign-test", "--plain-http", image)

	return cmd.Run()
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

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix +
			"?query={RepoListWithNewestImage{Name%20NewestImage{Tag}}}")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = os.Remove(path.Join(rootDir,
			"zot-test/blobs/sha256", GetTestBlobDigest("zot-test", "manifest").Encoded()))
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
			"zot-test/blobs/sha256/", GetTestBlobDigest("zot-test", "config").Encoded()))
		if err != nil {
			panic(err)
		}

		err = os.Remove(path.Join(rootDir,
			"zot-test/blobs/sha256", GetTestBlobDigest("zot-test", "layer").Encoded()))
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
		manifestNoAnnotations := "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"" + GetTestBlobDigest("zot-test", "manifest").String() + "\",\"size\":350}]}"
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

		substring := "\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}" //nolint:lll // gofumpt conflicts with lll
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

		query := "{ExpandedRepoInfo(repo:\"test1\"){Summary%20{Name%20LastUpdated%20Size%20Platforms%20{Os%20Arch}%20Vendors%20Score}%20Images%20{Digest%20IsSigned%20Tag%20Layers%20{Size%20Digest}}}}" //nolint: lll

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

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 422)

		query := "{ExpandedRepoInfo(repo:\"zot-cve-test\"){Summary%20{Name%20LastUpdated%20Size%20Platforms%20{Os%20Arch}%20Vendors%20Score}}}" //nolint: lll

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
		found := false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
			if m.Digest == GetTestBlobDigest("zot-cve-test", "manifest").Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, false)
			}
		}
		So(found, ShouldEqual, true)

		err = signUsingCosign(port)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
			if m.Digest == GetTestBlobDigest("zot-cve-test", "manifest").Encoded() {
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
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
			if m.Digest == GetTestBlobDigest("zot-test", "manifest").Encoded() {
				found = true
				So(m.IsSigned, ShouldEqual, false)
			}
		}
		So(found, ShouldEqual, true)

		err = signUsingNotary(port)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "/query?query=" + query)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries[0].Layers), ShouldNotEqual, 0)
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.ImageSummaries {
			if m.Digest == GetTestBlobDigest("zot-test", "manifest").Encoded() {
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
		defaultStore := local.NewImageStore(rootDir, false,
			storage.DefaultGCDelay, false, false, log, metrics, nil)

		subStore := local.NewImageStore(subRootDir, false,
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

		repoName := "test-repo" //nolint:goconst

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

		repoName = "same-layers" //nolint:goconst

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
		So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeTrue) //nolint:goconst
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

//nolint:dupl
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

		_, _, err := olu.GetImageManifest("nonexistent-repo", "latest")
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

		_, _, err := olu.GetImageManifest("test-repo", "latest") //nolint:goconst
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

		repoName := "test-repo" //nolint:goconst

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

		repoName = "same-layers" //nolint:goconst

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
		So(strings.Contains(string(resp.Body()), "same-layers"), ShouldBeTrue) //nolint:goconst
		So(strings.Contains(string(resp.Body()), "less-layers"), ShouldBeTrue)
		So(strings.Contains(string(resp.Body()), "less-layers-false"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "more-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "diff-layers"), ShouldBeFalse)
		So(strings.Contains(string(resp.Body()), "test-repo"), ShouldBeTrue) //nolint:goconst // should not list given image
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

//nolint:dupl
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

func TestGlobalSearch(t *testing.T) {
	Convey("Test global search", t, func() {
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

		query := `
			{
				GlobalSearch(query:""){
					Images {
						RepoName
						Tag
						LastUpdated
						Size
						IsSigned
						Vendor
						Score
						Platform {
							Os
							Arch
						}
						Vulnerabilities {
							Count
							MaxSeverity
						}
					}
					Repos {
						Name
						LastUpdated
						Size
						Platforms {
							Os
							Arch
						}
						Vendors
						Score
						NewestImage {
							RepoName
							Tag
							LastUpdated
							Size
							IsSigned
							Vendor
							Score
							Platform {
								Os
								Arch
							}
							Vulnerabilities {
								Count
								MaxSeverity
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

		// There are 2 repos: zot-cve-test and zot-test, each having an image with tag 0.0.1
		imageStore := ctlr.StoreController.DefaultStore

		repos, err := imageStore.GetRepositories()
		So(err, ShouldBeNil)
		expectedRepoCount := len(repos)

		allExpectedTagMap := make(map[string][]string, expectedRepoCount)
		expectedImageCount := 0
		for _, repo := range repos {
			tags, err := imageStore.GetImageTags(repo)
			So(err, ShouldBeNil)

			allExpectedTagMap[repo] = tags
			expectedImageCount += len(tags)
		}

		// Make sure the repo/image counts match before comparing actual content
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeNil)
		t.Logf("returned images: %v", responseStruct.GlobalSearchResult.GlobalSearch.Images)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, expectedImageCount)
		t.Logf("returned repos: %v", responseStruct.GlobalSearchResult.GlobalSearch.Repos)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Repos), ShouldEqual, expectedRepoCount)
		t.Logf("returned layers: %v", responseStruct.GlobalSearchResult.GlobalSearch.Layers)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Layers), ShouldNotBeEmpty)

		newestImageMap := make(map[string]common.ImageSummary)
		for _, image := range responseStruct.GlobalSearchResult.GlobalSearch.Images {
			// Make sure all returned results are supposed to be in the repo
			So(allExpectedTagMap[image.RepoName], ShouldContain, image.Tag)
			// Identify the newest image in each repo
			if newestImage, ok := newestImageMap[image.RepoName]; ok {
				if newestImage.LastUpdated.Before(image.LastUpdated) {
					newestImageMap[image.RepoName] = image
				}
			} else {
				newestImageMap[image.RepoName] = image
			}
		}
		t.Logf("expected results for newest images in repos: %v", newestImageMap)

		for _, repo := range responseStruct.GlobalSearchResult.GlobalSearch.Repos {
			image := newestImageMap[repo.Name]
			So(repo.Name, ShouldEqual, image.RepoName)
			So(repo.LastUpdated, ShouldEqual, image.LastUpdated)
			So(repo.Size, ShouldEqual, image.Size)
			So(repo.Vendors[0], ShouldEqual, image.Vendor)
			So(repo.Platforms[0].Os, ShouldEqual, image.Platform.Os)
			So(repo.Platforms[0].Arch, ShouldEqual, image.Platform.Arch)
			So(repo.NewestImage.RepoName, ShouldEqual, image.RepoName)
			So(repo.NewestImage.Tag, ShouldEqual, image.Tag)
			So(repo.NewestImage.LastUpdated, ShouldEqual, image.LastUpdated)
			So(repo.NewestImage.Size, ShouldEqual, image.Size)
			So(repo.NewestImage.IsSigned, ShouldEqual, image.IsSigned)
			So(repo.NewestImage.Vendor, ShouldEqual, image.Vendor)
			So(repo.NewestImage.Platform.Os, ShouldEqual, image.Platform.Os)
			So(repo.NewestImage.Platform.Arch, ShouldEqual, image.Platform.Arch)
			So(repo.NewestImage.Vulnerabilities.Count, ShouldEqual, 0)
			So(repo.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "")
		}

		// GetRepositories fail

		err = os.Chmod(rootDir, 0o333)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Errors, ShouldNotBeEmpty)
		err = os.Chmod(rootDir, 0o777)
		So(err, ShouldBeNil)
	})

	Convey("Test global search with vulnerabitity scanning enabled", t, func() {
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

		// Wait for trivy db to download
		substring := "\"Extensions\":{\"Search\":{\"CVE\":{\"UpdateInterval\":3600000000000},\"Enable\":true},\"Sync\":null,\"Metrics\":null,\"Scrub\":null,\"Lint\":null}" //nolint:lll // gofumpt conflicts with lll
		found, err := readFileAndSearchString(logPath, substring, 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "updating the CVE database", 2*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = readFileAndSearchString(logPath, "DB update completed, next update scheduled", 4*time.Minute)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		query := `
			{
				GlobalSearch(query:""){
					Images {
						RepoName
						Tag
						LastUpdated
						Size
						IsSigned
						Vendor
						Score
						Platform {
							Os
							Arch
						}
						Vulnerabilities {
							Count
							MaxSeverity
						}
					}
					Repos {
						Name
						LastUpdated
						Size
						Platforms {
							Os
							Arch
						}
						Vendors
						Score
						NewestImage {
							RepoName
							Tag
							LastUpdated
							Size
							IsSigned
							Vendor
							Score
							Platform {
								Os
								Arch
							}
							Vulnerabilities {
								Count
								MaxSeverity
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

		// There are 2 repos: zot-cve-test and zot-test, each having an image with tag 0.0.1
		imageStore := ctlr.StoreController.DefaultStore

		repos, err := imageStore.GetRepositories()
		So(err, ShouldBeNil)
		expectedRepoCount := len(repos)

		allExpectedTagMap := make(map[string][]string, expectedRepoCount)
		expectedImageCount := 0
		for _, repo := range repos {
			tags, err := imageStore.GetImageTags(repo)
			So(err, ShouldBeNil)

			allExpectedTagMap[repo] = tags
			expectedImageCount += len(tags)
		}

		// Make sure the repo/image counts match before comparing actual content
		So(responseStruct.GlobalSearchResult.GlobalSearch.Images, ShouldNotBeNil)
		t.Logf("returned images: %v", responseStruct.GlobalSearchResult.GlobalSearch.Images)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, expectedImageCount)
		t.Logf("returned repos: %v", responseStruct.GlobalSearchResult.GlobalSearch.Repos)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Repos), ShouldEqual, expectedRepoCount)
		t.Logf("returned layers: %v", responseStruct.GlobalSearchResult.GlobalSearch.Layers)
		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Layers), ShouldNotBeEmpty)

		newestImageMap := make(map[string]common.ImageSummary)
		for _, image := range responseStruct.GlobalSearchResult.GlobalSearch.Images {
			// Make sure all returned results are supposed to be in the repo
			So(allExpectedTagMap[image.RepoName], ShouldContain, image.Tag)
			// Identify the newest image in each repo
			if newestImage, ok := newestImageMap[image.RepoName]; ok {
				if newestImage.LastUpdated.Before(image.LastUpdated) {
					newestImageMap[image.RepoName] = image
				}
			} else {
				newestImageMap[image.RepoName] = image
			}
		}
		t.Logf("expected results for newest images in repos: %v", newestImageMap)

		for _, repo := range responseStruct.GlobalSearchResult.GlobalSearch.Repos {
			image := newestImageMap[repo.Name]
			So(repo.Name, ShouldEqual, image.RepoName)
			So(repo.LastUpdated, ShouldEqual, image.LastUpdated)
			So(repo.Size, ShouldEqual, image.Size)
			So(repo.Vendors[0], ShouldEqual, image.Vendor)
			So(repo.Platforms[0].Os, ShouldEqual, image.Platform.Os)
			So(repo.Platforms[0].Arch, ShouldEqual, image.Platform.Arch)
			So(repo.NewestImage.RepoName, ShouldEqual, image.RepoName)
			So(repo.NewestImage.Tag, ShouldEqual, image.Tag)
			So(repo.NewestImage.LastUpdated, ShouldEqual, image.LastUpdated)
			So(repo.NewestImage.Size, ShouldEqual, image.Size)
			So(repo.NewestImage.IsSigned, ShouldEqual, image.IsSigned)
			So(repo.NewestImage.Vendor, ShouldEqual, image.Vendor)
			So(repo.NewestImage.Platform.Os, ShouldEqual, image.Platform.Os)
			So(repo.NewestImage.Platform.Arch, ShouldEqual, image.Platform.Arch)
			t.Logf("Found vulnerability summary %v", repo.NewestImage.Vulnerabilities)
			So(repo.NewestImage.Vulnerabilities.Count, ShouldEqual, image.Vulnerabilities.Count)
			So(repo.NewestImage.Vulnerabilities.Count, ShouldBeGreaterThan, 1)
			So(repo.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, image.Vulnerabilities.MaxSeverity)
			// This really depends on the test data, but with the current test images it's CRITICAL
			So(repo.NewestImage.Vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")
		}

		// GetRepositories fail

		err = os.Chmod(rootDir, 0o333)
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(responseStruct.Errors, ShouldNotBeEmpty)
		err = os.Chmod(rootDir, 0o777)
		So(err, ShouldBeNil)
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

		isSigned := false

		imageSummary := search.BuildImageInfo(invalid, invalid, manifestDigest, manifest,
			imageConfig, isSigned)

		So(len(imageSummary.Layers), ShouldEqual, len(manifest.Layers))
		imageSummaryLayerSize, err := strconv.Atoi(*imageSummary.Size)
		So(err, ShouldBeNil)
		So(imageSummaryLayerSize, ShouldEqual, manifestLayersSize)
	})
}

func TestBaseOciLayoutUtils(t *testing.T) {
	manifestDigest := GetTestBlobDigest("zot-test", "config").String()

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
				GlobalSearch(query:"test"){
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
		So(size, ShouldAlmostEqual, configSize+layersSize+manifestSize)

		repo := responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldAlmostEqual, configSize+layersSize+manifestSize)

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

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(err, ShouldBeNil)
		So(configSize+layersSize+manifestSize, ShouldNotBeZeroValue)

		responseStruct = &GlobalSearchResultResp{}
		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		So(len(responseStruct.GlobalSearchResult.GlobalSearch.Images), ShouldEqual, 2)
		// check that the repo size is the same
		repo = responseStruct.GlobalSearchResult.GlobalSearch.Repos[0]
		size, err = strconv.Atoi(repo.Size)
		So(err, ShouldBeNil)
		So(size, ShouldAlmostEqual, configSize+layersSize+manifestSize)
	})
}

func TestImageSummary(t *testing.T) {
	Convey("GraphQL query ImageSummary", t, func() {
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

		gqlQuery := `
			{
				Image(image:"%s:%s"){
					RepoName,
					Tag,
					Digest,
					ConfigDigest,
					LastUpdated,
					IsSigned,
					Size
					Layers { Digest Size }
				}
			}`

		gqlEndpoint := fmt.Sprintf("%s%s?query=", baseURL, graphqlQueryPrefix)
		config, layers, manifest, err := GetImageComponents(100)
		So(err, ShouldBeNil)

		configBlob, errConfig := json.Marshal(config)
		configDigest := digest.FromBytes(configBlob)
		So(errConfig, ShouldBeNil) // marshall success, config is valid JSON
		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		manifestBlob, errMarsal := json.Marshal(manifest)
		So(errMarsal, ShouldBeNil)
		So(manifestBlob, ShouldNotBeNil)
		manifestDigest := digest.FromBytes(manifestBlob)
		repoName := "test-repo" //nolint:goconst

		tagTarget := "latest"
		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
				Tag:      tagTarget,
			},
			baseURL,
			repoName,
		)
		So(err, ShouldBeNil)
		var (
			imgSummaryResponse ImageSummaryResult
			strQuery           string
			targetURL          string
			resp               *resty.Response
		)

		t.Log("starting Test retrieve image based on image identifier")
		// gql is parametrized with the repo.
		strQuery = fmt.Sprintf(gqlQuery, repoName, tagTarget)
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)

		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary.ImageSummary, ShouldNotBeNil)

		imgSummary := imgSummaryResponse.SingleImageSummary.ImageSummary
		So(imgSummary.RepoName, ShouldContainSubstring, repoName)
		So(imgSummary.ConfigDigest, ShouldContainSubstring, configDigest.Hex())
		So(imgSummary.Digest, ShouldContainSubstring, manifestDigest.Hex())
		So(len(imgSummary.Layers), ShouldEqual, 1)
		So(imgSummary.Layers[0].Digest, ShouldContainSubstring,
			digest.FromBytes(layers[0]).Hex())

		t.Log("starting Test retrieve duplicated image same layers based on image identifier")
		// gqlEndpoint
		strQuery = fmt.Sprintf(gqlQuery, "wrong-repo-does-not-exist", "latest")
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary.ImageSummary, ShouldNotBeNil)

		So(len(imgSummaryResponse.Errors), ShouldEqual, 1)
		So(imgSummaryResponse.Errors[0].Message,
			ShouldContainSubstring, "repository: not found")

		t.Log("starting Test retrieve image with bad tag")
		// gql is parametrized with the repo.
		strQuery = fmt.Sprintf(gqlQuery, repoName, "nonexisttag")
		targetURL = fmt.Sprintf("%s%s", gqlEndpoint, url.QueryEscape(strQuery))

		resp, err = resty.R().Get(targetURL)
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		So(resp.Body(), ShouldNotBeNil)
		err = json.Unmarshal(resp.Body(), &imgSummaryResponse)
		So(err, ShouldBeNil)
		So(imgSummaryResponse, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary, ShouldNotBeNil)
		So(imgSummaryResponse.SingleImageSummary.ImageSummary, ShouldNotBeNil)

		So(len(imgSummaryResponse.Errors), ShouldEqual, 1)
		So(imgSummaryResponse.Errors[0].Message,
			ShouldContainSubstring, "manifest: not found")
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
