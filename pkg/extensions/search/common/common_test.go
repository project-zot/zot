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
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
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
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	graphqlQueryPrefix = constants.ExtSearchPrefix
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
	RepoName    string    `json:"repoName"`
	Tag         string    `json:"tag"`
	LastUpdated time.Time `json:"lastUpdated"`
	Size        string    `json:"size"`
	Platform    OsArch    `json:"platform"`
	Vendor      string    `json:"vendor"`
	Score       int       `json:"score"`
	IsSigned    bool      `json:"isSigned"`
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

func signUsingCosign(port string) error {
	cwd, err := os.Getwd()
	So(err, ShouldBeNil)

	defer func() { _ = os.Chdir(cwd) }()

	tdir, err := os.MkdirTemp("", "cosign")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tdir)

	_ = os.Chdir(tdir)

	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
	if err != nil {
		return err
	}

	imageURL := fmt.Sprintf("localhost:%s/%s@%s", port, "zot-cve-test",
		"sha256:63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29")

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
		found := false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == "63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29" {
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == "63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29" {
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
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == "2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396" {
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
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images), ShouldNotEqual, 0)
		So(len(responseStruct.ExpandedRepoInfo.RepoInfo.Images[0].Layers), ShouldNotEqual, 0)
		found = false
		for _, m := range responseStruct.ExpandedRepoInfo.RepoInfo.Images {
			if m.Digest == "2bacca16b9df395fc855c14ccf50b12b58d35d468b8e7f25758aff90f89bf396" {
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

func TestGlobalSearch(t *testing.T) {
	Convey("Test utils", t, func() {
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

		newestImageMap := make(map[string]ImageSummary)
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
