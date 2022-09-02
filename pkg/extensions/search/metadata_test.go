package search_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"testing"
	"time"

	"github.com/mitchellh/mapstructure"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/storage"

	// . "zotregistry.io/zot/pkg/test"

	// "zotregistry.io/zot/pkg/api/config"
	// "zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/test"
)

const (
	graphqlQueryPrefix = constants.ExtSearchPrefix
)

// nolint:gochecknoglobals
var (
	rootDir    string
	subRootDir string
)

type RepoSummary struct {
	Name        string       `json:"name"`
	LastUpdated time.Time    `json:"lastUpdated"`
	Size        string       `json:"size"`
	Platforms   []OsArch     `json:"platforms"`
	Vendors     []string     `json:"vendors"`
	Score       int          `json:"score"`
	NewestImage ImageSummary `json:"newestImage"`
}

type OsArch struct {
	Os   string `json:"os"`
	Arch string `json:"arch"`
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

type PaginatedReposResultResp struct {
	data   RepoResults `json:"data"`
	Errors []ErrorGQL  `json:"errors"`
}

type RepoResults struct {
	Repos []RepoSummary `json:"repos"`
}

func parseBearerAuthHeader(authHeaderRaw string) *authHeader {
	re := regexp.MustCompile(`([a-zA-z]+)="(.+?)"`)
	matches := re.FindAllStringSubmatch(authHeaderRaw, -1)
	matchmap := make(map[string]string)

	for i := 0; i < len(matches); i++ {
		matchmap[matches[i][1]] = matches[i][2]
	}

	var h authHeader
	if err := mapstructure.Decode(matchmap, &h); err != nil {
		panic(err)
	}

	return &h
}

type ImgResponsWithLatestTag struct {
	ImgListWithLatestTag ImgListWithLatestTag `json:"data"`
	Errors               []ErrorGQL           `json:"errors"`
}

type ImgListWithLatestTag struct {
	Images []ImageInfo `json:"ImageListWithLatestTag"`
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

type (
	accessTokenResponse struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // token format
	}

	authHeader struct {
		Realm   string
		Service string
		Scope   string
	}
)

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

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}

func TestMetadataE2E(t *testing.T) {
	Convey("Two creds", t, func() {
		subpath := "/a"
		twoCredTests := []string{}
		user1 := "alicia"
		password1 := "aliciapassword"
		user2 := "bob"
		password2 := "robert"
		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n"+
			getCredString(user2, password2))

		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n"+
			getCredString(user2, password2)+"\n")

		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n\n"+
			getCredString(user2, password2)+"\n\n")

		for _, testString := range twoCredTests {
			func() {
				port := test.GetFreePort()
				baseURL := test.GetBaseURL(port)
				conf := config.New()
				conf.Storage.RootDirectory = rootDir
				conf.Storage.SubPaths = make(map[string]config.StorageConfig)
				conf.Storage.SubPaths[subpath] = config.StorageConfig{RootDirectory: subRootDir}
				defaultVal := true
				conf.Extensions = &extconf.ExtensionConfig{
					Search: &extconf.SearchConfig{Enable: &defaultVal},
				}

				conf.Extensions.Search.CVE = nil
				conf.HTTP.Port = port
				htpasswdPath := test.MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := api.NewController(conf)
				ctlr.Config.Storage.RootDirectory = t.TempDir()

				go startServer(ctlr)
				defer stopServer(ctlr)
				time.Sleep(1 * time.Second)
				test.WaitTillServerReady(baseURL)

				// url := fmt.Sprintf("%s/%s", baseURL, graphqlQueryPrefix)
				// with creds, should get expected status code
				// resp, _ := resty.R().SetBasicAuth(user1, password1).Get(url)
				// // http://127.0.0.1:44075//v2/_zot/ext/search
				// So(resp, ShouldNotBeNil)
				// So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// resp, _ := resty.R().SetBasicAuth(user2, password2).Get(fmt.Sprintf("%s/v2/%s", baseURL, graphqlQueryPrefix))
				// So(resp, ShouldNotBeNil)
				// So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// // with invalid creds, it should fail
				// resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(fmt.Sprintf("%s/v2/%s", baseURL, graphqlQueryPrefix))
				// So(resp, ShouldNotBeNil)
				// So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

				resty.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))
				resp, err := resty.R().SetBasicAuth(user1, password1).Get(
					fmt.Sprintf("%s%s?query=%s", baseURL, graphqlQueryPrefix,
						url.QueryEscape("{StarredRepos{Results{RepoSummary{RepoName}}}}")))
				So(resp, ShouldNotBeNil)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
				var pagRes PaginatedReposResultResp
				var repos RepoResults

				err = json.Unmarshal(resp.Body(), &pagRes)
				repos = pagRes.data
				So(err, ShouldBeNil)
				for _, val := range repos.Repos {

					So(val, ShouldNotBeBlank)
				}
			}()
		}
	})
}

func TestGetEmptyUser(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		t.Helper()

		srcConfig := config.New()
		sctlr := api.NewController(srcConfig)
		sctlr.StoreController.NonOciMetadata = storage.NewMetaStore(
			srcConfig.Storage.RootDirectory, "users", sctlr.Log.Logger)
		brepos, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos("")
		So(brepos, ShouldEqual, []string{})
		So(err, ShouldBeNil)
	})
}

func TestGetExistingUser(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		t.Helper()

		srcConfig := config.New()
		sctlr := api.NewController(srcConfig)
		sctlr.StoreController.NonOciMetadata = storage.NewMetaStore(
			srcConfig.Storage.RootDirectory, "users", sctlr.Log.Logger)
		brepos, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos("test")
		So(brepos, ShouldEqual, []string{})
		So(err, ShouldBeNil)

		sctlr.StoreController.NonOciMetadata.ToggleBookmarkRepo("test", "golang")
		brepos2, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos("test")
		So(brepos2, ShouldEqual, []string{"golang"})
		So(err, ShouldBeNil)

		sctlr.StoreController.NonOciMetadata.ToggleBookmarkRepo("test", "golang")
		brepos3, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos("test")
		So(brepos3, ShouldEqual, []string{})
		So(err, ShouldBeNil)
	})
}
