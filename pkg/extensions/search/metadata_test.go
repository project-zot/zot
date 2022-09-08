package search_test

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"net/url"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/api/constants"
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

func TestGetEmptyUser(t *testing.T) {
	Convey("Retrieve starred repos for empty user", t, func() {
		t.Helper()

		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = "/tmp/zotd/root"
		sctlr := api.NewController(srcConfig)
		sctlr.StoreController.NonOciMetadata = storage.NewMetaStore(
			srcConfig.Storage.RootDirectory, "users", sctlr.Log.Logger)
		brepos, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos("")
		So(brepos, ShouldResemble, []string(nil))
		So(err, ShouldBeNil)
	})
}

func TestGetExistingUser(t *testing.T) {
	Convey("Create User metadata DB", t, func(c C) {
		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = t.TempDir()
		sctlr := api.NewController(srcConfig)
		sctlr.CreateMetadataDatabaseDriver(srcConfig, sctlr.Log)
		So(sctlr.StoreController.NonOciMetadata, ShouldNotBeNil)
		_, err := os.Stat("users.db")
		So(err, ShouldNotBeNil)
		// sctlr.StoreController.NonOciMetadata = storage.NewMetaStore(
		// 	srcConfig.Storage.RootDirectory, "users", sctlr.Log.Logger)

		Convey("Retrieve starred repos for simulated user without initial user metadata", func(c C) {
			t.Helper()

			simulatedUser := "test"
			reponame := "golang"
			repo2name := "alpine"
			brepos, err := sctlr.StoreController.NonOciMetadata.GetStarredRepos(simulatedUser)
			So(brepos, ShouldResemble, []string(nil))
			So(err, ShouldBeNil)

			err = sctlr.StoreController.NonOciMetadata.ToggleStarRepo(simulatedUser, reponame)
			So(err, ShouldBeNil)
			brepos2, err := sctlr.StoreController.NonOciMetadata.GetStarredRepos(simulatedUser)
			So(brepos2, ShouldResemble, []string{reponame})
			So(err, ShouldBeNil)

			brepos3, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos(simulatedUser)
			So(brepos3, ShouldResemble, []string(nil))
			So(err, ShouldBeNil)
			err = sctlr.StoreController.NonOciMetadata.ToggleBookmarkRepo(simulatedUser, repo2name)
			So(err, ShouldBeNil)
			brepos4, err := sctlr.StoreController.NonOciMetadata.GetBookmarkedRepos(simulatedUser)
			So(brepos4, ShouldResemble, []string{repo2name})
			So(err, ShouldBeNil)

			brepos5, err := sctlr.StoreController.NonOciMetadata.GetStarredRepos(simulatedUser)
			So(brepos5, ShouldResemble, []string{reponame})
			So(err, ShouldBeNil)

			err = sctlr.StoreController.NonOciMetadata.ToggleStarRepo(simulatedUser, reponame)
			So(err, ShouldBeNil)
			brepos6, err := sctlr.StoreController.NonOciMetadata.GetStarredRepos(simulatedUser)
			So(brepos6, ShouldResemble, []string(nil)) // Nil or empty? []string{}
			So(err, ShouldBeNil)

		})
	})
}

func TestUserMetadata(t *testing.T) {
	Convey("UserMetadata", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort() // "8080"
		// conf.HTTP.Address = "172.24.56.23"
		baseURL := fmt.Sprintf("http://%s:%s", conf.HTTP.Address, port) // test.GetBaseURL(port)
		conf.HTTP.Port = port
		conf.HTTP.AllowOrigin = "*"

		tempDir := t.TempDir() // "/tmp/zotd/root"
		conf.Storage.RootDirectory = tempDir

		err := test.CopyFiles("../../test/data", tempDir)
		if err != nil {
			panic(err)
		}

		repoName := "zot-cve-test"
		inaccessibleRepo := "zot-test"

		defaultVal := true

		searchConfig := &extconf.SearchConfig{
			Enable: &defaultVal,
		}

		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		adminUser := "alice"
		adminPassword := "deepGoesTheRabbitHole"
		simpleUser := "test"
		simpleUserPassword := "test123"
		twoCredTests := fmt.Sprintf("%s\n%s\n\n", getCredString(adminUser, adminPassword),
			getCredString(simpleUser, simpleUserPassword))

		htpasswdPath := test.MakeHtpasswdFileFromString(twoCredTests)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				repoName: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{simpleUser},
							Actions: []string{"read"},
						},
					},
					DefaultPolicy: []string{},
				},
				inaccessibleRepo: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{},
							Actions: []string{},
						},
					},
					DefaultPolicy: []string{},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{adminUser},
				Actions: []string{"read", "create", "update"},
			},
		}

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		Convey("Flip Starred Repos in Usermetadata Authorized", func(c C) {
			query := `
				query UserStarRepos {
				StarredRepos(offset: 0) {
					Results {
						Name
						}
					}
				}
			`

			mutationCall := fmt.Sprintf(`
				mutation FlipStarForTestRepo {
					ToggleStar(repo: "%s") {
							success
					}
				}
			`, repoName)
			clientHttp := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)
			resp0, err0 := clientHttp.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.ExtSearchPrefix,
					url.QueryEscape(query)))
			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.ExtSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": mutationCall,
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldContainSubstring, "\"success\":true")

			resp2, err2 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(baseURL + constants.ExtSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldContainSubstring, repoName)

			resp3, err3 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": mutationCall,
				}).
				Post(urlTarget)
			So(err3, ShouldBeNil)
			So(resp3, ShouldNotBeNil)
			So(resp3.StatusCode(), ShouldEqual, 200)
			So(string(resp3.Body()), ShouldContainSubstring, "\"success\":true")

			resp4, err4 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(baseURL + constants.ExtSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err4, ShouldBeNil)
			So(resp4, ShouldNotBeNil)
			So(resp4.StatusCode(), ShouldEqual, 200)

			So(string(resp4.Body()), ShouldNotContainSubstring, repoName)
		})

		Convey("Flip Starred Repos in Usermetadata with Unauthorized Repo", func(c C) {
			query := `
				query UserStarRepos {
				StarredRepos(offset: 0) {
					Results {
						Name
						}
					}
				}
			`
			mutationCall := fmt.Sprintf(`
				mutation FlipStarForTestRepo {
					ToggleStar(repo: "%s") {
							success
					}
				}
			`, inaccessibleRepo)

			clientHttp := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)
			resp0, err0 := clientHttp.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.ExtSearchPrefix,
					url.QueryEscape(query)))
			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.ExtSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": mutationCall,
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldContainSubstring,
				"repo does not exist or you are not authorized to see it")

			resp2, err2 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(baseURL + constants.ExtSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldNotContainSubstring, inaccessibleRepo)
		})

		Convey("Flip Starred Repos in Usermetadata with Unauthorized Repo & admin user", func(c C) {
			query := `
				query UserStarRepos {
				StarredRepos(offset: 0) {
					Results {
						Name
						}
					}
				}
			`
			mutationCall := fmt.Sprintf(`
				mutation FlipStarForTestRepo {
					ToggleStar(repo: "%s") {
							success
					}
				}
			`, inaccessibleRepo)

			clientHttp := resty.R().SetBasicAuth(adminUser, adminPassword)
			resp0, err0 := clientHttp.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.ExtSearchPrefix,
					url.QueryEscape(query)))
			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.ExtSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(adminUser, adminPassword).
				SetBody(map[string]string{
					"query": mutationCall,
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldNotContainSubstring,
				"repo does not exist or you are not authorized to see it")

			resp2, err2 := resty.R().SetBasicAuth(adminUser, adminPassword).Get(baseURL + constants.ExtSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldContainSubstring, inaccessibleRepo)
		})
	})
}
