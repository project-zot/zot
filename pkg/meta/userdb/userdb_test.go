package userdb_test

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	msConfig "zotregistry.io/zot/pkg/meta/config"
	userdb "zotregistry.io/zot/pkg/meta/userdb"
	"zotregistry.io/zot/pkg/test"
)

const (
	simpleUserStars = `
		query UserStarRepos {
		StarredRepos {
			Results {
				Name
				StarCount
				IsBookmarked
				IsStarred
				NewestImage {Digest}
				}
			}
		}
	`

	allRepos = `
		query allRepos {
			RepoListWithNewestImage{
				Results {
					Name
					NewestImage{
						Tag
					}
				}
			}
		}
	`

	starMutationCall = `
		mutation FlipStarForTestRepo {
			ToggleStar(repo: "%s") {
					success
			}
		}
	`
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
	// data   RepoResults `json:"data"`.
	Errors []ErrorGQL `json:"errors"`
}

type RepoResults struct {
	Repos []RepoSummary `json:"repos"`
}

type ImgResponsWithLatestTag struct {
	ImgListWithLatestTag ImgListWithLatestTag `json:"data"`
	Errors               []ErrorGQL           `json:"errors"`
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
	RepoName    string
	Tag         string
	LastUpdated time.Time
	Description string
	Licenses    string
	Vendor      string
	Size        string
	Labels      string
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

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}

func TestGetExistingUser(t *testing.T) {
	Convey("Create User metadata DB", t, func(c C) {
		srcConfig := config.New()
		srcConfig.Extensions = &extconf.ExtensionConfig{}
		enable := true
		srcConfig.Extensions.Metadata = &msConfig.MetadataStoreConfig{
			User: &msConfig.UserMetadataStoreConfig{
				RootDir: t.TempDir(),
				Driver:  "local",
				Enabled: &enable,
			},
		}

		Convey("Default metadata settings", func(c C) {
			*srcConfig.Extensions.Metadata.User.Enabled = false
			sctlr := api.NewController(srcConfig)
			So(sctlr, ShouldNotBeNil)
			sctlr.MetaStore = sctlr.CreateMetadataDatabaseDriver(srcConfig, sctlr.Log)
			So(sctlr.MetaStore, ShouldNotBeNil)
			_, err := os.Stat("users.db")
			So(err, ShouldNotBeNil)
		})

		Convey("Retrieve starred repos for simulated user without initial user metadata", func(c C) {
			t.Helper()
			sctlr := api.NewController(srcConfig)
			So(sctlr, ShouldNotBeNil)
			sctlr.MetaStore = sctlr.CreateMetadataDatabaseDriver(srcConfig, sctlr.Log)
			So(sctlr.MetaStore, ShouldNotBeNil)
			_, err := os.Stat(path.Join(srcConfig.Extensions.Metadata.User.RootDir, "users.db"))
			So(err, ShouldNotBeNil)

			simulatedUser := "test"
			reponame := "golang"
			repo2name := "alpine"
			// GetStarredRepos: first pass
			brepos, err := sctlr.MetaStore.GetStarredRepos(simulatedUser)
			So(err, ShouldBeNil)
			So(brepos, ShouldResemble, []string{})

			res, err := sctlr.MetaStore.ToggleStarRepo(simulatedUser, reponame)
			So(res, ShouldEqual, msConfig.Added)
			So(err, ShouldBeNil)
			brepos2, err := sctlr.MetaStore.GetStarredRepos(simulatedUser)
			So(brepos2, ShouldResemble, []string{reponame})
			So(err, ShouldBeNil)

			// GetBookmarkedRepos: first pass
			brepos3, err := sctlr.MetaStore.GetBookmarkedRepos(simulatedUser)
			So(brepos3, ShouldResemble, []string{})
			So(err, ShouldBeNil)

			res, err = sctlr.MetaStore.ToggleBookmarkRepo(simulatedUser, repo2name)
			So(err, ShouldBeNil)
			So(res, ShouldEqual, msConfig.Added)

			brepos4, err := sctlr.MetaStore.GetBookmarkedRepos(simulatedUser)
			So(brepos4, ShouldResemble, []string{repo2name})
			So(err, ShouldBeNil)

			// GetStarredRepos: second pass
			brepos5, err := sctlr.MetaStore.GetStarredRepos(simulatedUser)
			So(brepos5, ShouldResemble, []string{reponame})
			So(err, ShouldBeNil)

			res, err = sctlr.MetaStore.ToggleStarRepo(simulatedUser, reponame)
			So(err, ShouldBeNil)
			So(res, ShouldEqual, msConfig.Removed)

			brepos6, err := sctlr.MetaStore.GetStarredRepos(simulatedUser)
			So(brepos6, ShouldResemble, []string{})
			So(err, ShouldBeNil)

			// GetStarredRepos: second pass
			brepos7, err := sctlr.MetaStore.GetBookmarkedRepos(simulatedUser)
			So(brepos7, ShouldResemble, []string{repo2name})
			So(err, ShouldBeNil)

			res, err = sctlr.MetaStore.ToggleBookmarkRepo(simulatedUser, repo2name)
			So(err, ShouldBeNil)
			So(res, ShouldEqual, msConfig.Removed)

			brepos8, err := sctlr.MetaStore.GetBookmarkedRepos(simulatedUser)
			So(brepos8, ShouldResemble, []string{})
			So(err, ShouldBeNil)
		})
	})
}

func TestUserMetadata(t *testing.T) {
	startOfTest := time.Now()
	zotServerRoot := t.TempDir()

	Convey("UserMetadata", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort() // "8080"
		// conf.HTTP.Address = "172.24.56.23"

		baseURL := fmt.Sprintf("http://%s", net.JoinHostPort(conf.HTTP.Address, port))
		conf.HTTP.Port = port
		conf.HTTP.AllowOrigin = "*"
		conf.Log.Level = "debug"
		conf.Log.Output = fmt.Sprintf(filepath.Join(zotServerRoot, "zot%s.log"),
			startOfTest.Local().Format("20060201_150405"))
		So(conf.Log.Output, ShouldNotBeEmpty)
		So(conf.Log.Output, ShouldNotContainSubstring, " ")

		tempDir := t.TempDir() // "/tmp/zotd/root"
		conf.Storage.RootDirectory = tempDir
		err := test.CopyFiles("../../../test/data", tempDir)
		So(err, ShouldBeNil)

		repoName := "zot-cve-test"
		inaccessibleRepo := "zot-test"
		defaultVal := true

		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{
					Enable: &defaultVal,
				},
			},
			Metadata: &msConfig.MetadataStoreConfig{
				User: &msConfig.UserMetadataStoreConfig{
					RootDir: tempDir,
					Driver:  msConfig.UserMetadataLocalDriver,
					Enabled: &defaultVal,
				},
			},
		}

		adminUser := "alice"
		adminPassword := "deepGoesTheRabbitBurrow"
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
				"**": config.PolicyGroup{
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
		clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

		resp0, err0 := clientHTTP.Get(
			fmt.Sprintf("%s%s?query=%s",
				baseURL,
				constants.FullSearchPrefix,
				url.QueryEscape(allRepos)))
		So(err0, ShouldBeNil)
		So(resp0, ShouldNotBeNil)
		So(resp0.Body(), ShouldNotBeNil)
		So(string(resp0.Body()), ShouldNotEqual, "")
		So(resp0.StatusCode(), ShouldEqual, 200)

		Convey("Flip Starred Repos in Usermetadata Authorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp0, err0 := clientHTTP.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.FullSearchPrefix,
					url.QueryEscape(simpleUserStars)))

			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.Body(), ShouldNotBeNil)
			So(string(resp0.Body()), ShouldNotEqual, "")
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.FullSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": fmt.Sprintf(starMutationCall, repoName),
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldContainSubstring, "\"success\":true")

			resp2, err2 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.FullSearchPrefix,
					url.QueryEscape(simpleUserStars)),
			)
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldContainSubstring, repoName)

			resp3, err3 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": fmt.Sprintf(starMutationCall, repoName),
				}).
				Post(urlTarget)
			So(err3, ShouldBeNil)
			So(resp3, ShouldNotBeNil)
			So(resp3.StatusCode(), ShouldEqual, 200)
			So(string(resp3.Body()), ShouldContainSubstring, "\"success\":true")

			resp4, err4 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(simpleUserStars))
			So(err4, ShouldBeNil)
			So(resp4, ShouldNotBeNil)
			So(resp4.StatusCode(), ShouldEqual, 200)

			So(string(resp4.Body()), ShouldNotContainSubstring, repoName)
		})

		Convey("Flip Starred Repos in Usermetadata with Unauthorized Repo", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)
			resp0, err0 := clientHTTP.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.FullSearchPrefix,
					url.QueryEscape(simpleUserStars)))
			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.FullSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).
				SetBody(map[string]string{
					"query": fmt.Sprintf(starMutationCall, inaccessibleRepo),
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldContainSubstring,
				"resource does not exist or you are not authorized to see it")

			resp2, err2 := resty.R().SetBasicAuth(simpleUser, simpleUserPassword).Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(simpleUserStars))
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldNotContainSubstring, inaccessibleRepo)
		})

		Convey("Flip Starred Repos in Usermetadata with Unauthorized Repo & admin user", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(adminUser, adminPassword)
			resp0, err0 := clientHTTP.Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.FullSearchPrefix,
					url.QueryEscape(simpleUserStars)))
			So(err0, ShouldBeNil)
			So(resp0, ShouldNotBeNil)
			So(resp0.StatusCode(), ShouldEqual, 200)

			urlTarget := fmt.Sprintf("%s%s",
				baseURL,
				constants.FullSearchPrefix,
			)

			resp1, err1 := resty.R().SetBasicAuth(adminUser, adminPassword).
				SetBody(map[string]string{
					"query": fmt.Sprintf(starMutationCall, inaccessibleRepo),
				}).
				Post(urlTarget)
			So(err1, ShouldBeNil)
			So(resp1, ShouldNotBeNil)
			So(resp1.StatusCode(), ShouldEqual, 200)
			So(string(resp1.Body()), ShouldNotContainSubstring,
				"repo does not exist or you are not authorized to see it")

			resp2, err2 := resty.R().SetBasicAuth(adminUser, adminPassword).Get(
				fmt.Sprintf("%s%s?query=%s",
					baseURL,
					constants.FullSearchPrefix,
					url.QueryEscape(simpleUserStars)))
			So(err2, ShouldBeNil)
			So(resp2, ShouldNotBeNil)
			So(resp2.StatusCode(), ShouldEqual, 200)

			So(string(resp2.Body()), ShouldContainSubstring, inaccessibleRepo)
		})
	})
}

func TestUserConfigNegative(t *testing.T) {
	Convey("Cannot create User metadata - config disabled ", t, func() {
		t.Helper()

		srcConfig := config.New()
		srcConfig.Storage.RootDirectory = t.TempDir()
		sctlr := api.NewController(srcConfig)
		enabled := false
		mstore, err := userdb.FactoryUserMetadataStore(&msConfig.UserMetadataStoreConfig{
			RootDir: srcConfig.Storage.RootDirectory,
			Driver:  "local",
			Enabled: &enabled,
		}, sctlr.Log)

		So(mstore, ShouldNotBeNil)
		So(err, ShouldBeNil)

		brepos, err := mstore.GetBookmarkedRepos("")
		So(brepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)

		srepos, err := mstore.GetStarredRepos("")
		So(srepos, ShouldResemble, []string{})
		So(err, ShouldBeNil)
	})
}
