//go:build search && userprefs

package search_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test"
)

//nolint:dupl
func TestUserData(t *testing.T) {
	Convey("Test user stars and bookmarks", t, func(c C) {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		defaultVal := true

		accessibleRepo := "accessible-repo"
		forbiddenRepo := "forbidden-repo"
		tag := "0.0.1"

		adminUser := "alice"
		adminPassword := "deepGoesTheRabbitBurrow"
		simpleUser := "test"
		simpleUserPassword := "test123"

		twoCredTests := fmt.Sprintf("%s\n%s\n\n", getCredString(adminUser, adminPassword),
			getCredString(simpleUser, simpleUserPassword))

		htpasswdPath := MakeHtpasswdFileFromString(twoCredTests)
		defer os.Remove(htpasswdPath)

		conf := config.New()
		conf.Storage.RootDirectory = t.TempDir()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{simpleUser},
							Actions: []string{"read"},
						},
					},
					AnonymousPolicy: []string{"read"},
					DefaultPolicy:   []string{},
				},
				forbiddenRepo: config.PolicyGroup{
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
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		config, layers, manifest, err := GetImageComponents(100)
		So(err, ShouldBeNil)

		err = UploadImageWithBasicAuth(
			Image{
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: tag,
			}, baseURL, accessibleRepo,
			adminUser, adminPassword,
		)
		So(err, ShouldBeNil)

		err = UploadImageWithBasicAuth(
			Image{
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: tag,
			}, baseURL, forbiddenRepo,
			adminUser, adminPassword,
		)
		So(err, ShouldBeNil)

		userStaredReposQuery := `{
			StarredRepos {
				Results {
					Name StarCount IsStarred
					NewestImage { Tag }
				}
			}
		}`

		userBookmarkedReposQuery := `{
			BookmarkedRepos {
				Results {
					Name IsBookmarked
					NewestImage { Tag }
				}
			}
		}`

		userprefsBaseURL := baseURL + constants.FullUserPreferencesPrefix

		Convey("Flip starred repo authorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 1)
			So(responseStruct.Results[0].Name, ShouldEqual, accessibleRepo)
			// need to update RepoSummary according to user settings
			So(responseStruct.Results[0].IsStarred, ShouldEqual, true)
			So(responseStruct.Results[0].StarCount, ShouldEqual, 1)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip starred repo unauthenticated user", func(c C) {
			clientHTTP := resty.R()

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip starred repo unauthorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip starred repo with unauthorized repo and admin user", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(adminUser, adminPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 1)
			So(responseStruct.Results[0].Name, ShouldEqual, forbiddenRepo)
			// need to update RepoSummary according to user settings
			So(responseStruct.Results[0].IsStarred, ShouldEqual, true)
			So(responseStruct.Results[0].StarCount, ShouldEqual, 1)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoStarURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = StarredReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip bookmark repo authorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 1)
			So(responseStruct.Results[0].Name, ShouldEqual, accessibleRepo)
			// need to update RepoSummary according to user settings
			So(responseStruct.Results[0].IsBookmarked, ShouldEqual, true)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip bookmark repo unauthenticated user", func(c C) {
			clientHTTP := resty.R()

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(accessibleRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip bookmark repo unauthorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})

		Convey("Flip bookmarked unauthorized repo and admin user", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(adminUser, adminPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 1)
			So(responseStruct.Results[0].Name, ShouldEqual, forbiddenRepo)
			// need to update RepoSummary according to user settings
			So(responseStruct.Results[0].IsBookmarked, ShouldEqual, true)

			resp, err = clientHTTP.Put(userprefsBaseURL + PutRepoBookmarkURL(forbiddenRepo))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userBookmarkedReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct = BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})
	})
}

func TestChangingRepoState(t *testing.T) {
	port := GetFreePort()
	baseURL := GetBaseURL(port)
	defaultVal := true

	simpleUser := "test"
	simpleUserPassword := "test123"

	forbiddenRepo := "forbidden"
	accesibleRepo := "accesible"

	credTests := fmt.Sprintf("%s\n\n", getCredString(simpleUser, simpleUserPassword))

	htpasswdPath := MakeHtpasswdFileFromString(credTests)
	defer os.Remove(htpasswdPath)

	conf := config.New()
	conf.Storage.RootDirectory = t.TempDir()
	conf.HTTP.Port = port
	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: htpasswdPath,
		},
	}
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users:   []string{simpleUser},
						Actions: []string{"read"},
					},
				},
				AnonymousPolicy: []string{"read"},
				DefaultPolicy:   []string{},
			},
			forbiddenRepo: config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users:   []string{},
						Actions: []string{},
					},
				},
				DefaultPolicy: []string{},
			},
		},
	}
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}

	gqlStarredRepos := `
	{
		StarredRepos() {
			Results {
				Name
				StarCount
				IsBookmarked
				IsStarred
			}
		}
	}
	`

	gqlBookmarkedRepos := `
	{
		BookmarkedRepos() {
			Results {
				Name
				StarCount
				IsBookmarked
				IsStarred
			}
		}
	}
	`

	ctlr := api.NewController(conf)

	img, err := GetRandomImage("tag")
	if err != nil {
		t.FailNow()
	}

	// ------ Create the test repos
	defaultStore := local.NewImageStore(conf.Storage.RootDirectory, false, 0, false, false,
		log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

	err = WriteImageToFileSystem(img, accesibleRepo, storage.StoreController{
		DefaultStore: defaultStore,
	})
	if err != nil {
		t.FailNow()
	}

	err = WriteImageToFileSystem(img, forbiddenRepo, storage.StoreController{
		DefaultStore: defaultStore,
	})
	if err != nil {
		t.FailNow()
	}

	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)

	defer ctlrManager.StopServer()

	simpleUserClient := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)
	anonynousClient := resty.R()

	userprefsBaseURL := baseURL + constants.FullUserPreferencesPrefix

	Convey("PutStars", t, func() {
		resp, err := simpleUserClient.Put(userprefsBaseURL + PutRepoStarURL(accesibleRepo))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(gqlStarredRepos))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := StarredReposResponse{}
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)
		So(responseStruct.Results[0].IsStarred, ShouldBeTrue)
		So(responseStruct.Results[0].Name, ShouldResemble, accesibleRepo)

		resp, err = anonynousClient.Put(userprefsBaseURL + PutRepoStarURL(accesibleRepo))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
	})
	//
	Convey("PutBookmark", t, func() {
		resp, err := simpleUserClient.Put(userprefsBaseURL + PutRepoBookmarkURL(accesibleRepo))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(gqlBookmarkedRepos))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := BookmarkedReposResponse{}
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)
		So(responseStruct.Results[0].IsBookmarked, ShouldBeTrue)
		So(responseStruct.Results[0].Name, ShouldResemble, accesibleRepo)

		resp, err = anonynousClient.Put(userprefsBaseURL + PutRepoBookmarkURL(accesibleRepo))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
	})
}

func PutRepoStarURL(repo string) string {
	return fmt.Sprintf("?repo=%s&action=toggleStar", repo)
}

func PutRepoBookmarkURL(repo string) string {
	return fmt.Sprintf("?repo=%s&action=toggleBookmark", repo)
}

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}
