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
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/log"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	. "zotregistry.dev/zot/pkg/test/oci-utils"
)

//nolint:dupl
func TestUserData(t *testing.T) {
	Convey("Test user stars and bookmarks", t, func(c C) {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		defaultVal := true

		accessibleRepo := "accessible-repo"
		forbiddenRepo := "forbidden-repo"
		tag := "0.0.1"

		adminUser := "alice"
		adminPassword := "deepGoesTheRabbitBurrow"
		simpleUser := "test"
		simpleUserPassword := "test123"

		content := test.GetCredString(adminUser, adminPassword) +
			test.GetCredString(simpleUser, simpleUserPassword)
		htpasswdPath := test.MakeHtpasswdFileFromString(content)
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
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		image := CreateDefaultImage()

		err := UploadImageWithBasicAuth(
			image, baseURL, accessibleRepo, tag,
			adminUser, adminPassword,
		)
		So(err, ShouldBeNil)

		err = UploadImageWithBasicAuth(
			image, baseURL, forbiddenRepo, tag,
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

		userprefsBaseURL := baseURL + constants.FullUserPrefs

		Convey("Flip starred repo authorized", func(c C) {
			clientHTTP := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

			resp, err := clientHTTP.Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(userStaredReposQuery))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)

			responseStruct := common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct := common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct := common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct := common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct = common.StarredReposResponse{}
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

			responseStruct := common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
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

			responseStruct := common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
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

			responseStruct := common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
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

			responseStruct := common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
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

			responseStruct = common.BookmarkedReposResponse{}
			err = json.Unmarshal(resp.Body(), &responseStruct)
			So(err, ShouldBeNil)
			So(len(responseStruct.Results), ShouldEqual, 0)
		})
	})
}

func TestChangingRepoState(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	defaultVal := true

	simpleUser := "test"
	simpleUserPassword := "test123"

	forbiddenRepo := "forbidden"
	accesibleRepo := "accesible"

	htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(simpleUser, simpleUserPassword))
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
	conf.Extensions = &extconf.ExtensionConfig{}
	conf.Extensions.Search = &extconf.SearchConfig{}
	conf.Extensions.Search.Enable = &defaultVal
	conf.Extensions.Search.CVE = nil
	conf.Extensions.UI = &extconf.UIConfig{}
	conf.Extensions.UI.Enable = &defaultVal

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

	img := CreateRandomImage()
	storeCtlr := GetDefaultStoreController(conf.Storage.RootDirectory, log.NewLogger("debug", ""))

	err := WriteImageToFileSystem(img, accesibleRepo, "tag", storeCtlr)
	if err != nil {
		t.FailNow()
	}

	err = WriteImageToFileSystem(img, forbiddenRepo, "tag", storeCtlr)
	if err != nil {
		t.FailNow()
	}

	ctlrManager := test.NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)

	defer ctlrManager.StopServer()

	simpleUserClient := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)
	anonynousClient := resty.R()

	userprefsBaseURL := baseURL + constants.FullUserPrefs

	Convey("PutStars", t, func() {
		resp, err := simpleUserClient.Put(userprefsBaseURL + PutRepoStarURL(accesibleRepo))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(gqlStarredRepos))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		responseStruct := common.StarredReposResponse{}
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

		responseStruct := common.BookmarkedReposResponse{}
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

func TestGlobalSearchWithUserPrefFiltering(t *testing.T) {
	Convey("Bookmarks and Stars filtering", t, func() {
		dir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		simpleUser := "simpleUser"
		simpleUserPassword := "simpleUserPass"
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(simpleUser, simpleUserPassword))
		defer os.Remove(htpasswdPath)

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
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		preferencesBaseURL := baseURL + constants.FullUserPrefs
		simpleUserClient := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

		// ------ Add simple repo
		repo := "repo"
		img := CreateRandomImage()

		err := UploadImageWithBasicAuth(img, baseURL, repo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		// ------ Add repo and star it
		sRepo := "starred-repo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, sRepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err := simpleUserClient.Put(preferencesBaseURL + PutRepoStarURL(sRepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// ------ Add repo and bookmark it
		bRepo := "bookmarked-repo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, bRepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoBookmarkURL(bRepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// ------ Add repo, star and bookmark it
		sbRepo := "starred-bookmarked-repo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, sbRepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoStarURL(sbRepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)
		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoBookmarkURL(sbRepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// Make global search requests filterin by IsStarred and IsBookmarked

		query := `{ GlobalSearch(query:"repo", ){ Repos { Name } } }`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := &common.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		foundRepos := responseStruct.Repos
		So(len(foundRepos), ShouldEqual, 4)

		// Filter by IsStarred = true
		query = `{ GlobalSearch(query:"repo", filter:{ IsStarred:true }) { Repos { Name IsStarred IsBookmarked }}}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &common.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		foundRepos = responseStruct.Repos
		So(len(foundRepos), ShouldEqual, 2)
		So(foundRepos, ShouldContain, common.RepoSummary{Name: sRepo, IsStarred: true, IsBookmarked: false})
		So(foundRepos, ShouldContain, common.RepoSummary{Name: sbRepo, IsStarred: true, IsBookmarked: true})

		// Filter by IsStarred = true && IsBookmarked = false
		query = `{
			GlobalSearch(query:"repo", filter:{ IsStarred:true, IsBookmarked:false }) {
				Repos { Name IsStarred IsBookmarked }
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &common.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		foundRepos = responseStruct.Repos
		So(len(foundRepos), ShouldEqual, 1)
		So(foundRepos, ShouldContain, common.RepoSummary{Name: sRepo, IsStarred: true, IsBookmarked: false})

		// Filter by IsBookmarked = true
		query = `{
			GlobalSearch(query:"repo", filter:{ IsBookmarked:true }) {
				Repos { Name IsStarred IsBookmarked }
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &common.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		foundRepos = responseStruct.Repos
		So(len(foundRepos), ShouldEqual, 2)
		So(foundRepos, ShouldContain, common.RepoSummary{Name: bRepo, IsStarred: false, IsBookmarked: true})
		So(foundRepos, ShouldContain, common.RepoSummary{Name: sbRepo, IsStarred: true, IsBookmarked: true})

		// Filter by IsBookmarked = true && IsStarred = false
		query = `{
			GlobalSearch(query:"repo", filter:{ IsBookmarked:true, IsStarred:false }) {
				Repos { Name IsStarred IsBookmarked }
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = &common.GlobalSearchResultResp{}

		err = json.Unmarshal(resp.Body(), responseStruct)
		So(err, ShouldBeNil)

		foundRepos = responseStruct.Repos
		So(len(foundRepos), ShouldEqual, 1)
		So(foundRepos, ShouldContain, common.RepoSummary{Name: bRepo, IsStarred: false, IsBookmarked: true})
	})
}

func TestExpandedRepoInfoWithUserPrefs(t *testing.T) {
	Convey("ExpandedRepoInfo with User Prefs", t, func() {
		dir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		simpleUser := "simpleUser"
		simpleUserPassword := "simpleUserPass"
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(simpleUser, simpleUserPassword))
		defer os.Remove(htpasswdPath)

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
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		preferencesBaseURL := baseURL + constants.FullUserPrefs
		simpleUserClient := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

		// ------ Add sbrepo and star/bookmark it
		sbrepo := "sbrepo"
		img := CreateRandomImage()

		err := UploadImageWithBasicAuth(img, baseURL, sbrepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err := simpleUserClient.Put(preferencesBaseURL + PutRepoStarURL(sbrepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoBookmarkURL(sbrepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// ExpandedRepoinfo

		query := `
		{
			ExpandedRepoInfo(repo:"sbrepo"){
				Summary {
					Name IsStarred IsBookmarked
				}
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct := common.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)

		repoInfo := responseStruct.RepoInfo
		So(repoInfo.Summary.IsBookmarked, ShouldBeTrue)
		So(repoInfo.Summary.IsStarred, ShouldBeTrue)

		// ------ Add srepo and star it
		srepo := "srepo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, srepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoStarURL(srepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// ExpandedRepoinfo
		query = `
		{
			ExpandedRepoInfo(repo:"srepo"){
				Summary {
					Name IsStarred IsBookmarked
				}
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = common.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)

		repoInfo = responseStruct.RepoInfo
		So(repoInfo.Summary.IsBookmarked, ShouldBeFalse)
		So(repoInfo.Summary.IsStarred, ShouldBeTrue)

		// ------ Add brepo and bookmark it
		brepo := "brepo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, brepo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		resp, err = simpleUserClient.Put(preferencesBaseURL + PutRepoBookmarkURL(brepo))
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)

		// ExpandedRepoinfo
		query = `
		{
			ExpandedRepoInfo(repo:"brepo"){
				Summary {
					Name IsStarred IsBookmarked
				}
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = common.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)

		repoInfo = responseStruct.RepoInfo
		So(repoInfo.Summary.IsBookmarked, ShouldBeTrue)
		So(repoInfo.Summary.IsStarred, ShouldBeFalse)

		// ------ Add repo without star/bookmark
		repo := "repo"
		img = CreateRandomImage()

		err = UploadImageWithBasicAuth(img, baseURL, repo, "tag", simpleUser, simpleUserPassword)
		So(err, ShouldBeNil)

		// ExpandedRepoinfo
		query = `
		{
			ExpandedRepoInfo(repo:"repo"){
				Summary {
					Name IsStarred IsBookmarked
				}
			}
		}`

		resp, err = simpleUserClient.Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		responseStruct = common.ExpandedRepoInfoResp{}

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)

		repoInfo = responseStruct.RepoInfo
		So(repoInfo.Summary.IsBookmarked, ShouldBeFalse)
		So(repoInfo.Summary.IsStarred, ShouldBeFalse)
	})
}

func PutRepoStarURL(repo string) string {
	return fmt.Sprintf("?repo=%s&action=toggleStar", repo)
}

func PutRepoBookmarkURL(repo string) string {
	return fmt.Sprintf("?repo=%s&action=toggleBookmark", repo)
}
