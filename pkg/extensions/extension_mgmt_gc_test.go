//go:build sync && metrics && mgmt && userprefs && search

package extensions_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestMgmtGC(t *testing.T) {
	Convey("On-demand GC through the mgmt extension", t, func() {
		adminUser, adminPass := "admin", "admin-pass"
		user, userPass := "user", "user-pass"
		htpasswdPath := test.MakeHtpasswdFileFromString(t,
			test.GetBcryptCredString(adminUser, adminPass)+"\n"+test.GetBcryptCredString(user, userPass))

		enable := true

		conf := config.New()
		conf.HTTP.Port = test.GetFreePort()
		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					Policies: []config.Policy{
						{Users: []string{user}, Actions: []string{"read", "create", "update", "delete"}},
					},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{adminUser},
				Actions: []string{"read", "create", "update", "delete"},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = true
		conf.Storage.GCDelay = time.Millisecond
		conf.Storage.GCInterval = time.Hour
		conf.Storage.SubPaths = map[string]config.StorageConfig{
			"/nogc": {RootDirectory: t.TempDir(), GC: false},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &enable},
			Mgmt:   &extconf.MgmtConfig{Enable: &enable},
		}

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)
		baseURL := ctlrManager.StartAndWait()
		defer ctlrManager.StopServer()

		gcURL := baseURL + constants.FullMgmt + constants.MgmtGC
		admin := resty.R().SetBasicAuth(adminUser, adminPass)

		Convey("only admins can use it", func() {
			resp, err := resty.R().SetBasicAuth(user, userPass).SetQueryParam("store", "/").Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = resty.R().SetBasicAuth(user, userPass).SetQueryParam("store", "/").Get(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			resp, err = resty.R().SetQueryParam("store", "/").Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})

		Convey("unknown stores and repos are rejected", func() {
			resp, err := admin.SetQueryParam("store", "/unknown").Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().SetBasicAuth(adminUser, adminPass).Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().SetBasicAuth(adminUser, adminPass).
				SetQueryParams(map[string]string{"store": "/", "repo": "does-not-exist"}).Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("invalid repository names are rejected", func() {
			for _, repo := range []string{"..", "../repo1", "UPPER"} {
				resp, err := resty.R().SetBasicAuth(adminUser, adminPass).
					SetQueryParams(map[string]string{"store": "/", "repo": repo}).Post(gcURL)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				resp, err = resty.R().SetBasicAuth(adminUser, adminPass).
					SetQueryParams(map[string]string{"store": "/", "repo": repo}).Get(gcURL)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
			}
		})

		Convey("stores with GC disabled are rejected", func() {
			resp, err := admin.SetQueryParam("store", "/nogc").Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusConflict)
		})

		Convey("a store sweep can be requested and its status read", func() {
			resp, err := admin.SetQueryParam("store", "/").Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			So(waitFor(func() bool {
				status := getGCStatus(gcURL, adminUser, adminPass, map[string]string{"store": "/"})

				return !status.Running && !status.FinishedAt.IsZero()
			}, 30*time.Second), ShouldBeTrue)
		})

		Convey("GC of one repository removes the blobs of a deleted image", func() {
			img := CreateRandomImage()
			So(UploadImageWithBasicAuth(img, baseURL, "repo1", "0.0.1", user, userPass), ShouldBeNil)
			So(UploadImageWithBasicAuth(CreateRandomImage(), baseURL, "repo1", "0.0.2", user, userPass), ShouldBeNil)

			resp, err := resty.R().SetBasicAuth(user, userPass).
				Delete(baseURL + "/v2/repo1/manifests/" + img.DigestStr())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			layerURL := baseURL + "/v2/repo1/blobs/" + img.Manifest.Layers[0].Digest.String()

			resp, err = resty.R().SetBasicAuth(user, userPass).Head(layerURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// the status of a repo which was never requested is not found
			resp, err = resty.R().SetBasicAuth(adminUser, adminPass).
				SetQueryParams(map[string]string{"store": "/", "repo": "repo1"}).Get(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().SetBasicAuth(adminUser, adminPass).
				SetQueryParams(map[string]string{"store": "/", "repo": "repo1"}).Post(gcURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			So(waitFor(func() bool {
				status := getGCStatus(gcURL, adminUser, adminPass, map[string]string{"store": "/", "repo": "repo1"})

				return !status.Running && !status.FinishedAt.IsZero()
			}, 30*time.Second), ShouldBeTrue)

			// the manifest was removed from the index by the delete, GC removes its blobs
			status := getGCStatus(gcURL, adminUser, adminPass, map[string]string{"store": "/", "repo": "repo1"})
			So(status.Error, ShouldBeEmpty)

			resp, err = resty.R().SetBasicAuth(user, userPass).Head(layerURL)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func getGCStatus(gcURL, username, password string, params map[string]string) gc.RunStatus {
	resp, err := resty.R().SetBasicAuth(username, password).SetQueryParams(params).Get(gcURL)
	So(err, ShouldBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	var status gc.RunStatus

	So(json.Unmarshal(resp.Body(), &status), ShouldBeNil)

	return status
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(50 * time.Millisecond)
	}

	return cond()
}

func TestMgmtGCWithoutAccessControl(t *testing.T) {
	enable := true

	newConf := func() *config.Config {
		conf := config.New()
		conf.HTTP.Port = test.GetFreePort()
		conf.Storage.RootDirectory = t.TempDir()
		conf.Storage.GC = true
		conf.Storage.GCInterval = time.Hour
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &enable},
			Mgmt:   &extconf.MgmtConfig{Enable: &enable},
		}

		return conf
	}

	Convey("Without accessControl every authenticated user is an admin", t, func() {
		username, password := "user", "user-pass"

		conf := newConf()
		conf.HTTP.Auth.HTPasswd.Path = test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		ctlrManager := test.NewControllerManager(api.NewController(conf))
		baseURL := ctlrManager.StartAndWait()
		defer ctlrManager.StopServer()

		resp, err := resty.R().SetBasicAuth(username, password).SetQueryParam("store", "/").
			Post(baseURL + constants.FullMgmt + constants.MgmtGC)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})

	Convey("Without authentication and accessControl anyone is an admin", t, func() {
		ctlrManager := test.NewControllerManager(api.NewController(newConf()))
		baseURL := ctlrManager.StartAndWait()
		defer ctlrManager.StopServer()

		resp, err := resty.R().SetQueryParam("store", "/").Post(baseURL + constants.FullMgmt + constants.MgmtGC)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})
}
