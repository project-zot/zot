//go:build search

package search_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestCVEListForImageGql(t *testing.T) {
	Convey("Image information should not be returned if user is not authorized for repo", t, func() {
		rootDir := t.TempDir()
		adminUserName := "admin"
		adminPassword := "admin123"
		normalUserName := "user"
		normalPassword := "user123"
		adminUserLine := GetBcryptCredString(adminUserName, adminPassword)
		normalUserLine := GetBcryptCredString(normalUserName, normalPassword)
		htpasswdPath := MakeHtpasswdFileFromString(t, adminUserLine+"\n"+normalUserLine)

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{Path: htpasswdPath}
		conf.Storage.RootDirectory = rootDir
		defaultVal := true

		updateDuration, _ := time.ParseDuration("1h")
		trivyConfig := &extconf.TrivyConfig{
			DBRepository: "ghcr.io/project-zot/trivy-db",
		}
		cveConfig := &extconf.CVEConfig{
			UpdateInterval: updateDuration,
			Trivy:          trivyConfig,
		}
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        cveConfig,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"admin/**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"admin"},
							Actions: []string{"create", "read", "delete"},
						},
					},
				},
			},
		}

		ctlr := api.NewController(conf)

		if err := ctlr.Init(); err != nil {
			t.Fatal(err)
		}

		testScanner := mocks.NewTestCveScanner()
		ctlr.CveScanner = testScanner

		go func() {
			if err := ctlr.Run(); !errors.Is(err, http.ErrServerClosed) {
				panic(err)
			}
		}()

		defer ctlr.Shutdown()

		cm := NewControllerManager(ctlr)
		cm.WaitServerReady()
		baseURL := cm.BaseURL()

		uploadedImage := CreateDefaultImage()

		err := UploadImageWithBasicAuth(uploadedImage, baseURL, "admin/zot-test", "0.0.1", adminUserName, adminPassword)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage("admin/zot-test:0.0.1", map[string]common.CVE{
			"CVE-2021-1234": {ID: "CVE-2021-1234", Severity: "CRITICAL"},
		})

		// Verify image with vulnerabilities returns correct data
		query := `{
			CVEListForImage(image:"admin/zot-test:0.0.1") {
				Tag
				CVEList { Id }
			}
		}`

		// admin user should be able to get image info
		adminClient := resty.New().SetBasicAuth(adminUserName, adminPassword)
		resp, err := adminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.CveListForImageResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(responseStruct.CVEListForImage.Tag, ShouldEqual, "0.0.1")
		So(responseStruct.CVEListForImage.CVEList, ShouldNotBeEmpty)

		// non-admin user should not be able to get image info
		nonAdminClient := resty.New().SetBasicAuth(normalUserName, normalPassword)
		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var nonAdminResponse zcommon.CveListForImageResponse
		err = json.Unmarshal(resp.Body(), &nonAdminResponse)
		So(err, ShouldBeNil)
		So(nonAdminResponse.CVEListForImage.Tag, ShouldEqual, "")
		So(nonAdminResponse.CVEListForImage.CVEList, ShouldBeEmpty)
	})
}
