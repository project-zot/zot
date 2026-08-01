//go:build search

package search_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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

func testImageCreateHelper(t *testing.T, layers [][]byte) Image {
	t.Helper()
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	So(err, ShouldBeNil)

	configDigest := godigest.FromBytes(configBlob)

	manifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
	}

	for i := range layers {
		manifest.Layers = append(manifest.Layers, ispec.Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar",
			Digest:    godigest.FromBytes(layers[i]),
			Size:      int64(len(layers[i])),
		})
	}

	return Image{
		Manifest: manifest,
		Config:   config,
		Layers:   layers,
	}
}

func TestCVEDiffListForImagesGqlAuthorization(t *testing.T) {
	Convey("CVE Diff list for a repo should only be accessible to authorized users", t, func() {
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
				"public/**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"admin"},
							Actions: []string{"create", "read", "delete"},
						},
						{
							Users:   []string{"user"},
							Actions: []string{"read"},
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

		adminImage1 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}})
		err := UploadImageWithBasicAuth(
			adminImage1, baseURL, "admin/admin-only", "0.0.1",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage(fmt.Sprintf("admin/admin-only@%s", adminImage1.Digest()), map[string]common.CVE{
			"CVE-2023-0001": {
				ID:          "CVE-2023-0001",
				Description: "Test CVE 1",
				Severity:    "HIGH",
			},
		})

		adminImage2 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}, {20, 21, 20, 21}, {30, 31, 30, 31}})
		err = UploadImageWithBasicAuth(
			adminImage2, baseURL, "admin/no-entry", "0.0.2",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage(fmt.Sprintf("admin/no-entry@%s", adminImage2.Digest()), map[string]common.CVE{
			"CVE-2023-0002": {
				ID:          "CVE-2023-0002",
				Description: "Test CVE 2",
				Severity:    "MEDIUM",
			},
		})

		publicImage1 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}, {20, 21, 20, 21}})
		err = UploadImageWithBasicAuth(
			publicImage1, baseURL, "public/open", "0.0.1",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage(fmt.Sprintf("public/open@%s", publicImage1.Digest()), map[string]common.CVE{
			"CVE-2023-0003": {
				ID:          "CVE-2023-0003",
				Description: "Test CVE 3",
				Severity:    "LOW",
			},
		})

		publicImage2 := testImageCreateHelper(t, [][]byte{
			{10, 11, 10, 11}, {20, 21, 20, 21}, {30, 31, 30, 31}, {40, 41, 40, 41},
		})
		err = UploadImageWithBasicAuth(
			publicImage2, baseURL, "public/open", "0.0.2",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage(fmt.Sprintf("public/open@%s", publicImage2.Digest()), map[string]common.CVE{
			"CVE-2023-0004": {
				ID:          "CVE-2023-0004",
				Description: "Test CVE 4",
				Severity:    "HIGH",
			},
		})

		// admin should be able to diff 2 admin images
		query := `
			{
				CVEDiffListForImages(minuend:{Repo: "admin/admin-only", Tag: "0.0.1"},
					subtrahend:{Repo: "admin/no-entry", Tag: "0.0.2"}){
					Minuend { Repo Tag }
					Subtrahend { Repo Tag }
					CVEList{
						Id
					}
				}
			}`

		// admin should be able to access the cve diff list for admin images
		adminClient := resty.New().SetBasicAuth(adminUserName, adminPassword)
		resp, err := adminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.CVEDiffListForImagesResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.CVEDiffListForImages.CVEList), ShouldEqual, 1)

		// non-admin user should not be able to access the cve diff list for admin images
		nonAdminClient := resty.New().SetBasicAuth(normalUserName, normalPassword)
		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var nonAdminResponse zcommon.CVEDiffListForImagesResponse
		err = json.Unmarshal(resp.Body(), &nonAdminResponse)
		So(err, ShouldBeNil)
		So(nonAdminResponse.CVEDiffListForImages.CVEList, ShouldBeEmpty)

		// non-admin user should be able to access the cve diff list for public images
		query = `
			{
				CVEDiffListForImages(minuend:{Repo: "public/open", Tag: "0.0.1"}, subtrahend:{Repo: "public/open", Tag: "0.0.2"}){
					Minuend { Repo Tag }
					Subtrahend { Repo Tag }
					CVEList{
						Id
					}
				}
			}`

		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var publicResponse zcommon.CVEDiffListForImagesResponse
		err = json.Unmarshal(resp.Body(), &publicResponse)
		So(err, ShouldBeNil)
		So(len(publicResponse.CVEDiffListForImages.CVEList), ShouldEqual, 1)

		// non-admin user should not be able to access the cve diff list for an admin image and a public image
		query = `
			{
				CVEDiffListForImages(minuend:{Repo: "admin/admin-only", Tag: "0.0.1"},
					subtrahend:{Repo: "public/open", Tag: "0.0.2"}){
					Minuend { Repo Tag }
					Subtrahend { Repo Tag }
					CVEList{
						Id
					}
				}
			}`

		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var mixedResponse zcommon.CVEDiffListForImagesResponse
		err = json.Unmarshal(resp.Body(), &mixedResponse)
		So(err, ShouldBeNil)
		So(mixedResponse.CVEDiffListForImages.CVEList, ShouldBeEmpty)

		// non-admin user should not be able to access the cve diff list for a public image and an admin image
		query = `
			{
				CVEDiffListForImages(minuend:{Repo: "public/open", Tag: "0.0.1"},
					subtrahend:{Repo: "admin/no-entry", Tag: "0.0.2"}){
					Minuend { Repo Tag }
					Subtrahend { Repo Tag }
					CVEList{
						Id
					}
				}
			}`

		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var mixedResponse2 zcommon.CVEDiffListForImagesResponse
		err = json.Unmarshal(resp.Body(), &mixedResponse2)
		So(err, ShouldBeNil)
		So(mixedResponse2.CVEDiffListForImages.CVEList, ShouldBeEmpty)
	})
}
