//go:build search

package search_test

import (
	"encoding/json"
	"errors"
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
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestBaseImageListGql(t *testing.T) {
	rootDir := t.TempDir()

	conf := config.New()
	conf.HTTP.Port = "0"
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

	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.WaitServerReady()
	baseURL := ctlrManager.BaseURL()

	Convey("Base image with vulnerability should have correct data in response", t, func() {
		// create test images
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

		layers := [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
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
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
			},
		}

		baseImage := Image{
			Manifest: manifest,
			Config:   config,
			Layers:   layers,
		}

		err = UploadImage(
			baseImage, baseURL, "test-repo", "latest",
		)
		So(err, ShouldBeNil)

		// create image with more layers than the original
		layers = [][]byte{
			{10, 11, 10, 11},
			{11, 11, 11, 11},
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
					Digest:    godigest.FromBytes(layers[0]),
					Size:      int64(len(layers[0])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[1]),
					Size:      int64(len(layers[1])),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(layers[2]),
					Size:      int64(len(layers[2])),
				},
			},
		}

		err = UploadImage(
			Image{
				Manifest: manifest,
				Config:   config,
				Layers:   layers,
			}, baseURL, "more-layers", "latest",
		)
		So(err, ShouldBeNil)

		testScanner.SetCveDataForImage(baseImage.Digest().String(), map[string]zcommon.CVE{
			"CVE1": {
				ID:          "CVE1",
				Severity:    "MEDIUM",
				Title:       "Title CVE1",
				Description: "Description CVE1",
			},
			"CVE2": {
				ID:          "CVE2",
				Severity:    "HIGH",
				Title:       "Title CVE2",
				Description: "Description CVE2",
			},
		})

		query := `
			{
				BaseImageList(image:"more-layers:latest"){
					Results{
						RepoName
						Tag
						Vulnerabilities {
							MaxSeverity
							Count
						}
					}
				}
			}`

		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.BaseImageListResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)

		respImg := responseStruct.Results[0]
		So(respImg.RepoName, ShouldEqual, "test-repo")
		So(respImg.Vulnerabilities.Count, ShouldEqual, 2)
		So(respImg.Vulnerabilities.MaxSeverity, ShouldEqual, "HIGH")

		// empty the cve data for the image and verify that the vulnerabilities count is 0
		testScanner.SetCveDataForImage(baseImage.Digest().String(), map[string]zcommon.CVE{})

		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)

		respImg = responseStruct.Results[0]
		So(respImg.RepoName, ShouldEqual, "test-repo")
		So(respImg.Vulnerabilities.Count, ShouldEqual, 0)
		So(respImg.Vulnerabilities.MaxSeverity, ShouldEqual, "NONE")
	})
}

func TestBaseImageListGqlAuthorization(t *testing.T) {
	Convey("Base image list for a repo should only be accessible to authorized users", t, func() {
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

		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
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
		cm := NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()

		adminImage1 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}})
		err := UploadImageWithBasicAuth(
			adminImage1, baseURL, "admin/secret-base", "latest",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		publicImage1 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}, {20, 21, 20, 21}})

		err = UploadImageWithBasicAuth(
			publicImage1, baseURL, "public/open", "latest",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		adminImage2 := testImageCreateHelper(t, [][]byte{{10, 11, 10, 11}, {20, 21, 20, 21}, {30, 31, 30, 31}})
		err = UploadImageWithBasicAuth(
			adminImage2, baseURL, "admin/another-secret", "latest",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		publicImage2 := testImageCreateHelper(t, [][]byte{
			{10, 11, 10, 11}, {20, 21, 20, 21}, {30, 31, 30, 31}, {40, 41, 40, 41},
		})
		err = UploadImageWithBasicAuth(
			publicImage2, baseURL, "public/freeforusers", "latest",
			adminUserName, adminPassword,
		)
		So(err, ShouldBeNil)

		query := `
			{
				BaseImageList(image:"public/freeforusers:latest"){
					Results{
						RepoName
						Tag
					}
				}
			}`

		// admin should be able to access the base image list for a public image
		adminClient := resty.New().SetBasicAuth(adminUserName, adminPassword)
		resp, err := adminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.BaseImageListResponse
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 3)

		// check that the base image list contains the expected images
		imagesToCheck := map[string]bool{
			"public/open:latest":          false,
			"admin/another-secret:latest": false,
			"admin/secret-base:latest":    false,
		}

		for _, img := range responseStruct.Results {
			key := img.RepoName + ":" + img.Tag
			if _, ok := imagesToCheck[key]; ok {
				imagesToCheck[key] = true
			}
		}

		for _, found := range imagesToCheck {
			So(found, ShouldBeTrue)
		}

		// non-admin user should be able to access the base image list for a public image
		// but admin images should not be in the list since they don't have access to it.
		nonAdminClient := resty.New().SetBasicAuth(normalUserName, normalPassword)
		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var nonAdminResponse zcommon.BaseImageListResponse
		err = json.Unmarshal(resp.Body(), &nonAdminResponse)
		So(err, ShouldBeNil)
		So(len(nonAdminResponse.Results), ShouldEqual, 1)
		So(nonAdminResponse.Results[0].RepoName, ShouldEqual, "public/open")
		So(nonAdminResponse.Results[0].Tag, ShouldEqual, "latest")

		// admin should be able to access the base image list for the public/open image
		query = `
			{
				BaseImageList(image:"admin/another-secret:latest"){
					Results{
						RepoName
						Tag
					}
				}
			}`

		resp, err = adminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var adminAdminRepoBaseResp zcommon.BaseImageListResponse
		err = json.Unmarshal(resp.Body(), &adminAdminRepoBaseResp)
		So(err, ShouldBeNil)
		So(len(adminAdminRepoBaseResp.Results), ShouldEqual, 2)

		expectedImages := map[string]bool{
			"admin/secret-base:latest": false,
			"public/open:latest":       false,
		}

		for _, img := range adminAdminRepoBaseResp.Results {
			key := img.RepoName + ":" + img.Tag
			if _, ok := expectedImages[key]; ok {
				expectedImages[key] = true
			}
		}

		for _, found := range expectedImages {
			So(found, ShouldBeTrue)
		}

		// non-admin user should not be able to access the base image list for the admin image
		// even though one of the base images is accessible to them.
		resp, err = nonAdminClient.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var nonAdminAdminRepoBaseResp zcommon.BaseImageListResponse
		err = json.Unmarshal(resp.Body(), &nonAdminAdminRepoBaseResp)
		So(err, ShouldBeNil)
		So(nonAdminAdminRepoBaseResp.Results, ShouldBeEmpty)
	})
}
