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
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
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

		testScanner.SetCveDataForImage(baseImage.Digest().String(), map[string]cvemodel.CVE{
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
		testScanner.SetCveDataForImage(baseImage.Digest().String(), map[string]cvemodel.CVE{})

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
