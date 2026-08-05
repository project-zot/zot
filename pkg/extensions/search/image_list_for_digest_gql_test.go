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
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	. "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestImageListForDigestGql(t *testing.T) {
	Convey("Test ImageListForDigest with vulnerability scan enabled", t, func() {
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

		ctlr.CveScanner = getMockCveScanner(ctlr.MetaDB)

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

		createdTime := time.Date(2010, 1, 1, 12, 0, 0, 0, time.UTC)
		createdTimeL2 := time.Date(2010, 2, 1, 12, 0, 0, 0, time.UTC)
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
			History: []ispec.History{
				{
					Created:    &createdTime,
					CreatedBy:  "go test data",
					Author:     "ZotUser",
					Comment:    "Test history comment",
					EmptyLayer: true,
				},
				{
					Created:    &createdTimeL2,
					CreatedBy:  "go test data 2",
					Author:     "ZotUser",
					Comment:    "Test history comment2",
					EmptyLayer: false,
				},
			},
		}

		image := CreateImageWith().RandomLayers(1, 100).ImageConfig(config).Build()

		err := UploadImage(uploadedImage, baseURL, "zot-cve-test", "0.0.1")
		So(err, ShouldBeNil)

		err = UploadImage(image, baseURL, "zot-no-vuln", "0.0.1")
		So(err, ShouldBeNil)

		// Verify image with vulnerabilities returns correct data
		query := fmt.Sprintf(`{
			ImageListForDigest(id:"%s") {
				Results {
					RepoName
					Tag
					Vulnerabilities {
						MaxSeverity
						Count
					}
				}
			}
		}`, uploadedImage.Digest())
		resp, err := resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		var responseStruct zcommon.ImagesForDigest
		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)

		img := responseStruct.Results[0]
		So(img.RepoName, ShouldEqual, "zot-cve-test")
		So(img.Vulnerabilities.Count, ShouldEqual, 4)
		So(img.Vulnerabilities.MaxSeverity, ShouldEqual, "CRITICAL")

		// Verify image with no vulnerabilities returns empty vulnerability data
		query = fmt.Sprintf(`{
			ImageListForDigest(id:"%s") {
				Results {
					RepoName
					Tag
					Vulnerabilities {
						MaxSeverity
						Count
					}
				}
			}
		}`, image.Digest())
		resp, err = resty.R().Get(baseURL + graphqlQueryPrefix + "?query=" + url.QueryEscape(query))
		So(resp, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &responseStruct)
		So(err, ShouldBeNil)
		So(len(responseStruct.Results), ShouldEqual, 1)

		img = responseStruct.Results[0]
		So(img.RepoName, ShouldEqual, "zot-no-vuln")
		So(img.Vulnerabilities.Count, ShouldEqual, 0)
		So(img.Vulnerabilities.MaxSeverity, ShouldEqual, "NONE")
	})
}
