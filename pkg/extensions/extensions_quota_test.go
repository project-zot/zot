//go:build search && quota

package extensions_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func boolPtr(b bool) *bool { return &b }

func startQuotaServer(t *testing.T, quotaConf *extconf.QuotaConfig) (string, func()) {
	t.Helper()

	port := test.GetFreePort()
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = t.TempDir()
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: boolPtr(true)},
		},
		Quota: quotaConf,
	}

	ctlr := api.NewController(conf)
	ctlrManager := test.NewControllerManager(ctlr)
	ctlrManager.StartAndWait(port)

	return test.GetBaseURL(port), func() { ctlrManager.StopServer() }
}

func TestQuotaExtensionEnforcement(t *testing.T) {
	Convey("Given a registry with maxRepos set to 2", t, func() {
		baseURL, stop := startQuotaServer(t, &extconf.QuotaConfig{
			BaseConfig: extconf.BaseConfig{Enable: boolPtr(true)},
			MaxRepos:   2,
		})
		defer stop()

		Convey("Push to two different repos succeeds", func() {
			err := UploadImage(CreateRandomImage(), baseURL, "repo1", "v1")
			So(err, ShouldBeNil)

			err = UploadImage(CreateRandomImage(), baseURL, "repo2", "v1")
			So(err, ShouldBeNil)

			Convey("Push to a third new repo is rejected with 429", func() {
				img := CreateRandomImage()
				manifestBody, err := json.Marshal(img.Manifest)
				So(err, ShouldBeNil)

				// Blobs are not needed to trigger the middleware — the manifest
				// PUT is intercepted before the handler processes the body.
				resp, err := resty.R().
					SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
					SetBody(manifestBody).
					Put(baseURL + "/v2/repo3/manifests/v1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusTooManyRequests)

				var body map[string]interface{}
				So(json.Unmarshal(resp.Body(), &body), ShouldBeNil)
				errors, ok := body["errors"].([]interface{})
				So(ok, ShouldBeTrue)
				So(len(errors), ShouldBeGreaterThan, 0)
				firstErr, ok := errors[0].(map[string]interface{})
				So(ok, ShouldBeTrue)
				So(firstErr["code"], ShouldEqual, "TOOMANYREQUESTS")
			})

			Convey("Push a new tag to an existing repo is allowed at the limit", func() {
				err := UploadImage(CreateRandomImage(), baseURL, "repo1", "v2")
				So(err, ShouldBeNil)
			})

			Convey("Re-pushing an existing tag is allowed at the limit", func() {
				err := UploadImage(CreateRandomImage(), baseURL, "repo2", "v1")
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestQuotaExtensionDisabled(t *testing.T) {
	Convey("Given a registry with quota disabled", t, func() {
		baseURL, stop := startQuotaServer(t, &extconf.QuotaConfig{
			BaseConfig: extconf.BaseConfig{Enable: boolPtr(false)},
			MaxRepos:   2,
		})
		defer stop()

		Convey("Pushing beyond the configured MaxRepos value succeeds", func() {
			for _, repo := range []string{"repo1", "repo2", "repo3"} {
				err := UploadImage(CreateRandomImage(), baseURL, repo, "v1")
				So(err, ShouldBeNil)
			}
		})
	})
}

func TestQuotaExtensionUnlimited(t *testing.T) {
	Convey("Given a registry with maxRepos set to 0 (unlimited)", t, func() {
		baseURL, stop := startQuotaServer(t, &extconf.QuotaConfig{
			BaseConfig: extconf.BaseConfig{Enable: boolPtr(true)},
			MaxRepos:   0,
		})
		defer stop()

		Convey("Pushing any number of repos succeeds", func() {
			for _, repo := range []string{"repo1", "repo2", "repo3", "repo4", "repo5"} {
				err := UploadImage(CreateRandomImage(), baseURL, repo, "v1")
				So(err, ShouldBeNil)
			}
		})
	})
}

func TestQuotaExtensionConcurrency(t *testing.T) {
	Convey("Given a registry with maxRepos set to 5", t, func() {
		baseURL, stop := startQuotaServer(t, &extconf.QuotaConfig{
			BaseConfig: extconf.BaseConfig{Enable: boolPtr(true)},
			MaxRepos:   5,
		})
		defer stop()

		Convey("Concurrent pushes to different new repos do not exceed the limit", func() {
			const goroutines = 10

			var wg sync.WaitGroup
			results := make([]int, goroutines)

			wg.Add(goroutines)
			for i := range goroutines {
				go func(idx int) {
					defer wg.Done()
					err := UploadImage(CreateRandomImage(), baseURL, fmt.Sprintf("concurrent-repo-%d", idx), "v1")
					if err != nil {
						results[idx] = http.StatusTooManyRequests
					} else {
						results[idx] = http.StatusCreated
					}
				}(i)
			}
			wg.Wait()

			created := 0
			rejected := 0
			for _, code := range results {
				if code == http.StatusCreated {
					created++
				} else {
					rejected++
				}
			}

			So(created, ShouldBeLessThanOrEqualTo, 5)
			So(rejected, ShouldBeGreaterThanOrEqualTo, 5)
		})
	})
}

func TestQuotaExtensionNotConfigured(t *testing.T) {
	Convey("Given a registry with no quota extension config", t, func() {
		baseURL, stop := startQuotaServer(t, nil)
		defer stop()

		Convey("Pushing any number of repos succeeds", func() {
			for _, repo := range []string{"repo1", "repo2", "repo3"} {
				err := UploadImage(CreateRandomImage(), baseURL, repo, "v1")
				So(err, ShouldBeNil)
			}
		})
	})
}
