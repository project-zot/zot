package api_test

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
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func startQuotaServer(t *testing.T, maxRepos int) (string, func()) {
	t.Helper()

	port := test.GetFreePort()
	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = t.TempDir()
	conf.Storage.MaxRepos = maxRepos

	ctlr := api.NewController(conf)
	ctlrManager := test.NewControllerManager(ctlr)
	ctlrManager.StartAndWait(port)

	return test.GetBaseURL(port), func() { ctlrManager.StopServer() }
}

func TestQuotaEnforcement(t *testing.T) {
	Convey("Given a registry with maxRepos set to 2", t, func() {
		baseURL, stop := startQuotaServer(t, 2)
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

				resp, err := resty.R().
					SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
					SetBody(manifestBody).
					Put(baseURL + "/v2/repo3/manifests/v1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusTooManyRequests)

				var body map[string]any
				So(json.Unmarshal(resp.Body(), &body), ShouldBeNil)
				errors, ok := body["errors"].([]any)
				So(ok, ShouldBeTrue)
				So(len(errors), ShouldBeGreaterThan, 0)
				firstErr, ok := errors[0].(map[string]any)
				So(ok, ShouldBeTrue)
				So(firstErr["code"], ShouldEqual, "TOOMANYREQUESTS")

				detail, ok := firstErr["detail"].(map[string]any)
				So(ok, ShouldBeTrue)
				So(detail["limit"], ShouldEqual, "2")
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

func TestQuotaDisabled(t *testing.T) {
	Convey("Given a registry with maxRepos set to 0 (disabled)", t, func() {
		baseURL, stop := startQuotaServer(t, 0)
		defer stop()

		Convey("Pushing any number of repos succeeds", func() {
			for _, repo := range []string{"repo1", "repo2", "repo3"} {
				err := UploadImage(CreateRandomImage(), baseURL, repo, "v1")
				So(err, ShouldBeNil)
			}
		})
	})
}

func TestQuotaConcurrency(t *testing.T) {
	Convey("Given a registry with maxRepos set to 5", t, func() {
		baseURL, stop := startQuotaServer(t, 5)
		defer stop()

		Convey("Concurrent pushes to different new repos do not exceed the limit", func() {
			const goroutines = 10

			var wg sync.WaitGroup
			results := make([]int, goroutines)

			for i := range goroutines {
				idx := i
				wg.Go(func() {
					err := UploadImage(CreateRandomImage(), baseURL, fmt.Sprintf("concurrent-repo-%d", idx), "v1")
					if err != nil {
						results[idx] = http.StatusTooManyRequests
					} else {
						results[idx] = http.StatusCreated
					}
				})
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
