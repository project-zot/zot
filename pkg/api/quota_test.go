package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func startQuotaServer(t *testing.T, maxRepos int) (string, func()) {
	t.Helper()

	conf := config.New()
	conf.HTTP.Port = "0"
	conf.Storage.RootDirectory = t.TempDir()
	conf.Storage.MaxRepos = maxRepos

	ctlr := api.NewController(conf)
	ctlrManager := test.NewControllerManager(ctlr)
	baseURL := ctlrManager.StartAndWait()

	return baseURL, func() { ctlrManager.StopServer() }
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

// startQuotaServerAt starts a quota-enforcing registry on a given root directory, so a test can restart
// the server over the same storage.
func startQuotaServerAt(t *testing.T, maxRepos int, rootDir string, gc bool) (string, func()) {
	t.Helper()

	conf := config.New()
	conf.HTTP.Port = "0"
	conf.Storage.RootDirectory = rootDir
	conf.Storage.MaxRepos = maxRepos
	// Dedupe keeps its cache open past Shutdown, blocking a restart on the same dir.
	conf.Storage.Dedupe = false

	if gc {
		conf.Storage.GC = true
		conf.Storage.GCDelay = 1 * time.Second
		conf.Storage.GCInterval = 2 * time.Second
	}

	ctlr := api.NewController(conf)
	ctlrManager := test.NewControllerManager(ctlr)
	baseURL := ctlrManager.StartAndWait()

	return baseURL, func() { ctlrManager.StopServer() }
}

func manifestDigest(t *testing.T, baseURL, repo, ref string) string {
	t.Helper()

	resp, err := resty.R().
		SetHeader("Accept", ispec.MediaTypeImageManifest).
		Get(baseURL + "/v2/" + repo + "/manifests/" + ref)
	So(err, ShouldBeNil)

	return resp.Header().Get("Docker-Content-Digest")
}

// uploadNewRepo pushes a complete image into a new repo.
func uploadNewRepo(t *testing.T, baseURL, repo string) error {
	t.Helper()

	return UploadImage(CreateRandomImage(), baseURL, repo, "v1")
}

// catalogRepos lists the repositories the catalog currently reports.
func catalogRepos(t *testing.T, baseURL string) []string {
	t.Helper()

	resp, err := resty.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	var catalog struct {
		Repositories []string `json:"repositories"`
	}

	So(json.Unmarshal(resp.Body(), &catalog), ShouldBeNil)

	return catalog.Repositories
}

// pushNewRepoStatus reports how the quota answers a new-repo push. Only a refusal is meaningful: the
// manifest is sent without blobs, so an allowed push fails later in the handler. Use uploadNewRepo to
// assert acceptance.
func pushNewRepoStatus(t *testing.T, baseURL, repo string) int {
	t.Helper()

	img := CreateRandomImage()

	manifestBody, err := json.Marshal(img.Manifest)
	So(err, ShouldBeNil)

	resp, err := resty.R().
		SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(manifestBody).
		Put(baseURL + "/v2/" + repo + "/manifests/v1")
	So(err, ShouldBeNil)

	return resp.StatusCode()
}

// TestQuotaSlotReleasedOnDelete checks that a partial delete keeps the slot, a full delete releases it,
// and the remaining images stay pullable.
func TestQuotaSlotReleasedOnDelete(t *testing.T) {
	Convey("Given a registry at its repo limit", t, func() {
		rootDir := t.TempDir()
		baseURL, stop := startQuotaServerAt(t, 3, rootDir, false)
		defer stop()

		first := CreateRandomImage()
		second := CreateRandomImage()

		So(UploadImage(first, baseURL, "shared", "v1"), ShouldBeNil)
		So(UploadImage(second, baseURL, "shared", "v2"), ShouldBeNil)
		So(UploadImage(CreateRandomImage(), baseURL, "second", "v1"), ShouldBeNil)
		So(UploadImage(CreateRandomImage(), baseURL, "third", "v1"), ShouldBeNil)

		So(pushNewRepoStatus(t, baseURL, "overflow"), ShouldEqual, http.StatusTooManyRequests)

		Convey("Deleting one tag of a two-tag repo releases nothing", func() {
			resp, err := resty.R().Delete(baseURL + "/v2/shared/manifests/" + first.DigestStr())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			// The sibling tag is untouched, and still serves the same bytes.
			So(manifestDigest(t, baseURL, "shared", "v2"), ShouldEqual, second.DigestStr())

			// The repo still holds content, so it still holds its slot.
			So(pushNewRepoStatus(t, baseURL, "overflow"), ShouldEqual, http.StatusTooManyRequests)

			Convey("Deleting the last tag releases the slot, and the name is reusable", func() {
				resp, err := resty.R().Delete(baseURL + "/v2/shared/manifests/" + second.DigestStr())
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

				// The layout goes with the meta record, so the catalog and the quota
				// count cannot diverge.
				So(catalogRepos(t, baseURL), ShouldNotContain, "shared")

				Convey("A differently named repo can take the freed slot", func() {
					So(uploadNewRepo(t, baseURL, "afterfree"), ShouldBeNil)
				})

				Convey("The emptied name can be reused, and round-trips intact", func() {
					reused := CreateRandomImage()
					So(UploadImage(reused, baseURL, "shared", "again"), ShouldBeNil)
					So(manifestDigest(t, baseURL, "shared", "again"), ShouldEqual, reused.DigestStr())
				})
			})
		})
	})
}

// TestQuotaSlotStaysReleasedAcrossRestart checks the startup reparse does not hand back a slot that a
// delete released.
func TestQuotaSlotStaysReleasedAcrossRestart(t *testing.T) {
	Convey("Given a repo emptied while at the limit", t, func() {
		rootDir := t.TempDir()
		baseURL, stop := startQuotaServerAt(t, 2, rootDir, false)

		doomed := CreateRandomImage()
		keeper := CreateRandomImage()

		So(UploadImage(doomed, baseURL, "doomed", "v1"), ShouldBeNil)
		So(UploadImage(keeper, baseURL, "keeper", "v1"), ShouldBeNil)
		So(pushNewRepoStatus(t, baseURL, "extra"), ShouldEqual, http.StatusTooManyRequests)

		resp, err := resty.R().Delete(baseURL + "/v2/doomed/manifests/" + doomed.DigestStr())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		stop()

		Convey("The slot is still free after a restart, and the survivor is intact", func() {
			restartedURL, stopAgain := startQuotaServerAt(t, 2, rootDir, false)
			defer stopAgain()

			So(manifestDigest(t, restartedURL, "keeper", "v1"), ShouldEqual, keeper.DigestStr())
			So(uploadNewRepo(t, restartedURL, "extra"), ShouldBeNil)
		})
	})
}

// TestQuotaSlotReleaseWithGCEnabled runs the release path with GC active, since GC also writes to
// metadata.
func TestQuotaSlotReleaseWithGCEnabled(t *testing.T) {
	Convey("Given a registry with GC enabled and at its limit", t, func() {
		rootDir := t.TempDir()
		baseURL, stop := startQuotaServerAt(t, 2, rootDir, true)
		defer stop()

		doomed := CreateRandomImage()
		keeper := CreateRandomImage()

		So(UploadImage(doomed, baseURL, "doomed", "v1"), ShouldBeNil)
		So(UploadImage(keeper, baseURL, "keeper", "v1"), ShouldBeNil)

		resp, err := resty.R().Delete(baseURL + "/v2/doomed/manifests/" + doomed.DigestStr())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		So(uploadNewRepo(t, baseURL, "extra"), ShouldBeNil)

		// Let several GC cycles run over the emptied repo.
		time.Sleep(6 * time.Second)

		So(manifestDigest(t, baseURL, "keeper", "v1"), ShouldEqual, keeper.DigestStr())
		So(pushNewRepoStatus(t, baseURL, "yetanother"), ShouldEqual, http.StatusTooManyRequests)
	})
}

// TestQuotaRepushOfRemovedNameCounts checks that a repo whose delete released its slot is treated as
// brand new when pushed again: it must consume a slot, not slip past the limit.
func TestQuotaRepushOfRemovedNameCounts(t *testing.T) {
	Convey("Given a repo emptied while at the limit", t, func() {
		rootDir := t.TempDir()
		baseURL, stop := startQuotaServerAt(t, 2, rootDir, false)
		defer stop()

		doomed := CreateRandomImage()

		So(UploadImage(doomed, baseURL, "doomed", "v1"), ShouldBeNil)
		So(UploadImage(CreateRandomImage(), baseURL, "keeper", "v1"), ShouldBeNil)
		So(pushNewRepoStatus(t, baseURL, "extra"), ShouldEqual, http.StatusTooManyRequests)

		resp, err := resty.R().Delete(baseURL + "/v2/doomed/manifests/" + doomed.DigestStr())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		So(catalogRepos(t, baseURL), ShouldNotContain, "doomed")

		Convey("Re-pushing the removed name succeeds but consumes the freed slot", func() {
			repushed := CreateRandomImage()
			So(UploadImage(repushed, baseURL, "doomed", "v2"), ShouldBeNil)
			So(manifestDigest(t, baseURL, "doomed", "v2"), ShouldEqual, repushed.DigestStr())

			// Had the re-push slipped past the limit, a further new name would still fit.
			So(pushNewRepoStatus(t, baseURL, "onemore"), ShouldEqual, http.StatusTooManyRequests)
		})
	})
}
