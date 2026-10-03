//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	ext "zotregistry.dev/zot/v2/pkg/extensions"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// Stand-in for a contended redis/redsync lock error from UpdateStatsOnDownload.
var errStatsLockContention = errors.New("failed to acquire redis lock")

type mockSyncOnDemand struct {
	syncImageFn                   func(ctx context.Context, repo, reference string) error
	shouldCheckUpstreamManifestFn func(repo, reference string) bool
}

func (m *mockSyncOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	if m.syncImageFn != nil {
		return m.syncImageFn(ctx, repo, reference)
	}

	return nil
}

func (m *mockSyncOnDemand) SyncReferrers(_ context.Context, _, _ string, _ []string) error {
	return nil
}

func (m *mockSyncOnDemand) ShouldCheckUpstreamManifest(repo, reference string) bool {
	if m.shouldCheckUpstreamManifestFn != nil {
		return m.shouldCheckUpstreamManifestFn(repo, reference)
	}

	return true
}

func (m *mockSyncOnDemand) ShouldQueueOnDemandSync(string) bool {
	return false
}

func (m *mockSyncOnDemand) QueueImage(context.Context, string, string) {}

func newSyncTestRouteHandler(
	t *testing.T,
	store mocks.MockedImageStore,
	syncOnDemand ext.SyncOnDemand,
) *api.RouteHandler {
	t.Helper()

	trueVal := true

	ctlr := api.NewController(config.New())
	ctlr.Router = mux.NewRouter()
	ctlr.Config.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &trueVal},
	}
	ctlr.StoreController.DefaultStore = store
	ctlr.SyncOnDemand = syncOnDemand

	return api.NewRouteHandler(ctlr)
}

func TestListTagsStorageErrors(t *testing.T) {
	Convey("ListTags maps storage classes without collapsing outages to NAME_UNKNOWN", t, func() {
		runCase := func(tagsErr error) int {
			ctlr := api.NewController(config.New())
			ctlr.Router = mux.NewRouter()
			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				GetImageTagsFn: func(_ string) ([]string, error) {
					return nil, tagsErr
				},
			}

			handler := api.NewRouteHandler(ctlr)
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/tags/list",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{"name": "test"})

			rec := httptest.NewRecorder()
			handler.ListTags(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			return resp.StatusCode
		}

		Convey("ErrRepoNotFound → 404", func() {
			So(runCase(zerr.ErrRepoNotFound), ShouldEqual, http.StatusNotFound)
		})

		Convey("ErrStorageTransient → 500 (not NAME_UNKNOWN 404)", func() {
			So(runCase(zerr.ErrStorageTransient), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ErrStoragePermanent → 500 (not NAME_UNKNOWN 404)", func() {
			So(runCase(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestUpdateManifestStorageErrorsSkipCleanup(t *testing.T) {
	Convey("UpdateManifest does not delete an existing reference on PutImageManifest errors", t, func() {
		const (
			repo      = "test"
			reference = "v1.0"
		)

		manifestBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPut,
				"http://example.com/v2/"+repo+"/manifests/"+reference,
				bytes.NewReader(manifestBody),
			)
			req.Header.Set("Content-Type", ispec.MediaTypeImageManifest)

			return mux.SetURLVars(req, map[string]string{
				"name":      repo,
				"reference": reference,
			})
		}

		runCase := func(putErr error) (int, int) {
			deleteCalls := 0
			ctlr := api.NewController(config.New())
			ctlr.Router = mux.NewRouter()
			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				PutImageManifestFn: func(_ context.Context, _, _, _ string, _ []byte, _ []string,
				) (godigest.Digest, godigest.Digest, error) {
					return "", "", putErr
				},
				DeleteImageManifestFn: func(_ context.Context, _, _ string, _ bool) error {
					deleteCalls++

					return nil
				},
			}

			handler := api.NewRouteHandler(ctlr)
			rec := httptest.NewRecorder()
			handler.UpdateManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			return resp.StatusCode, deleteCalls
		}

		Convey("ErrStorageTransient returns 500 without DeleteImageManifest", func() {
			status, deletes := runCase(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(deletes, ShouldEqual, 0)
		})

		Convey("ErrStoragePermanent returns 500 without DeleteImageManifest", func() {
			status, deletes := runCase(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(deletes, ShouldEqual, 0)
		})

		Convey("unrecognized pre-commit errors return 500 without DeleteImageManifest", func() {
			status, deletes := runCase(io.ErrShortWrite)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(deletes, ShouldEqual, 0)
		})
	})
}

func TestGetManifestServesDespiteStatsError(t *testing.T) {
	Convey("GetManifest serves the manifest when download-stats update fails", t, func() {
		const (
			reference    = "v1.0"
			statsFailMsg = "failed to update stats on download image"
		)

		manifest := []byte(`{"schemaVersion":2}`)
		digest := godigest.FromBytes(manifest)

		newHandler := func(statsErr error) (*api.RouteHandler, *bytes.Buffer) {
			var logBuf bytes.Buffer

			ctlr := api.NewController(config.New())
			ctlr.Log = log.NewLoggerWithWriter("debug", &logBuf)
			ctlr.Router = mux.NewRouter()
			ctlr.StoreController.DefaultStore = mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return manifest, digest, ispec.MediaTypeImageManifest, nil
				},
			}
			ctlr.MetaDB = mocks.MetaDBMock{
				UpdateStatsOnDownloadFn: func(_ string, _ string) error {
					return statsErr
				},
			}

			return api.NewRouteHandler(ctlr), &logBuf
		}

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		assertServed := func(handler *api.RouteHandler) {
			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, digest.String())
			So(resp.Header.Get("Content-Type"), ShouldEqual, ispec.MediaTypeImageManifest)

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(body, ShouldResemble, manifest)
		}

		Convey("when UpdateStatsOnDownload returns ErrRepoMetaNotFound", func() {
			handler, logBuf := newHandler(zerr.ErrRepoMetaNotFound)
			assertServed(handler)
			So(logBuf.String(), ShouldNotContainSubstring, statsFailMsg)
		})

		Convey("when UpdateStatsOnDownload returns a lock-style error", func() {
			handler, logBuf := newHandler(errStatsLockContention)
			assertServed(handler)
			So(logBuf.String(), ShouldContainSubstring, `"level":"warn"`)
			So(logBuf.String(), ShouldContainSubstring, statsFailMsg)
			So(logBuf.String(), ShouldNotContainSubstring, `"level":"error"`)
		})
	})
}

func TestGetManifestCheckInterval(t *testing.T) {
	Convey("GetManifest honours the manifest check interval", t, func() {
		const reference = "v1.0"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		localManifest := []byte(`{"schemaVersion":2}`)
		localDigest := godigest.FromBytes(localManifest)

		localStore := mocks.MockedImageStore{
			GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
				return localManifest, localDigest, ispec.MediaTypeImageManifest, nil
			},
		}

		Convey("serves the local manifest without syncing while the interval has not elapsed", func() {
			syncCalls := 0

			syncOnDemand := &mockSyncOnDemand{
				shouldCheckUpstreamManifestFn: func(_, _ string) bool { return false },
				syncImageFn: func(_ context.Context, _, _ string) error {
					syncCalls++

					return nil
				},
			}
			handler := newSyncTestRouteHandler(t, localStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, localDigest.String())

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(body, ShouldResemble, localManifest)

			So(syncCalls, ShouldEqual, 0)
		})

		Convey("falls through to sync when the local manifest is missing", func() {
			syncCalls := 0

			syncOnDemand := &mockSyncOnDemand{
				shouldCheckUpstreamManifestFn: func(_, _ string) bool { return false },
				syncImageFn: func(_ context.Context, _, _ string) error {
					syncCalls++

					return nil
				},
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(syncCalls, ShouldEqual, 1)
		})

		Convey("syncs when the interval has elapsed even though the manifest is local", func() {
			syncCalls := 0

			syncOnDemand := &mockSyncOnDemand{
				shouldCheckUpstreamManifestFn: func(_, _ string) bool { return true },
				syncImageFn: func(_ context.Context, _, _ string) error {
					syncCalls++

					return nil
				},
			}
			handler := newSyncTestRouteHandler(t, localStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(syncCalls, ShouldEqual, 1)
		})
	})
}

func TestGetManifestOnDemandSyncErrors(t *testing.T) {
	Convey("GetManifest maps opaque sync sentinels only when the cache is empty", t, func() {
		const reference = "v1.0"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		Convey("serves a cached manifest when the upstream refresh fails", func() {
			localManifest := []byte(`{"schemaVersion":2}`)
			localDigest := godigest.FromBytes(localManifest)
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return localManifest, localDigest, ispec.MediaTypeImageManifest, nil
				},
			}, &mockSyncOnDemand{
				syncImageFn: func(_ context.Context, _, _ string) error {
					return zerr.ErrSyncInternal
				},
			})

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(strings.TrimSpace(string(body)), ShouldEqual, string(localManifest))
		})

		Convey("keeps 404 when sync only reports a content-filter miss", func() {
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, &mockSyncOnDemand{
				syncImageFn: func(_ context.Context, _, _ string) error {
					return zerr.ErrSyncImageFilteredOut
				},
			})

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("prefers a local storage error over a sync failure", func() {
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrStoragePermanent
				},
			}, &mockSyncOnDemand{
				syncImageFn: func(_ context.Context, _, _ string) error {
					return zerr.ErrSyncInternal
				},
			})

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("returns 503 when sync reports an internal failure", func() {
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, &mockSyncOnDemand{
				syncImageFn: func(_ context.Context, _, _ string) error {
					return zerr.ErrSyncInternal
				},
			})

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)
			So(string(body), ShouldContainSubstring, zerr.ErrSyncInternal.Error())
		})
	})
}

func TestCheckManifestOnDemandSyncErrors(t *testing.T) {
	Convey("CheckManifest maps opaque sync sentinels only when the cache is empty", t, func() {
		const reference = "v1.0"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodHead,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		Convey("returns 503 when sync reports an internal failure", func() {
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, &mockSyncOnDemand{
				syncImageFn: func(_ context.Context, _, _ string) error {
					return zerr.ErrSyncInternal
				},
			})

			rec := httptest.NewRecorder()
			handler.CheckManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)
			So(string(body), ShouldContainSubstring, zerr.ErrSyncInternal.Error())
		})
	})
}
