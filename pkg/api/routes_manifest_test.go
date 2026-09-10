//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
