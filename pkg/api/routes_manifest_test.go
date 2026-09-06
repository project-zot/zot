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
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/oci"
	rocispec "github.com/regclient/regclient/types/oci/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	ext "zotregistry.dev/zot/v2/pkg/extensions"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// Stand-in for a contended redis/redsync lock error from UpdateStatsOnDownload.
var errStatsLockContention = errors.New("failed to acquire redis lock")

type mockSyncOnDemand struct {
	syncImageFn                   func(ctx context.Context, repo, reference string) error
	shouldCheckUpstreamManifestFn func(repo, reference string) bool
	fetchManifestForStreamFn      func(ctx context.Context, repo, reference string) (manifest.Manifest, error)
	isStreamingEnabledForRepoFn   func(repo string) bool
	streamManager                 sync.StreamManager
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

func (m *mockSyncOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
) (manifest.Manifest, error) {
	if m.fetchManifestForStreamFn != nil {
		return m.fetchManifestForStreamFn(ctx, repo, reference)
	}

	return nil, zerr.ErrManifestNotFound
}

func (m *mockSyncOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	if m.isStreamingEnabledForRepoFn != nil {
		return m.isStreamingEnabledForRepoFn(repo)
	}

	return false
}

func (m *mockSyncOnDemand) StreamManager() sync.StreamManager {
	return m.streamManager
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

func TestGetManifestStreaming(t *testing.T) {
	Convey("GetManifest fetches directly from upstream for a streaming-enabled repo", t, func() {
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

		// manifest.New only recognizes regclient's own OCI types (github.com/regclient/regclient/types/oci/v1),
		// not github.com/opencontainers/image-spec/specs-go/v1 - the two are structurally similar but
		// distinct Go types, so passing an ispec.Manifest here fails with "unsupported type to convert
		// to a manifest".
		upstreamManifest := rocispec.Manifest{
			Versioned: oci.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Config: descriptor.Descriptor{
				MediaType: ispec.MediaTypeEmptyJSON,
				Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				Size:      2,
				Data:      []byte(`{}`),
			},
		}

		man, err := manifest.New(manifest.WithOrig(upstreamManifest))
		So(err, ShouldBeNil)

		body, err := man.RawBody()
		So(err, ShouldBeNil)

		notFoundStore := mocks.MockedImageStore{
			GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
				return nil, "", "", zerr.ErrManifestNotFound
			},
		}

		Convey("returns the upstream manifest directly, without calling SyncImage", func() {
			syncCalls := 0

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (manifest.Manifest, error) {
					return man, nil
				},
				syncImageFn: func(_ context.Context, _, _ string) error {
					syncCalls++

					return nil
				},
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, man.GetDescriptor().Digest.String())

			respBody, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(respBody, ShouldResemble, body)

			So(syncCalls, ShouldEqual, 0)
		})

		Convey("falls back to the local store when FetchManifestForStream fails", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (manifest.Manifest, error) {
					return nil, zerr.ErrSyncImageNotSigned
				},
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			// notFoundStore has nothing locally either, so the fallback surfaces as 404 - the
			// important assertion is that this path is reached at all (no panic/bad response)
			// when streaming's own fetch fails.
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("falls back to a non-streaming on-demand sync when the concurrent-stream cap is hit", func() {
			localStore := mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return body, man.GetDescriptor().Digest, man.GetDescriptor().MediaType, nil
				},
			}

			syncCalls := 0

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (manifest.Manifest, error) {
					return nil, zerr.ErrTooManyConcurrentStreams
				},
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

			// hitting the cap must fall back to an ordinary (non-streaming) on-demand sync
			// rather than surfacing as a failed request - see RegistryConfig.MaxConcurrentStreams.
			So(syncCalls, ShouldEqual, 1)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			respBody, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(respBody, ShouldResemble, body)
		})
	})
}
