//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

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
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	"zotregistry.dev/zot/v2/pkg/test/storageerrclass"
)

var (
	// Stand-in for a contended redis/redsync lock error from UpdateStatsOnDownload.
	errStatsLockContention = errors.New("failed to acquire redis lock")
	errStorageInjected     = errors.New("injected storage failure")
)

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

		Convey("ErrStorageTransient → 503 (not NAME_UNKNOWN 404)", func() {
			So(runCase(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
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

		Convey("ErrStorageTransient returns 503 without DeleteImageManifest", func() {
			status, deletes := runCase(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
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

func TestHTTPStorageClassStatusMapping(t *testing.T) {
	Convey("direct storage Transient → 503, Permanent → 500, never 404-shaped codes", t, func() {
		const (
			repo        = "test"
			validDigest = "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"
			sessionID   = "upload-session"
			reference   = "v1.0"
		)

		newHandler := func(store mocks.MockedImageStore) *api.RouteHandler {
			ctlr := api.NewController(config.New())
			ctlr.Router = mux.NewRouter()
			ctlr.StoreController.DefaultStore = store

			return api.NewRouteHandler(ctlr)
		}

		Convey("CheckBlob", func() {
			run := func(statErr error) (int, string) {
				handler := newHandler(mocks.MockedImageStore{
					StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
						return false, -1, time.Time{}, statErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodHead,
					"http://example.com/v2/"+repo+"/blobs/"+validDigest, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "digest": validDigest})
				rec := httptest.NewRecorder()
				handler.CheckBlob(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				return resp.StatusCode, string(body)
			}

			status, body := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(body, ShouldNotContainSubstring, "BLOB_UNKNOWN")

			status, body = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(body, ShouldNotContainSubstring, "BLOB_UNKNOWN")

			status, body = run(zerr.ErrBlobNotFound)
			So(status, ShouldEqual, http.StatusNotFound)
			So(body, ShouldContainSubstring, "BLOB_UNKNOWN")
		})

		Convey("GetBlob", func() {
			run := func(getErr error) (int, string) {
				handler := newHandler(mocks.MockedImageStore{
					GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
						return nil, -1, getErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
					"http://example.com/v2/"+repo+"/blobs/"+validDigest, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "digest": validDigest})
				rec := httptest.NewRecorder()
				handler.GetBlob(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				return resp.StatusCode, string(body)
			}

			status, body := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(body, ShouldNotContainSubstring, "BLOB_UNKNOWN")

			status, body = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(body, ShouldNotContainSubstring, "BLOB_UNKNOWN")
		})

		Convey("CreateBlobUpload", func() {
			run := func(newErr error) (int, string) {
				handler := newHandler(mocks.MockedImageStore{
					NewBlobUploadFn: func(_ context.Context, _ string) (string, error) {
						return "", newErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
					"http://example.com/v2/"+repo+"/blobs/uploads/", http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo})
				rec := httptest.NewRecorder()
				handler.CreateBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				return resp.StatusCode, string(body)
			}

			status, body := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(body, ShouldNotContainSubstring, "NAME_UNKNOWN")

			status, body = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(body, ShouldNotContainSubstring, "NAME_UNKNOWN")
		})

		Convey("UpdateBlobUpload FinishBlobUpload", func() {
			run := func(finishErr error) (int, string, bool) {
				deleted := false
				handler := newHandler(mocks.MockedImageStore{
					FinishBlobUploadFn: func(_ string, _ string, _ io.Reader, _ godigest.Digest) error {
						return finishErr
					},
					DeleteBlobUploadFn: func(_, _ string) error {
						deleted = true

						return nil
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
					"http://example.com/v2/"+repo+"/blobs/uploads/"+sessionID+"?digest="+validDigest,
					http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "session_id": sessionID})
				q := req.URL.Query()
				q.Set("digest", validDigest)
				req.URL.RawQuery = q.Encode()
				rec := httptest.NewRecorder()
				handler.UpdateBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				return resp.StatusCode, string(body), deleted
			}

			status, body, deleted := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(body, ShouldNotContainSubstring, "BLOB_UPLOAD_UNKNOWN")
			So(deleted, ShouldBeFalse)

			status, body, deleted = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(body, ShouldNotContainSubstring, "BLOB_UPLOAD_UNKNOWN")
			So(deleted, ShouldBeTrue)
		})

		Convey("CheckManifest / GetManifest local Transient without MANIFEST_INVALID", func() {
			store := mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrStorageTransient
				},
			}
			handler := newHandler(store)

			for _, method := range []string{http.MethodHead, http.MethodGet} {
				req := httptest.NewRequestWithContext(context.Background(), method,
					"http://example.com/v2/"+repo+"/manifests/"+reference, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "reference": reference})
				rec := httptest.NewRecorder()
				if method == http.MethodHead {
					handler.CheckManifest(rec, req)
				} else {
					handler.GetManifest(rec, req)
				}
				resp := rec.Result()
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)
				So(string(body), ShouldNotContainSubstring, "MANIFEST_INVALID")
				So(string(body), ShouldNotContainSubstring, "MANIFEST_UNKNOWN")
			}

			handler = newHandler(mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrStoragePermanent
				},
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://example.com/v2/"+repo+"/manifests/"+reference, http.NoBody)
			req = mux.SetURLVars(req, map[string]string{"name": repo, "reference": reference})
			rec := httptest.NewRecorder()
			handler.GetManifest(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("CheckManifest unrecognized error → 500", func() {
			handler := newHandler(mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", errors.New("unexpected manifest failure") //nolint:err113 // test
				},
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodHead,
				"http://example.com/v2/"+repo+"/manifests/"+reference, http.NoBody)
			req = mux.SetURLVars(req, map[string]string{"name": repo, "reference": reference})
			rec := httptest.NewRecorder()
			handler.CheckManifest(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteManifest", func() {
			run := func(getErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
						return nil, "", "", getErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
					"http://example.com/v2/"+repo+"/manifests/"+reference, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "reference": reference})
				rec := httptest.NewRecorder()
				handler.DeleteManifest(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteManifest delete arm Transient/Permanent", func() {
			run := func(deleteErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
						return []byte(`{}`), godigest.Digest(validDigest), ispec.MediaTypeImageManifest, nil
					},
					DeleteImageManifestFn: func(_ context.Context, _ string, _ string, _ bool) error {
						return deleteErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
					"http://example.com/v2/"+repo+"/manifests/"+reference, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "reference": reference})
				rec := httptest.NewRecorder()
				handler.DeleteManifest(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteBlob", func() {
			run := func(deleteErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					DeleteBlobFn: func(_ string, _ godigest.Digest) error {
						return deleteErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
					"http://example.com/v2/"+repo+"/blobs/"+validDigest, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "digest": validDigest})
				rec := httptest.NewRecorder()
				handler.DeleteBlob(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("CreateBlobUpload FullBlobUpload Transient/Permanent", func() {
			run := func(uploadErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					FullBlobUploadFn: func(_ context.Context, _ string, _ io.Reader, _ godigest.Digest,
					) (string, int64, error) {
						return "", -1, uploadErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
					"http://example.com/v2/"+repo+"/blobs/uploads/?digest="+validDigest,
					bytes.NewReader([]byte("blob")))
				req = mux.SetURLVars(req, map[string]string{"name": repo})
				req.Header.Set("Content-Type", constants.BinaryMediaType)
				req.ContentLength = 4
				rec := httptest.NewRecorder()
				handler.CreateBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("GetBlobUpload Transient/Permanent", func() {
			run := func(getErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					GetBlobUploadFn: func(_, _ string) (int64, error) {
						return -1, getErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
					"http://example.com/v2/"+repo+"/blobs/uploads/"+sessionID, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "session_id": sessionID})
				rec := httptest.NewRecorder()
				handler.GetBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("PatchBlobUpload streamed Transient/Permanent", func() {
			run := func(patchErr error) (int, bool) {
				deleted := false
				handler := newHandler(mocks.MockedImageStore{
					PutBlobChunkStreamedFn: func(_ context.Context, _, _ string, _ io.Reader) (int64, error) {
						return -1, patchErr
					},
					DeleteBlobUploadFn: func(_, _ string) error {
						deleted = true

						return nil
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch,
					"http://example.com/v2/"+repo+"/blobs/uploads/"+sessionID,
					bytes.NewReader([]byte("chunk")))
				req = mux.SetURLVars(req, map[string]string{"name": repo, "session_id": sessionID})
				rec := httptest.NewRecorder()
				handler.PatchBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode, deleted
			}

			status, deleted := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(deleted, ShouldBeFalse)

			status, deleted = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(deleted, ShouldBeTrue)
		})

		Convey("UpdateBlobUpload PutBlobChunk Transient/Permanent", func() {
			run := func(chunkErr error) (int, bool) {
				deleted := false
				handler := newHandler(mocks.MockedImageStore{
					PutBlobChunkFn: func(_ context.Context, _, _ string, _, _ int64, _ io.Reader) (int64, error) {
						return -1, chunkErr
					},
					DeleteBlobUploadFn: func(_, _ string) error {
						deleted = true

						return nil
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
					"http://example.com/v2/"+repo+"/blobs/uploads/"+sessionID+"?digest="+validDigest,
					bytes.NewReader([]byte("x")))
				req = mux.SetURLVars(req, map[string]string{"name": repo, "session_id": sessionID})
				req.Header.Set("Content-Length", "1")
				rec := httptest.NewRecorder()
				handler.UpdateBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode, deleted
			}

			status, deleted := run(zerr.ErrStorageTransient)
			So(status, ShouldEqual, http.StatusServiceUnavailable)
			So(deleted, ShouldBeFalse)

			status, deleted = run(zerr.ErrStoragePermanent)
			So(status, ShouldEqual, http.StatusInternalServerError)
			So(deleted, ShouldBeTrue)
		})

		Convey("DeleteBlobUpload Transient/Permanent", func() {
			run := func(deleteErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					DeleteBlobUploadFn: func(_, _ string) error {
						return deleteErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
					"http://example.com/v2/"+repo+"/blobs/uploads/"+sessionID, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "session_id": sessionID})
				rec := httptest.NewRecorder()
				handler.DeleteBlobUpload(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("GetReferrers", func() {
			run := func(refErr error) int {
				handler := newHandler(mocks.MockedImageStore{
					GetReferrersFn: func(_ string, _ godigest.Digest, _ []string) (ispec.Index, error) {
						return ispec.Index{}, refErr
					},
				})
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
					"http://example.com/v2/"+repo+"/referrers/"+validDigest, http.NoBody)
				req = mux.SetURLVars(req, map[string]string{"name": repo, "digest": validDigest})
				rec := httptest.NewRecorder()
				handler.GetReferrers(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			So(run(zerr.ErrStorageTransient), ShouldEqual, http.StatusServiceUnavailable)
			So(run(zerr.ErrStoragePermanent), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ListRepositories Walk-level Transient → 503; soft-skip path stays 200", func() {
			handler := newHandler(mocks.MockedImageStore{
				GetNextRepositoriesFn: func(_ string, _ int, _ storageTypes.FilterRepoFunc,
				) ([]string, bool, error) {
					return nil, false, zerr.ErrStorageTransient
				},
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://example.com/v2/_catalog", http.NoBody)
			rec := httptest.NewRecorder()
			handler.ListRepositories(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)

			handler = newHandler(mocks.MockedImageStore{
				GetNextRepositoriesFn: func(_ string, _ int, _ storageTypes.FilterRepoFunc,
				) ([]string, bool, error) {
					return []string{"kept"}, false, nil
				},
			})
			req = httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://example.com/v2/_catalog", http.NoBody)
			rec = httptest.NewRecorder()
			handler.ListRepositories(rec, req)
			resp = rec.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("ListRepositories on a real local store with injected storage failures", func() {
			imgStore, hooks := storageerrclass.NewStore(t, storageerrclass.Local())
			storeController := storage.StoreController{DefaultStore: imgStore}

			for _, name := range []string{"a/repo", "b", "c/repo"} {
				So(WriteImageToFileSystem(CreateRandomImage(), name, "v1", storeController), ShouldBeNil)
			}

			ctlr := api.NewController(config.New())
			ctlr.Router = mux.NewRouter()
			ctlr.StoreController.DefaultStore = imgStore
			handler := api.NewRouteHandler(ctlr)

			listCatalog := func() (int, string) {
				req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
					"http://example.com/v2/_catalog", http.NoBody)
				rec := httptest.NewRecorder()
				handler.ListRepositories(rec, req)
				resp := rec.Result()
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)

				return resp.StatusCode, string(body)
			}

			Convey("a Transient root walk is 503", func() {
				hooks.AddFault(storageerrclass.Fault{
					Op: storageerrclass.OpWalk, Path: imgStore.RootDir(), Err: errclass.MarkTransient(errStorageInjected),
				})

				status, _ := listCatalog()
				So(status, ShouldEqual, http.StatusServiceUnavailable)
			})

			Convey("a Permanent root walk is 500", func() {
				hooks.AddFault(storageerrclass.Fault{
					Op: storageerrclass.OpWalk, Path: imgStore.RootDir(), Err: errclass.MarkPermanent(errStorageInjected),
				})

				status, _ := listCatalog()
				So(status, ShouldEqual, http.StatusInternalServerError)
			})

			Convey("a Transient failure validating one repository is a partial 200", func() {
				hooks.AddFault(storageerrclass.Fault{
					Op: storageerrclass.OpList, Path: path.Join(imgStore.RootDir(), "b"),
					Err: errclass.MarkTransient(errStorageInjected),
				})

				status, body := listCatalog()
				So(status, ShouldEqual, http.StatusOK)
				So(body, ShouldContainSubstring, `"a/repo"`)
				So(body, ShouldContainSubstring, `"c/repo"`)
				So(body, ShouldNotContainSubstring, `"b"`)
			})
		})
	})
}
