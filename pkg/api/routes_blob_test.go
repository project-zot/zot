//go:build sync && scrub && metrics && search && lint && mgmt

package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	rcblob "github.com/regclient/regclient/types/blob"
	rcdesc "github.com/regclient/regclient/types/descriptor"
	rcmanifest "github.com/regclient/regclient/types/manifest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	sync_pkg "zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type mockSyncOnDemand struct {
	isStreamingEnabledForRepoFn func(repo string) bool
	streamManagerFn             func() sync_pkg.StreamManager
	fetchManifestForStreamFn    func(ctx context.Context, name, reference string) (rcmanifest.Manifest, error)
}

func (m *mockSyncOnDemand) SyncImage(_ context.Context, _, _ string) error { return nil }

func (m *mockSyncOnDemand) SyncReferrers(_ context.Context, _, _ string, _ []string) error {
	return nil
}

func (m *mockSyncOnDemand) FetchManifestForStream(
	ctx context.Context, name, reference string,
) (rcmanifest.Manifest, error) {
	if m.fetchManifestForStreamFn != nil {
		return m.fetchManifestForStreamFn(ctx, name, reference)
	}

	return nil, zerr.ErrBlobNotFound
}

func (m *mockSyncOnDemand) StreamManager() sync_pkg.StreamManager {
	if m.streamManagerFn != nil {
		return m.streamManagerFn()
	}

	return nil
}

func (m *mockSyncOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	if m.isStreamingEnabledForRepoFn != nil {
		return m.isStreamingEnabledForRepoFn(repo)
	}

	return false
}

type mockStreamManager struct {
	connectClientFn  func(blobDigest string, writer io.Writer) (*sync_pkg.InFlightBlobCopier, error)
	cachedBlobInfoFn func(digest string) (int64, string, error)
}

func (m *mockStreamManager) ConnectClient(
	blobDigest string, writer io.Writer,
) (*sync_pkg.InFlightBlobCopier, error) {
	if m.connectClientFn != nil {
		return m.connectClientFn(blobDigest, writer)
	}

	return nil, zerr.ErrBlobNotFoundInActiveStreams
}

func (m *mockStreamManager) StreamingBlobReader(r *rcblob.BReader) (*rcblob.BReader, error) {
	return r, nil
}

func (m *mockStreamManager) StoreImageForStreaming(_, _ string, _ rcmanifest.Manifest) error {
	return nil
}

func (m *mockStreamManager) StreamingImageManifest(_, _ string) (rcmanifest.Manifest, bool) {
	return nil, false
}

func (m *mockStreamManager) RemoveStreamingImage(_, _ string) {}

func (m *mockStreamManager) CachedBlobInfo(digest string) (int64, string, error) {
	if m.cachedBlobInfoFn != nil {
		return m.cachedBlobInfoFn(digest)
	}

	return 0, "", zerr.ErrBlobNotFound
}

func newStreamingBlobTestRouteHandler(
	t *testing.T,
	store mocks.MockedImageStore,
	syncOnDemand api.SyncOnDemand,
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

func TestGetBlobStreaming(t *testing.T) {
	Convey("GetBlob streaming path", t, func() {
		Convey("falls through to normal 404 when streaming is not enabled for repo", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return false },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.BLOB_UNKNOWN.String())
		})

		Convey("falls through to 400 for non-streamable error even when streaming enabled", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBadBlobDigest
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.DIGEST_INVALID.String())
		})

		Convey("returns 404 BLOB_UNKNOWN when no active stream for blob", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						connectClientFn: func(_ string, _ io.Writer) (*sync_pkg.InFlightBlobCopier, error) {
							return nil, zerr.ErrBlobNotFoundInActiveStreams
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.BLOB_UNKNOWN.String())
		})

		Convey("returns 404 NAME_UNKNOWN when no active stream for repo", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						connectClientFn: func(_ string, _ io.Writer) (*sync_pkg.InFlightBlobCopier, error) {
							return nil, zerr.ErrBlobNotFoundInActiveStreams
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrRepoNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.NAME_UNKNOWN.String())
		})

		Convey("returns 500 on unexpected ConnectClient error", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						connectClientFn: func(_ string, _ io.Writer) (*sync_pkg.InFlightBlobCopier, error) {
							return nil, ErrUnexpectedError
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("streams blob with correct headers when copier succeeds", func() {
			const blobData = "hello streaming world"

			blobDigest := godigest.FromBytes([]byte(blobData))
			blobMediaType := ispec.MediaTypeImageLayerGzip

			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")

			cbr, err := sync_pkg.NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			bReader := rcblob.NewReader(
				rcblob.WithDesc(rcdesc.Descriptor{
					Digest:    blobDigest,
					Size:      int64(len(blobData)),
					MediaType: blobMediaType,
				}),
				rcblob.WithReader(strings.NewReader(blobData)),
			)
			cbr.InitReader(bReader, bReader.GetDescriptor())

			// Drain the CBR so all bytes are written to blobPath. Copy() can then
			// open the file independently and read them back into the response writer.
			buf := make([]byte, len(blobData))
			_, readErr := cbr.Read(buf)
			So(readErr, ShouldEqual, io.EOF)

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						connectClientFn: func(_ string, writer io.Writer) (*sync_pkg.InFlightBlobCopier, error) {
							return sync_pkg.NewInFlightBlobCopier(cbr, blobPath, writer, log.NewTestLogger()), nil
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": blobDigest.String(),
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.Itoa(len(blobData)))
			So(resp.Header.Get("Content-Type"), ShouldEqual, blobMediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, blobDigest.String())

			respBody, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(string(respBody), ShouldEqual, blobData)
		})

		Convey("returns 200 with empty body when copier fails after headers written", func() {
			const blobData = "hello"

			blobDigest := godigest.FromBytes([]byte(blobData))
			blobMediaType := ispec.MediaTypeImageLayerGzip

			dir := t.TempDir()
			blobPath := filepath.Join(dir, "blob.bin")

			cbr, err := sync_pkg.NewChunkedBlobReader(blobPath, log.NewTestLogger())
			So(err, ShouldBeNil)

			bReader := rcblob.NewReader(
				rcblob.WithDesc(rcdesc.Descriptor{
					Digest:    blobDigest,
					Size:      int64(len(blobData)),
					MediaType: blobMediaType,
				}),
				rcblob.WithReader(strings.NewReader(blobData)),
			)
			cbr.InitReader(bReader, bReader.GetDescriptor())

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						connectClientFn: func(_ string, writer io.Writer) (*sync_pkg.InFlightBlobCopier, error) {
							// Use a non-existent on-disk path so Copy() fails at os.Open,
							// after the handler has already written the 200 headers.
							return sync_pkg.NewInFlightBlobCopier(
								cbr,
								filepath.Join(dir, "nonexistent.bin"),
								writer,
								log.NewTestLogger(),
							), nil
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/blobs/sha256:test",
				http.NoBody,
			)
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": blobDigest.String(),
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			// Status 200 was written before Copy() ran; the handler cannot change it.
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, blobDigest.String())
			So(resp.Header.Get("Content-Type"), ShouldEqual, blobMediaType)

			respBody, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(respBody, ShouldBeEmpty)
		})
	})
}

func TestCheckBlobStreaming(t *testing.T) {
	Convey("CheckBlob streaming path", t, func() {
		const blobDigestStr = "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodHead,
				"http://example.com/v2/test/blobs/"+blobDigestStr,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": blobDigestStr,
			})
		}

		Convey("falls through to normal 404 when streaming is not enabled for repo", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return false },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.BLOB_UNKNOWN.String())
		})

		Convey("falls through to 400 for non-streamable error even when streaming enabled", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn:             func() sync_pkg.StreamManager { return &mockStreamManager{} },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrBadBlobDigest
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.DIGEST_INVALID.String())
		})

		Convey("returns 404 BLOB_UNKNOWN when blob not found in stream cache", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn:             func() sync_pkg.StreamManager { return &mockStreamManager{} },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.BLOB_UNKNOWN.String())
		})

		Convey("returns 404 NAME_UNKNOWN when repo not found in stream cache", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn:             func() sync_pkg.StreamManager { return &mockStreamManager{} },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrRepoNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.NAME_UNKNOWN.String())
		})

		Convey("returns 200 with blob headers when blob found in stream cache", func() {
			const blobSize = int64(1024)

			blobMediaType := ispec.MediaTypeImageLayerGzip

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						cachedBlobInfoFn: func(_ string) (int64, string, error) {
							return blobSize, blobMediaType, nil
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.FormatInt(blobSize, 10))
			So(resp.Header.Get("Accept-Ranges"), ShouldEqual, "bytes")
			So(resp.Header.Get("Content-Type"), ShouldEqual, blobMediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, blobDigestStr)
		})

		Convey("returns 200 with blob headers when repo and blob found in stream cache", func() {
			const blobSize = int64(2048)

			blobMediaType := ispec.MediaTypeImageLayerGzip

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						cachedBlobInfoFn: func(_ string) (int64, string, error) {
							return blobSize, blobMediaType, nil
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrRepoNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.FormatInt(blobSize, 10))
			So(resp.Header.Get("Accept-Ranges"), ShouldEqual, "bytes")
			So(resp.Header.Get("Content-Type"), ShouldEqual, blobMediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, blobDigestStr)
		})

		Convey("returns 404 error when stream cache cannot be read", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManagerFn: func() sync_pkg.StreamManager {
					return &mockStreamManager{
						cachedBlobInfoFn: func(_ string) (int64, string, error) {
							return 0, "", zerr.ErrUnknownCode
						},
					}
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(_ string, _ godigest.Digest) (bool, int64, error) {
					return false, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}
