//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errFakeStreamManager = errors.New("fake stream manager: not configured for this call")

// fakeStreamManager is a minimal sync.StreamManager for the blob routes' streaming fallbacks, which
// only call CachedBlobInfo and ConnectClient.
type fakeStreamManager struct {
	cachedBlobInfoFn func(repo, blobDigest string) (int64, string, error)
	connectClientFn  func(repo, blobDigest string, writer io.Writer) (sync.BlobCopier, error)
	// hasStreamsForRepoFn overrides HasStreamsForRepo's default of true.
	hasStreamsForRepoFn func(repo string) bool
}

func (f *fakeStreamManager) ConnectClient(repo, blobDigest string, writer io.Writer) (sync.BlobCopier, error) {
	if f.connectClientFn != nil {
		return f.connectClientFn(repo, blobDigest, writer)
	}

	return nil, errFakeStreamManager
}

func (f *fakeStreamManager) DownloadStreamedBlobs(_ context.Context, _, _ string, _ sync.BlobFetcher,
) map[godigest.Digest]string {
	return nil
}

func (f *fakeStreamManager) StoreImageForStreaming(_, _ string, m *sync.StreamableManifest,
) (*sync.StreamableManifest, error) {
	return m, nil
}

func (f *fakeStreamManager) StreamingImageManifest(_, _ string) (*sync.StreamableManifest, bool) {
	return nil, false
}

func (f *fakeStreamManager) JoinStreamingImage(_, _ string, _ func(manifest.Manifest),
) (*sync.StreamableManifest, bool) {
	return nil, false
}

func (f *fakeStreamManager) RemoveStreamingImage(_, _ string, _ bool) {}

// HasStreamsForRepo defaults to true: these tests model a repo with an image being streamed.
func (f *fakeStreamManager) HasStreamsForRepo(repo string) bool {
	if f.hasStreamsForRepoFn != nil {
		return f.hasStreamsForRepoFn(repo)
	}

	return true
}

func (f *fakeStreamManager) CachedBlobInfo(repo, blobDigest string) (int64, string, error) {
	if f.cachedBlobInfoFn != nil {
		return f.cachedBlobInfoFn(repo, blobDigest)
	}

	return 0, "", errFakeStreamManager
}

// fakeBlobCopier is a minimal sync.BlobCopier: Descriptor returns descFn's result, or desc or
// descErr, and Copy/CopyRange write body (or a slice of it) to the ConnectClient writer.
type fakeBlobCopier struct {
	desc        descriptor.Descriptor
	descErr     error
	descFn      func(ctx context.Context) (descriptor.Descriptor, error)
	body        []byte
	writer      io.Writer
	copyErr     error
	closed      bool
	copied      bool
	rangeStart  int64
	rangeEnd    int64
	copiedRange bool
}

func (c *fakeBlobCopier) Descriptor(ctx context.Context) (descriptor.Descriptor, error) {
	if c.descFn != nil {
		return c.descFn(ctx)
	}

	return c.desc, c.descErr
}

func (c *fakeBlobCopier) Copy() error {
	c.copied = true

	if c.copyErr != nil {
		return c.copyErr
	}

	_, err := c.writer.Write(c.body)

	return err
}

func (c *fakeBlobCopier) CopyRange(start, end int64) error {
	c.copiedRange = true
	c.rangeStart = start
	c.rangeEnd = end

	if c.copyErr != nil {
		return c.copyErr
	}

	_, err := c.writer.Write(c.body[start : end+1])

	return err
}

func (c *fakeBlobCopier) Close() { c.closed = true }

func newBlobStreamTestRouteHandlerRequest(method string) *http.Request {
	const (
		name   = "test"
		digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	)

	req := httptest.NewRequestWithContext(
		context.Background(),
		method,
		"http://example.com/v2/"+name+"/blobs/"+digest,
		http.NoBody,
	)

	return mux.SetURLVars(req, map[string]string{
		"name":   name,
		"digest": digest,
	})
}

func TestCheckBlobStreamingFallback(t *testing.T) {
	Convey("CheckBlob for a streaming-enabled repo", t, func() {
		const digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

		Convey("serves stream-cache info when the blob is not local but is being streamed", func() {
			streamMgr := &fakeStreamManager{
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					return 42, constants.BinaryMediaType, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, "42")
			So(resp.Header.Get("Content-Type"), ShouldEqual, constants.BinaryMediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, digest)
		})

		Convey("falls through to 404 when the blob is neither local nor in the stream cache", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               &fakeStreamManager{}, // CachedBlobInfo always errors
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("does not consult the stream cache on a storage outage", func() {
			for storageErr, status := range map[error]int{
				zerr.ErrStorageTransient: http.StatusServiceUnavailable,
				zerr.ErrStoragePermanent: http.StatusInternalServerError,
			} {
				cacheCalled := false
				syncOnDemand := &mockSyncOnDemand{
					isStreamingEnabledForRepoFn: func(_ string) bool { return true },
					streamManager: &fakeStreamManager{
						cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
							cacheCalled = true

							return 42, constants.BinaryMediaType, nil
						},
					},
				}
				handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
					StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
						return false, -1, time.Time{}, storageErr
					},
				}, syncOnDemand)

				rec := httptest.NewRecorder()
				handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

				resp := rec.Result()
				_ = resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, status)
				So(cacheCalled, ShouldBeFalse)
			}
		})

		Convey("falls through to 404 when there is no stream manager at all", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				// streamManager left nil: SyncOnDemand.StreamManager() returns nil.
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestGetBlobStreamingFallback(t *testing.T) {
	Convey("GetBlob for a streaming-enabled repo", t, func() {
		const digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

		notFoundStore := mocks.MockedImageStore{
			GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
				return nil, 0, zerr.ErrBlobNotFound
			},
		}

		Convey("streams the blob from the active upstream stream", func() {
			body := []byte("streamed blob content")
			copier := &fakeBlobCopier{
				desc: descriptor.Descriptor{Size: int64(len(body))},
				body: body,
			}
			streamMgr := &fakeStreamManager{
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Type"), ShouldEqual, constants.BinaryMediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, digest)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body)
			So(copier.copied, ShouldBeTrue)
		})

		Convey("falls through to the not-found error when the descriptor never becomes ready", func() {
			copier := &fakeBlobCopier{descErr: errFakeStreamManager}
			streamMgr := &fakeStreamManager{
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(copier.copied, ShouldBeFalse)
			So(copier.closed, ShouldBeTrue)
		})

		Convey("falls through to the not-found error when there is no active stream", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               &fakeStreamManager{}, // ConnectClient always errors
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("waits for the download only while the client is connected", func() {
			copier := &fakeBlobCopier{}
			streamMgr := &fakeStreamManager{
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// The download never starts; like the real copier, the fake only stops waiting
			// when the request's context is done (the client disconnected).
			copier.descFn = func(waitCtx context.Context) (descriptor.Descriptor, error) {
				cancel()

				select {
				case <-waitCtx.Done():
					return descriptor.Descriptor{}, waitCtx.Err()
				case <-time.After(10 * time.Second):
					return descriptor.Descriptor{}, errFakeStreamManager
				}
			}

			// The mux vars live in the request's context, so carry them over to the new one.
			req := newBlobStreamTestRouteHandlerRequest(http.MethodGet)
			req = mux.SetURLVars(req.WithContext(ctx), mux.Vars(req))

			start := time.Now()
			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(time.Since(start), ShouldBeLessThan, 5*time.Second)
			So(copier.copied, ShouldBeFalse)
			So(copier.closed, ShouldBeTrue)
		})

		Convey("does not try the stream or retry storage on a storage outage", func() {
			for storageErr, status := range map[error]int{
				zerr.ErrStorageTransient: http.StatusServiceUnavailable,
				zerr.ErrStoragePermanent: http.StatusInternalServerError,
			} {
				getBlobCalls := 0
				outageStore := mocks.MockedImageStore{
					GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
						getBlobCalls++

						return nil, 0, storageErr
					},
				}
				connectCalled := false
				streamMgr := &fakeStreamManager{
					connectClientFn: func(_, _ string, _ io.Writer) (sync.BlobCopier, error) {
						connectCalled = true

						return nil, errFakeStreamManager
					},
				}
				syncOnDemand := &mockSyncOnDemand{
					isStreamingEnabledForRepoFn: func(_ string) bool { return true },
					streamManager:               streamMgr,
				}
				handler := newSyncTestRouteHandler(t, outageStore, syncOnDemand)

				rec := httptest.NewRecorder()
				handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

				resp := rec.Result()
				_ = resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, status)
				So(connectCalled, ShouldBeFalse)
				So(getBlobCalls, ShouldEqual, 1)
			}
		})
	})
}

// TestGetBlobRedirectMissFallsBackToStream: with redirectBlobURL on, a blob not committed yet
// misses the redirect lookup; for a streaming repo that must fall through to the stream rather
// than 404, since only range GETs would otherwise ever reach it.
func TestGetBlobRedirectMissFallsBackToStream(t *testing.T) {
	Convey("GetBlob with blob redirects enabled", t, func() {
		redirectCalls := 0

		notFoundStore := mocks.MockedImageStore{
			GetBlobRedirectURLFn: func(_ *http.Request, _ string, _ godigest.Digest) (string, error) {
				redirectCalls++

				return "", zerr.ErrBlobNotFound
			},
			GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
				return nil, 0, zerr.ErrBlobNotFound
			},
		}

		enableRedirect := func(cfg *config.Config) { cfg.Storage.RedirectBlobURL = true }

		get := func(syncOnDemand *mockSyncOnDemand) *http.Response {
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand, enableRedirect)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			return rec.Result()
		}

		Convey("streams a blob the redirect lookup can't find yet", func() {
			body := []byte("streamed blob content")
			copier := &fakeBlobCopier{desc: descriptor.Descriptor{Size: int64(len(body))}, body: body}

			resp := get(&mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager: &fakeStreamManager{
					connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
						copier.writer = writer

						return copier, nil
					},
				},
			})
			defer resp.Body.Close()

			So(redirectCalls, ShouldEqual, 1)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body)
		})

		Convey("still 404s when the blob isn't streaming either", func() {
			resp := get(&mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               &fakeStreamManager{}, // ConnectClient always errors
			})
			defer resp.Body.Close()

			So(redirectCalls, ShouldEqual, 1)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("returns the redirect lookup's error for a repo with no streams", func() {
			connectCalls := 0

			resp := get(&mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager: &fakeStreamManager{
					hasStreamsForRepoFn: func(_ string) bool { return false },
					connectClientFn: func(_, _ string, _ io.Writer) (sync.BlobCopier, error) {
						connectCalls++

						return nil, errFakeStreamManager
					},
				},
			})
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(connectCalls, ShouldEqual, 0)
		})
	})
}

func TestGetBlobRangeStreamingFallback(t *testing.T) {
	Convey("GetBlob with a Range header for a streaming-enabled repo", t, func() {
		const digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

		body := []byte("streamed blob content")

		notFoundStore := mocks.MockedImageStore{
			StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
				return false, -1, time.Time{}, zerr.ErrBlobNotFound
			},
		}

		newRangeRequest := func(rangeHeader string) *http.Request {
			req := newBlobStreamTestRouteHandlerRequest(http.MethodGet)
			req.Header.Set("Range", rangeHeader)

			return req
		}

		Convey("streams a single range from the active upstream stream", func() {
			copier := &fakeBlobCopier{desc: descriptor.Descriptor{Size: int64(len(body))}, body: body}
			streamMgr := &fakeStreamManager{
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					return int64(len(body)), constants.BinaryMediaType, nil
				},
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest("bytes=9-17"))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusPartialContent)
			So(resp.Header.Get("Content-Range"), ShouldEqual, fmt.Sprintf("bytes 9-17/%d", len(body)))
			So(resp.Header.Get("Content-Length"), ShouldEqual, "9")
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, digest)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body[9:18])
			So(copier.copiedRange, ShouldBeTrue)
			So(copier.rangeStart, ShouldEqual, 9)
			So(copier.rangeEnd, ShouldEqual, 17)
		})

		Convey("returns 416 for an out-of-bounds range against a digest that is streaming", func() {
			streamMgr := &fakeStreamManager{
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					return int64(len(body)), constants.BinaryMediaType, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest(fmt.Sprintf("bytes=%d-%d", len(body)+10, len(body)+20)))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
			So(resp.Header.Get("Content-Range"), ShouldEqual, fmt.Sprintf("bytes */%d", len(body)))
		})

		Convey("falls through without writing a 206 when the producer never becomes ready", func() {
			copier := &fakeBlobCopier{descErr: errFakeStreamManager, body: body}
			streamMgr := &fakeStreamManager{
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					return int64(len(body)), constants.BinaryMediaType, nil
				},
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest("bytes=0-3"))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(copier.copiedRange, ShouldBeFalse)
			So(copier.closed, ShouldBeTrue)
		})

		Convey("serves the whole blob with a 200 for a multi-range request against a streaming digest", func() {
			copier := &fakeBlobCopier{desc: descriptor.Descriptor{Size: int64(len(body))}, body: body}
			streamMgr := &fakeStreamManager{
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					return int64(len(body)), constants.BinaryMediaType, nil
				},
				connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
					copier.writer = writer

					return copier, nil
				},
			}
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               streamMgr,
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest("bytes=0-2,4-6"))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body)
			So(copier.copied, ShouldBeTrue)
			So(copier.copiedRange, ShouldBeFalse)
		})

		Convey("falls through to 404 when the digest is not staged for streaming either", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager:               &fakeStreamManager{}, // CachedBlobInfo always errors
			}
			handler := newSyncTestRouteHandler(t, notFoundStore, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest("bytes=0-2"))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("does not consult the stream on a storage outage", func() {
			cacheCalled := false
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				streamManager: &fakeStreamManager{
					cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
						cacheCalled = true

						return int64(len(body)), constants.BinaryMediaType, nil
					},
				},
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, zerr.ErrStorageTransient
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newRangeRequest("bytes=0-2"))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusServiceUnavailable)
			So(cacheCalled, ShouldBeFalse)
		})
	})
}

// TestBlobRoutesOnDemandInBackgroundWinsOverStreaming: when background mode wins for a repo,
// nothing is staged, so the blob routes return their normal 404.
func TestBlobRoutesOnDemandInBackgroundWinsOverStreaming(t *testing.T) {
	Convey("Blob routes when onDemandInBackground and streaming both match the repo", t, func() {
		syncOnDemand := &mockSyncOnDemand{
			shouldQueueOnDemandSyncFn:   func(_ string) bool { return true },
			isStreamingEnabledForRepoFn: func(_ string) bool { return true },
			streamManager:               &fakeStreamManager{}, // nothing staged: every lookup errors
		}
		handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
			StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
				return false, -1, time.Time{}, zerr.ErrBlobNotFound
			},
			GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
				return nil, 0, zerr.ErrBlobNotFound
			},
		}, syncOnDemand)

		Convey("HEAD returns 404", func() {
			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("GET returns 404", func() {
			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}

// TestBlobRoutesRecheckStorageAfterStreamMiss: the sync commits a blob before dropping its stream,
// so a request can miss both. Each blob route must recheck storage instead of returning 404.
func TestBlobRoutesRecheckStorageAfterStreamMiss(t *testing.T) {
	Convey("A blob committed between the storage miss and the stream-cache miss", t, func() {
		body := []byte("blob committed by the background sync")

		syncOnDemand := &mockSyncOnDemand{
			isStreamingEnabledForRepoFn: func(_ string) bool { return true },
			streamManager:               &fakeStreamManager{}, // stream already dropped
		}

		statCalls := 0
		getCalls := 0
		store := mocks.MockedImageStore{
			// Missing on the first lookup, committed by the second.
			StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
				statCalls++
				if statCalls == 1 {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				}

				return true, int64(len(body)), time.Time{}, nil
			},
			GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
				getCalls++
				if getCalls == 1 {
					return nil, 0, zerr.ErrBlobNotFound
				}

				return io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
			},
			GetBlobPartialFn: func(_ string, _ godigest.Digest, _ string, from, to int64,
			) (io.ReadCloser, int64, int64, error) {
				return io.NopCloser(bytes.NewReader(body[from : to+1])), to - from + 1, int64(len(body)), nil
			},
		}
		handler := newSyncTestRouteHandler(t, store, syncOnDemand)

		Convey("HEAD reports the blob", func() {
			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.Itoa(len(body)))
			So(statCalls, ShouldEqual, 2)
		})

		Convey("Range GET serves the range", func() {
			req := newBlobStreamTestRouteHandlerRequest(http.MethodGet)
			req.Header.Set("Range", "bytes=0-3")

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusPartialContent)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body[:4])
			So(statCalls, ShouldEqual, 2)
		})

		Convey("plain GET serves the blob", func() {
			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			respBody, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(respBody, ShouldResemble, body)
			So(getCalls, ShouldEqual, 2)
		})
	})
}

// TestBlobRoutesServeRetainedStreamsAfterReload: a reload can stop a repo streaming, or turn sync
// off, while the stream manager keeps its in-flight streams (a reload never drops it, and with sync
// off the controller keeps the previous SyncOnDemand). A client already served the manifest must
// still get the blobs from them, not a 404.
func TestBlobRoutesServeRetainedStreamsAfterReload(t *testing.T) {
	falseVal := false

	for name, configure := range map[string]func(*config.Config){
		"the repo no longer streams": func(*config.Config) {},
		"sync is turned off":         func(cfg *config.Config) { cfg.Extensions.Sync.Enable = &falseVal },
	} {
		Convey("Blob routes with streams staged before a reload: "+name, t, func() {
			body := []byte("blob staged before the reload")

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return false },
				streamManager: &fakeStreamManager{
					cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
						return int64(len(body)), constants.BinaryMediaType, nil
					},
					connectClientFn: func(_, _ string, writer io.Writer) (sync.BlobCopier, error) {
						return &fakeBlobCopier{
							desc:   descriptor.Descriptor{Size: int64(len(body))},
							body:   body,
							writer: writer,
						}, nil
					},
				},
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				},
				GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
					return nil, 0, zerr.ErrBlobNotFound
				},
			}, syncOnDemand, configure)

			Convey("HEAD is answered from the stream", func() {
				rec := httptest.NewRecorder()
				handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

				resp := rec.Result()
				defer resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.Itoa(len(body)))
			})

			Convey("GET is streamed", func() {
				rec := httptest.NewRecorder()
				handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

				resp := rec.Result()
				defer resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, http.StatusOK)

				respBody, err := io.ReadAll(resp.Body)
				So(err, ShouldBeNil)
				So(respBody, ShouldResemble, body)
			})
		})
	}
}

// TestBlobRoutesSkipStreamsForRepoWithoutStreams: with streaming configured but nothing staged for
// the repo, a miss (e.g. a client's HEAD before pushing a blob) costs one storage lookup, as without
// streaming: no stream lookup and no recheck.
func TestBlobRoutesSkipStreamsForRepoWithoutStreams(t *testing.T) {
	Convey("Blob routes for a repo with nothing staged", t, func() {
		var statCalls, getCalls, streamCalls int

		syncOnDemand := &mockSyncOnDemand{
			isStreamingEnabledForRepoFn: func(_ string) bool { return true },
			streamManager: &fakeStreamManager{
				hasStreamsForRepoFn: func(_ string) bool { return false },
				cachedBlobInfoFn: func(_, _ string) (int64, string, error) {
					streamCalls++

					return 0, "", errFakeStreamManager
				},
				connectClientFn: func(_, _ string, _ io.Writer) (sync.BlobCopier, error) {
					streamCalls++

					return nil, errFakeStreamManager
				},
			},
		}
		handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
			StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
				statCalls++

				return false, -1, time.Time{}, zerr.ErrBlobNotFound
			},
			GetBlobFn: func(_ string, _ godigest.Digest, _ string) (io.ReadCloser, int64, error) {
				getCalls++

				return nil, 0, zerr.ErrBlobNotFound
			},
		}, syncOnDemand)

		Convey("HEAD", func() {
			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(statCalls, ShouldEqual, 1)
			So(streamCalls, ShouldEqual, 0)
		})

		Convey("GET", func() {
			rec := httptest.NewRecorder()
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
			So(getCalls, ShouldEqual, 1)
			So(streamCalls, ShouldEqual, 0)
		})
	})
}
