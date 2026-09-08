//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errFakeStreamManager = errors.New("fake stream manager: not configured for this call")

// fakeStreamManager is a minimal sync.StreamManager for exercising RouteHandler's
// writeBlobInfoFromStreamCache (via CheckBlob) and streamBlobToClient (via GetBlob) fallback
// paths, which only ever call CachedBlobInfo and ConnectClient respectively.
type fakeStreamManager struct {
	cachedBlobInfoFn func(repo, blobDigest string) (int64, string, error)
	connectClientFn  func(repo, blobDigest string, writer io.Writer) (sync.BlobCopier, error)
}

func (f *fakeStreamManager) ConnectClient(repo, blobDigest string, writer io.Writer) (sync.BlobCopier, error) {
	if f.connectClientFn != nil {
		return f.connectClientFn(repo, blobDigest, writer)
	}

	return nil, errFakeStreamManager
}

func (f *fakeStreamManager) StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error) {
	return reader, nil
}

func (f *fakeStreamManager) StoreImageForStreaming(_, _ string, m *sync.StreamableManifest,
) (*sync.StreamableManifest, error) {
	return m, nil
}

func (f *fakeStreamManager) StreamingImageManifest(_, _ string) (*sync.StreamableManifest, bool) {
	return nil, false
}

func (f *fakeStreamManager) RemoveStreamingImage(_, _ string) {}

func (f *fakeStreamManager) CachedBlobInfo(repo, blobDigest string) (int64, string, error) {
	if f.cachedBlobInfoFn != nil {
		return f.cachedBlobInfoFn(repo, blobDigest)
	}

	return 0, "", errFakeStreamManager
}

// fakeBlobCopier is a minimal sync.BlobCopier: Descriptor reports desc (or descErr), and Copy
// writes body to whatever writer ConnectClient was given.
type fakeBlobCopier struct {
	desc    descriptor.Descriptor
	descErr error
	body    []byte
	writer  io.Writer
	copyErr error
	closed  bool
	copied  bool
}

func (c *fakeBlobCopier) Descriptor() (descriptor.Descriptor, error) { return c.desc, c.descErr }

func (c *fakeBlobCopier) Copy() error {
	c.copied = true

	if c.copyErr != nil {
		return c.copyErr
	}

	_, err := c.writer.Write(c.body)

	return err
}

func (c *fakeBlobCopier) Close() { c.closed = true }

func newBlobStreamTestRouteHandlerRequest(method, name, digest string) *http.Request {
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
					return false, 0, time.Time{}, nil
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead, "test", digest))

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
					return false, 0, time.Time{}, nil
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead, "test", digest))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("falls through to 404 when there is no stream manager at all", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				// streamManager left nil: SyncOnDemand.StreamManager() returns nil.
			}
			handler := newSyncTestRouteHandler(t, mocks.MockedImageStore{
				StatBlobFn: func(_ string, _ godigest.Digest) (bool, int64, time.Time, error) {
					return false, 0, time.Time{}, nil
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodHead, "test", digest))

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
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet, "test", digest))

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
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet, "test", digest))

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
			handler.GetBlob(rec, newBlobStreamTestRouteHandlerRequest(http.MethodGet, "test", digest))

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}
