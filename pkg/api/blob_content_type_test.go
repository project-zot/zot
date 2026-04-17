package api_test

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func testLayerDigest() godigest.Digest { return godigest.FromString("layer") }

func testManifestDigest() godigest.Digest { return godigest.FromString("manifest") }

func testConfigDigest() godigest.Digest { return godigest.FromString("config") }

func newBlobRouteHandler(store mocks.MockedImageStore) *api.RouteHandler {
	controller := api.NewController(config.New())
	controller.Router = mux.NewRouter()
	controller.StoreController.DefaultStore = store

	return api.NewRouteHandler(controller)
}

func descriptorFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()

	manifest := ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    testConfigDigest(),
			Size:      1,
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    testLayerDigest(),
				Size:      4,
			},
		},
	}
	manifest.SchemaVersion = 2

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	index := ispec.Index{
		Manifests: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    testManifestDigest(),
				Size:      int64(len(manifestJSON)),
				Annotations: map[string]string{
					ispec.AnnotationRefName: "latest",
				},
			},
		},
	}
	index.SchemaVersion = 2

	indexJSON, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	return indexJSON, manifestJSON
}

func descriptorStore(t *testing.T) mocks.MockedImageStore {
	t.Helper()

	indexJSON, manifestJSON := descriptorFixture(t)

	return mocks.MockedImageStore{
		RootDirFn: func() string { return "/tmp" },
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			if digest == testLayerDigest() {
				return true, 4, nil
			}

			return true, 0, nil
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return indexJSON, nil
		},
		GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
			if digest == testManifestDigest() {
				return manifestJSON, nil
			}

			t.Fatalf("unexpected blob content lookup for %s", digest)

			return nil, nil
		},
	}
}

func TestCheckBlobUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.CheckBlobFn = func(repo string, digest godigest.Digest) (bool, int64, error) {
		return true, 42, nil
	}

	handler := newBlobRouteHandler(store)

	req := httptest.NewRequest(http.MethodHead, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testLayerDigest().String(),
	})

	rec := httptest.NewRecorder()
	handler.CheckBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got := resp.Header.Get("Content-Type"); got != ispec.MediaTypeImageLayerGzip {
		t.Fatalf("content-type = %q, want %q", got, ispec.MediaTypeImageLayerGzip)
	}
}

func TestGetBlobUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.GetBlobFn = func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
		if mediaType != ispec.MediaTypeImageLayerGzip {
			t.Fatalf("mediaType = %q, want %q", mediaType, ispec.MediaTypeImageLayerGzip)
		}

		return io.NopCloser(strings.NewReader("blob")), 4, nil
	}

	handler := newBlobRouteHandler(store)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testLayerDigest().String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got := resp.Header.Get("Content-Type"); got != ispec.MediaTypeImageLayerGzip {
		t.Fatalf("content-type = %q, want %q", got, ispec.MediaTypeImageLayerGzip)
	}
}

func TestGetBlobPartialFallsBackToBinaryContentType(t *testing.T) {
	handler := newBlobRouteHandler(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 4, nil
		},
		GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
			if mediaType != constants.BinaryMediaType {
				t.Fatalf("mediaType = %q, want %q", mediaType, constants.BinaryMediaType)
			}

			return io.NopCloser(strings.NewReader("blob")), 4, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got := resp.Header.Get("Content-Type"); got != constants.BinaryMediaType {
		t.Fatalf("content-type = %q, want %q", got, constants.BinaryMediaType)
	}
}

func TestGetBlobPartialUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.GetBlobPartialFn = func(
		repo string,
		digest godigest.Digest,
		mediaType string,
		from,
		to int64,
	) (io.ReadCloser, int64, int64, error) {
		if mediaType != ispec.MediaTypeImageLayerGzip {
			t.Fatalf("mediaType = %q, want %q", mediaType, ispec.MediaTypeImageLayerGzip)
		}

		if from != 0 || to != 1 {
			t.Fatalf("range = %d-%d, want 0-1", from, to)
		}

		return io.NopCloser(strings.NewReader("bl")), 2, 4, nil
	}

	handler := newBlobRouteHandler(store)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testLayerDigest().String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}

	if got := resp.Header.Get("Content-Type"); got != ispec.MediaTypeImageLayerGzip {
		t.Fatalf("content-type = %q, want %q", got, ispec.MediaTypeImageLayerGzip)
	}
}

func TestGetBlobFallsBackToBinaryContentType(t *testing.T) {
	handler := newBlobRouteHandler(mocks.MockedImageStore{
		GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
			if mediaType != constants.BinaryMediaType {
				t.Fatalf("mediaType = %q, want %q", mediaType, constants.BinaryMediaType)
			}

			return io.NopCloser(strings.NewReader("blob")), 4, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testLayerDigest().String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if got := resp.Header.Get("Content-Type"); got != constants.BinaryMediaType {
		t.Fatalf("content-type = %q, want %q", got, constants.BinaryMediaType)
	}
}

func TestGetBlobSupportsMultipleRanges(t *testing.T) {
	const blob = "0123456789"

	handler := newBlobRouteHandler(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, int64(len(blob)), nil
		},
		GetBlobPartialFn: func(
			repo string,
			digest godigest.Digest,
			mediaType string,
			from,
			to int64,
		) (io.ReadCloser, int64, int64, error) {
			if mediaType != constants.BinaryMediaType {
				t.Fatalf("mediaType = %q, want %q", mediaType, constants.BinaryMediaType)
			}

			return io.NopCloser(strings.NewReader(blob[from : to+1])), to - from + 1, int64(len(blob)), nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1,5-7")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testLayerDigest().String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}

	contentType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse media type: %v", err)
	}

	if contentType != "multipart/byteranges" {
		t.Fatalf("content-type = %q, want multipart/byteranges", contentType)
	}

	reader := multipart.NewReader(resp.Body, params["boundary"])

	firstPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("read first part: %v", err)
	}

	firstBody, err := io.ReadAll(firstPart)
	if err != nil {
		t.Fatalf("read first body: %v", err)
	}

	if got := string(firstBody); got != "01" {
		t.Fatalf("first body = %q, want %q", got, "01")
	}

	if got := firstPart.Header.Get("Content-Range"); got != "bytes 0-1/10" {
		t.Fatalf("first content-range = %q, want %q", got, "bytes 0-1/10")
	}

	if got := firstPart.Header.Get("Content-Type"); got != constants.BinaryMediaType {
		t.Fatalf("first part content-type = %q, want %q", got, constants.BinaryMediaType)
	}

	secondPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("read second part: %v", err)
	}

	secondBody, err := io.ReadAll(secondPart)
	if err != nil {
		t.Fatalf("read second body: %v", err)
	}

	if got := string(secondBody); got != "567" {
		t.Fatalf("second body = %q, want %q", got, "567")
	}

	if got := secondPart.Header.Get("Content-Range"); got != "bytes 5-7/10" {
		t.Fatalf("second content-range = %q, want %q", got, "bytes 5-7/10")
	}

	if got := secondPart.Header.Get("Content-Type"); got != constants.BinaryMediaType {
		t.Fatalf("second part content-type = %q, want %q", got, constants.BinaryMediaType)
	}

	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
