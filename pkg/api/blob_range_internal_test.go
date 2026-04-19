package api

import (
	"context"
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func testBlobDigest() godigest.Digest {
	return godigest.FromString("layer")
}

func newInternalBlobRouteHandler(store mocks.MockedImageStore) *RouteHandler {
	controller := NewController(config.New())
	controller.Router = mux.NewRouter()
	controller.StoreController.DefaultStore = store

	return NewRouteHandler(controller)
}

func withBinaryFallback(store mocks.MockedImageStore) mocks.MockedImageStore {
	store.GetIndexContentFn = func(repo string) ([]byte, error) {
		return nil, zerr.ErrRepoNotFound
	}

	return store
}

func newBlobGetRequest(rangeHeader string, forceEmptyRange bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/"+testBlobDigest().String(), nil)
	if forceEmptyRange {
		req.Header["Range"] = []string{""}
	} else if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	return mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": testBlobDigest().String(),
	})
}

type trackedReadCloser struct {
	reader   io.Reader
	closeErr error
	closed   bool
}

func (reader *trackedReadCloser) Read(p []byte) (int, error) {
	return reader.reader.Read(p)
}

func (reader *trackedReadCloser) Close() error {
	reader.closed = true

	return reader.closeErr
}

type erroringResponseWriter struct {
	header http.Header
	status int
	err    error
}

func (writer *erroringResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}

	return writer.header
}

func (writer *erroringResponseWriter) WriteHeader(status int) {
	writer.status = status
}

func (writer *erroringResponseWriter) Write(p []byte) (int, error) {
	return 0, writer.err
}

func TestParseRangeHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		header  string
		size    int64
		want    []blobRange
		wantErr error
	}{
		{
			name:   "empty header",
			header: "",
			size:   10,
			want:   nil,
		},
		{
			name:    "invalid prefix",
			header:  "items=0-1",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:    "missing dash",
			header:  "bytes=1",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:    "empty range member",
			header:  "bytes=0-1,",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:    "malformed suffix",
			header:  "bytes=--1",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:    "nonnumeric suffix",
			header:  "bytes=-abc",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:   "suffix larger than blob",
			header: "bytes=-20",
			size:   10,
			want: []blobRange{
				{start: 0, length: 10},
			},
		},
		{
			name:    "suffix collapses to zero on empty blob",
			header:  "bytes=-1",
			size:    0,
			wantErr: zerr.ErrBadUploadRange,
		},
		{
			name:    "invalid start",
			header:  "bytes=abc-1",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:    "non overlapping range",
			header:  "bytes=10-11",
			size:    10,
			wantErr: zerr.ErrBadUploadRange,
		},
		{
			name:   "open ended range",
			header: "bytes=5-",
			size:   10,
			want: []blobRange{
				{start: 5, length: 5},
			},
		},
		{
			name:    "invalid end",
			header:  "bytes=5-4",
			size:    10,
			wantErr: zerr.ErrParsingHTTPHeader,
		},
		{
			name:   "range end clamps to blob size",
			header: "bytes=8-20",
			size:   10,
			want: []blobRange{
				{start: 8, length: 2},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRangeHeader(testCase.header, testCase.size)
			if !stderrors.Is(err, testCase.wantErr) {
				t.Fatalf("error = %v, want %v", err, testCase.wantErr)
			}

			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("ranges = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

func TestWriteMultipartByteRangesHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recorder := httptest.NewRecorder()
	readerCalled := false

	writeMultipartByteRanges(
		ctx,
		recorder,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			readerCalled = true

			return io.NopCloser(strings.NewReader("ab")), nil
		},
		zlog.NewTestLogger(),
	)

	if readerCalled {
		t.Fatalf("range reader should not be called when the context is already canceled")
	}

	if recorder.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusPartialContent)
	}
}

func TestWriteMultipartByteRangesClosesReaderOnContextCancelAfterLookup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	reader := &trackedReadCloser{reader: strings.NewReader("ab")}
	recorder := httptest.NewRecorder()

	writeMultipartByteRanges(
		ctx,
		recorder,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			cancel()

			return reader, nil
		},
		zlog.NewTestLogger(),
	)

	if !reader.closed {
		t.Fatalf("range reader was not closed after the context was canceled")
	}
}

func TestWriteMultipartByteRangesStopsOnRangeReaderError(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	readerCalled := false

	writeMultipartByteRanges(
		context.Background(),
		recorder,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			readerCalled = true

			return nil, stderrors.New("boom")
		},
		zlog.NewTestLogger(),
	)

	if !readerCalled {
		t.Fatalf("range reader was not called")
	}

	if recorder.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusPartialContent)
	}
}

func TestWriteMultipartByteRangesStopsOnShortRead(t *testing.T) {
	t.Parallel()

	reader := &trackedReadCloser{reader: strings.NewReader("a")}
	recorder := httptest.NewRecorder()

	writeMultipartByteRanges(
		context.Background(),
		recorder,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			return reader, nil
		},
		zlog.NewTestLogger(),
	)

	if !reader.closed {
		t.Fatalf("range reader was not closed after a short read")
	}
}

func TestWriteMultipartByteRangesStopsOnCloseError(t *testing.T) {
	t.Parallel()

	reader := &trackedReadCloser{
		reader:   strings.NewReader("ab"),
		closeErr: stderrors.New("close failed"),
	}
	recorder := httptest.NewRecorder()

	writeMultipartByteRanges(
		context.Background(),
		recorder,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			return reader, nil
		},
		zlog.NewTestLogger(),
	)

	if !reader.closed {
		t.Fatalf("range reader was not closed when Close returned an error")
	}
}

func TestWriteMultipartByteRangesHandlesResponseWriteError(t *testing.T) {
	t.Parallel()

	writer := &erroringResponseWriter{err: stderrors.New("response write failed")}

	writeMultipartByteRanges(
		context.Background(),
		writer,
		"application/octet-stream",
		4,
		[]blobRange{{start: 0, length: 2}},
		func(blobRange) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("ab")), nil
		},
		zlog.NewTestLogger(),
	)

	if writer.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", writer.status, http.StatusPartialContent)
	}
}

func TestGetBlobRejectsExplicitEmptyRangeHeader(t *testing.T) {
	t.Parallel()

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
			t.Fatalf("GetBlob should not be called when Range is explicitly empty")

			return nil, 0, nil
		},
	}))

	req := newBlobGetRequest("", true)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	if recorder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestedRangeNotSatisfiable)
	}
}

func TestGetBlobReturnsInternalServerErrorWhenRangePreflightFails(t *testing.T) {
	t.Parallel()

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return false, 0, stderrors.New("boom")
		},
		GetBlobPartialFn: func(repo string, digest godigest.Digest, mediaType string, from, to int64,
		) (io.ReadCloser, int64, int64, error) {
			t.Fatalf("GetBlobPartial should not be called when range preflight fails")

			return nil, 0, 0, nil
		},
	}))

	req := newBlobGetRequest("bytes=0-1", false)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestGetBlobReturnsNotFoundWhenRangePreflightBlobIsMissing(t *testing.T) {
	t.Parallel()

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return false, 0, nil
		},
		GetBlobPartialFn: func(repo string, digest godigest.Digest, mediaType string, from, to int64,
		) (io.ReadCloser, int64, int64, error) {
			t.Fatalf("GetBlobPartial should not be called when the blob is missing")

			return nil, 0, 0, nil
		},
	}))

	req := newBlobGetRequest("bytes=0-1", false)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestGetBlobSupportsOpenEndedRanges(t *testing.T) {
	t.Parallel()

	const blob = "0123456789"

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, int64(len(blob)), nil
		},
		GetBlobPartialFn: func(repo string, digest godigest.Digest, mediaType string, from, to int64,
		) (io.ReadCloser, int64, int64, error) {
			if from != 7 || to != 9 {
				t.Fatalf("range = %d-%d, want 7-9", from, to)
			}

			return io.NopCloser(strings.NewReader(blob[from : to+1])), to - from + 1, int64(len(blob)), nil
		},
	}))

	req := newBlobGetRequest("bytes=7-", false)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}

	if got := resp.Header.Get("Content-Range"); got != "bytes 7-9/10" {
		t.Fatalf("content-range = %q, want %q", got, "bytes 7-9/10")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if got := string(body); got != "789" {
		t.Fatalf("body = %q, want %q", got, "789")
	}
}

func TestGetBlobClampsRangeEndToBlobSize(t *testing.T) {
	t.Parallel()

	const blob = "0123456789"

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, int64(len(blob)), nil
		},
		GetBlobPartialFn: func(repo string, digest godigest.Digest, mediaType string, from, to int64,
		) (io.ReadCloser, int64, int64, error) {
			if from != 8 || to != 9 {
				t.Fatalf("range = %d-%d, want 8-9", from, to)
			}

			return io.NopCloser(strings.NewReader(blob[from : to+1])), to - from + 1, int64(len(blob)), nil
		},
	}))

	req := newBlobGetRequest("bytes=8-20", false)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}

	if got := resp.Header.Get("Content-Range"); got != "bytes 8-9/10" {
		t.Fatalf("content-range = %q, want %q", got, "bytes 8-9/10")
	}
}

func TestGetBlobRejectsMalformedRangeHeader(t *testing.T) {
	t.Parallel()

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 10, nil
		},
	}))

	testCases := []string{
		"items=0-1",
		"bytes=1",
	}

	for _, header := range testCases {
		t.Run(header, func(t *testing.T) {
			req := newBlobGetRequest(header, false)
			recorder := httptest.NewRecorder()
			handler.GetBlob(recorder, req)

			if recorder.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestedRangeNotSatisfiable)
			}
		})
	}
}

func TestGetBlobMultipleRangesStopsWhenBlobReadFails(t *testing.T) {
	t.Parallel()

	handler := newInternalBlobRouteHandler(withBinaryFallback(mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 10, nil
		},
		GetBlobPartialFn: func(repo string, digest godigest.Digest, mediaType string, from, to int64,
		) (io.ReadCloser, int64, int64, error) {
			return nil, 0, 0, stderrors.New("boom")
		},
	}))

	req := newBlobGetRequest("bytes=0-1,5-7", false)
	recorder := httptest.NewRecorder()
	handler.GetBlob(recorder, req)

	if recorder.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusPartialContent)
	}

	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "multipart/byteranges; boundary=") {
		t.Fatalf("content-type = %q, want multipart/byteranges boundary", got)
	}
}
