//go:build sync

package sync

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/log"
)

// TestInFlightBlobCopierStopsWhenClientLeaves: a client whose request ends while the download is
// stalled is released at once, rather than held until the blob completes or the stream is torn down.
func TestInFlightBlobCopierStopsWhenClientLeaves(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("x"), 64)
	desc := descriptor.Descriptor{Digest: godigest.FromBytes(content), Size: int64(len(content))}

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeWriter.Close() })

	cbr, err := NewChunkedBlobReader(filepath.Join(t.TempDir(), "blob"), log.NewTestLogger())
	require.NoError(t, err)
	require.True(t, cbr.InitReader(blob.NewReader(blob.WithDesc(desc), blob.WithReader(pipeReader)), desc))

	announceChan, subscriptionID := cbr.Subscribe()

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), io.Discard, announceChan, subscriptionID, log.NewTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	copyDone := make(chan error, 1)

	go func() { copyDone <- copier.Copy(ctx) }()

	cancel()

	select {
	case err := <-copyDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Copy kept waiting for bytes after its client left")
	}

	assert.False(t, isSubscribed(cbr, subscriptionID), "a client that left must be unsubscribed")
}

// TestInFlightBlobCopierFlushesHTTPResponse: each chunk is flushed to an HTTP client as it is
// copied.
func TestInFlightBlobCopierFlushesHTTPResponse(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("stream-me "), 100)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()
	response := httptest.NewRecorder()

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), response, announceChan, subscriptionID, log.NewTestLogger())

	readDone := make(chan error, 1)
	go func() { readDone <- readAllChunks(cbr) }()

	require.NoError(t, copier.Copy(context.Background()))
	require.ErrorIs(t, <-readDone, io.EOF)

	assert.True(t, response.Flushed)
	assert.Equal(t, content, response.Body.Bytes())
}

// gatedResponse is a response whose first Write signals entered and then waits for release, so a
// test can hold the copy loop inside a write while more bytes are announced. It also records
// whether the latest write has been flushed since.
type gatedResponse struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	flushedAfterLastWrite bool
}

func (w *gatedResponse) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})

	w.flushedAfterLastWrite = false

	return w.ResponseRecorder.Write(p)
}

func (w *gatedResponse) Flush() {
	w.flushedAfterLastWrite = true
	w.ResponseRecorder.Flush()
}

// TestInFlightBlobCopierFlushesFinalDrain: bytes announced while the copy loop is writing, after
// which the announcer exits, are copied and flushed on the way out. Whether the loop then sees
// the wake-up or the announcer's exit first is select's random choice, so the copy is repeated.
func TestInFlightBlobCopierFlushesFinalDrain(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("stream-me "), 100)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))
	require.ErrorIs(t, readAllChunks(cbr), io.EOF)

	for range 32 {
		announce := make(chan int64, 1)
		response := &gatedResponse{
			ResponseRecorder: httptest.NewRecorder(),
			entered:          make(chan struct{}),
			release:          make(chan struct{}),
		}

		copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), response, announce, -1, log.NewTestLogger())

		copyDone := make(chan error, 1)
		go func() { copyDone <- copier.Copy(context.Background()) }()

		announce <- 10
		<-response.entered

		announce <- int64(len(content))

		require.Eventually(t, func() bool { return copier.latestOffset.Load() == int64(len(content)) },
			5*time.Second, time.Millisecond)
		time.Sleep(10 * time.Millisecond)

		close(response.release)

		require.NoError(t, <-copyDone)
		assert.Equal(t, content, response.Body.Bytes())
		assert.True(t, response.flushedAfterLastWrite, "the last bytes written must be flushed")
	}
}
