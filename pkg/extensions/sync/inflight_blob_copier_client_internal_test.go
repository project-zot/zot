//go:build sync

package sync

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"path/filepath"
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
