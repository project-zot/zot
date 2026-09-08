//go:build sync

package sync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// isSubscribed reports whether subscriptionID is still registered on cbr - used to verify a
// copier released its subscription (via Unsubscribe/Close) rather than leaking it.
func isSubscribed(cbr *ChunkedBlobReader, subscriptionID int) bool {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	_, ok := cbr.clients[subscriptionID]

	return ok
}

// failingWriter is an io.Writer that always fails, for exercising Copy's downstream-write error
// path without a real network connection.
type failingWriter struct {
	err error
}

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestInFlightBlobCopierFullCopy(t *testing.T) {
	t.Parallel()

	// Long enough, relative to readAllChunks' 4-byte buffer, to require several Read calls (and
	// so several announce/copy round trips) rather than completing in one shot.
	content := bytes.Repeat([]byte("stream-me "), 100)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	var dest bytes.Buffer

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &dest, announceChan, subscriptionID, log.NewTestLogger())

	desc, err := copier.Descriptor()
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), desc.Size)

	readDone := make(chan error, 1)
	go func() { readDone <- readAllChunks(cbr) }()

	require.NoError(t, copier.Copy())
	require.ErrorIs(t, <-readDone, io.EOF)

	assert.Equal(t, content, dest.Bytes(), "the client must receive exactly the streamed content")
	assert.False(t, isSubscribed(cbr, subscriptionID), "Copy must unsubscribe once it returns")
}

// TestInFlightBlobCopierOsOpenFailure is the regression test for the Unsubscribe-ordering fix:
// ConnectClient registers the subscription before Copy is ever called (see NewInFlightBlobCopier's
// doc comment), so a failure opening the on-disk temp file - the very first thing Copy does - must
// still release it, or it lingers until RemoveStreamingImage's drain timeout forces it out.
func TestInFlightBlobCopierOsOpenFailure(t *testing.T) {
	t.Parallel()

	content := []byte("os open failure test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	// Deliberately wrong on-disk path, independent of cbr's real one, to force os.Open to fail
	// without needing to corrupt cbr's own state.
	badPath := filepath.Join(t.TempDir(), "does-not-exist")
	copier := NewInFlightBlobCopier(cbr, badPath, &bytes.Buffer{}, announceChan, subscriptionID, log.NewTestLogger())

	err := copier.Copy()
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "expected a not-exist error, got %v", err)
	assert.False(t, isSubscribed(cbr, subscriptionID), "a failed os.Open must still release the subscription")
}

// TestInFlightBlobCopierAbortedUpstream is the regression test for propagating a failed upstream
// download to an already-attached client: a digest mismatch (or any integrity/upstream failure)
// closes every subscriber's channel via abortAllClients rather than announcing completion, and
// Copy must surface that as ErrSyncUpstreamDownloadFailed instead of a silent short copy.
func TestInFlightBlobCopierAbortedUpstream(t *testing.T) {
	t.Parallel()

	content := []byte("hello streaming world, this is more than four bytes")
	wrongDigest := godigest.FromString("not-the-real-content")
	cbr := newTestChunkedBlobReader(t, content, wrongDigest)

	announceChan, subscriptionID := cbr.Subscribe()

	var dest bytes.Buffer

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &dest, announceChan, subscriptionID, log.NewTestLogger())

	go func() { _ = readAllChunks(cbr) }()

	err := copier.Copy()
	require.ErrorIs(t, err, zerr.ErrSyncUpstreamDownloadFailed)
}

// TestInFlightBlobCopierDestWriteFailure exercises the downstream-write error path (e.g. a client
// that disconnects mid-stream): Copy must surface the write error and shut down its announcement
// goroutine promptly rather than hanging or leaking it.
func TestInFlightBlobCopierDestWriteFailure(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("x"), 64)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	wantErr := errors.New("simulated downstream write failure")
	dest := &failingWriter{err: wantErr}

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), dest, announceChan, subscriptionID, log.NewTestLogger())

	go func() { _ = readAllChunks(cbr) }()

	err := copier.Copy()
	require.ErrorIs(t, err, wantErr)
}

func TestInFlightBlobCopierCloseWithoutCopy(t *testing.T) {
	t.Parallel()

	content := []byte("close without copy test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()
	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &bytes.Buffer{}, announceChan, subscriptionID, log.NewTestLogger())

	copier.Close()
	assert.False(t, isSubscribed(cbr, subscriptionID))

	// Mirrors Copy's own deferred Unsubscribe potentially running on an already-removed
	// subscription (e.g. a caller that calls Close defensively after Copy already ran) - must be
	// a harmless no-op, not a panic.
	require.NotPanics(t, func() { copier.Close() })
}
