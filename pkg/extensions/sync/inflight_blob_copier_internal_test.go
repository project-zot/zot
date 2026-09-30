//go:build sync

package sync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// isSubscribed reports whether subscriptionID is still registered, to check a copier released it.
func isSubscribed(cbr *ChunkedBlobReader, subscriptionID int) bool {
	cbr.clientMu.Lock()
	defer cbr.clientMu.Unlock()

	_, ok := cbr.clients[subscriptionID]

	return ok
}

// failingWriter always fails, standing in for a disconnected client.
type failingWriter struct {
	err error
}

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestInFlightBlobCopierFullCopy(t *testing.T) {
	t.Parallel()

	// Several small reads, so Copy goes through several announce/copy rounds.
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

// TestInFlightBlobCopierOsOpenFailure: Copy releases its subscription even when opening the temp
// file fails.
func TestInFlightBlobCopierOsOpenFailure(t *testing.T) {
	t.Parallel()

	content := []byte("os open failure test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	// A path that doesn't exist, so os.Open fails.
	badPath := filepath.Join(t.TempDir(), "does-not-exist")
	copier := NewInFlightBlobCopier(cbr, badPath, &bytes.Buffer{}, announceChan, subscriptionID, log.NewTestLogger())

	err := copier.Copy()
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "expected a not-exist error, got %v", err)
	assert.False(t, isSubscribed(cbr, subscriptionID), "a failed os.Open must still release the subscription")
}

// TestInFlightBlobCopierAbortedUpstream: an attached client gets ErrSyncUpstreamDownloadFailed when
// the download fails, not a silent short copy.
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

// TestInFlightBlobCopierDestWriteFailure: a client write error is returned, and the announcement
// goroutine exits instead of leaking.
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

func TestInFlightBlobCopierCopyRange(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("stream-me "), 100)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	var dest bytes.Buffer

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &dest, announceChan, subscriptionID, log.NewTestLogger())

	readDone := make(chan error, 1)
	go func() { readDone <- readAllChunks(cbr) }()

	const start, end = 17, 41

	require.NoError(t, copier.CopyRange(start, end))
	require.ErrorIs(t, <-readDone, io.EOF)

	assert.Equal(t, content[start:end+1], dest.Bytes(), "must receive exactly the requested byte range")
	assert.False(t, isSubscribed(cbr, subscriptionID), "CopyRange must unsubscribe once it returns")
}

func TestInFlightBlobCopierCopyRangeOutOfBounds(t *testing.T) {
	t.Parallel()

	content := []byte("short blob")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &bytes.Buffer{}, announceChan, subscriptionID, log.NewTestLogger())

	err := copier.CopyRange(0, int64(len(content)))
	require.ErrorIs(t, err, zerr.ErrBadRange)
	assert.False(t, isSubscribed(cbr, subscriptionID), "an invalid range must still release the subscription")
}

// blockingTailReader serves releaseAfter bytes, then blocks until release is closed.
type blockingTailReader struct {
	content      []byte
	releaseAfter int64
	pos          int64
	release      chan struct{}
}

func (r *blockingTailReader) Read(p []byte) (int, error) {
	if r.pos >= r.releaseAfter {
		<-r.release
	}

	if r.pos >= int64(len(r.content)) {
		return 0, io.EOF
	}

	n := copy(p, r.content[r.pos:])
	r.pos += int64(n)

	return n, nil
}

func TestInFlightBlobCopierCopyRangeDoesNotWaitForFullBlob(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("0123456789"), 4) // 40 bytes

	onDiskPath := filepath.Join(t.TempDir(), "blob")
	cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
	require.NoError(t, err)

	desc := descriptor.Descriptor{Digest: godigest.FromBytes(content), Size: int64(len(content))}

	// Blocks after 8 bytes. The range below needs only those, so CopyRange must finish without
	// another upstream read.
	blocked := &blockingTailReader{content: content, releaseAfter: 8, release: make(chan struct{})}
	defer close(blocked.release)

	upstream := blob.NewReader(blob.WithDesc(desc), blob.WithReader(blocked))

	require.True(t, cbr.InitReader(upstream, desc))

	// Write the requested bytes (0-7) before subscribing, so the first announcement already covers
	// the range.
	buf := make([]byte, 4)
	_, err = cbr.Read(buf)
	require.NoError(t, err)
	_, err = cbr.Read(buf)
	require.NoError(t, err)

	announceChan, subscriptionID := cbr.Subscribe()

	var dest bytes.Buffer

	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &dest, announceChan, subscriptionID, log.NewTestLogger())

	copyDone := make(chan error, 1)
	go func() { copyDone <- copier.CopyRange(0, 7) }()

	select {
	case err := <-copyDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("CopyRange did not return even though its entire range was already on disk - it waited for more")
	}

	assert.Equal(t, content[0:8], dest.Bytes())
}

func TestInFlightBlobCopierCloseWithoutCopy(t *testing.T) {
	t.Parallel()

	content := []byte("close without copy test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	announceChan, subscriptionID := cbr.Subscribe()
	copier := NewInFlightBlobCopier(cbr, cbr.OnDiskPath(), &bytes.Buffer{}, announceChan, subscriptionID, log.NewTestLogger())

	copier.Close()
	assert.False(t, isSubscribed(cbr, subscriptionID))

	// A second Unsubscribe (e.g. Close after Copy) must be a harmless no-op.
	require.NotPanics(t, func() { copier.Close() })
}
