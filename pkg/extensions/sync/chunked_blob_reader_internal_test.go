//go:build sync

package sync

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// readAllChunks drains cbr in small reads, like a real io.Copy, and returns the final error.
func readAllChunks(cbr *ChunkedBlobReader) error {
	buf := make([]byte, 4)

	for {
		_, err := cbr.Read(buf)
		if err != nil {
			return err
		}
	}
}

// newTestChunkedBlobReader returns a reader over content whose descriptor claims expectedDigest
// (which may deliberately not match).
func newTestChunkedBlobReader(t *testing.T, content []byte, expectedDigest godigest.Digest) *ChunkedBlobReader {
	t.Helper()

	onDiskPath := filepath.Join(t.TempDir(), "blob")

	cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
	require.NoError(t, err)

	desc := descriptor.Descriptor{Digest: expectedDigest, Size: int64(len(content))}
	upstream := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	require.True(t, cbr.InitReader(upstream, desc))

	return cbr
}

func TestChunkedBlobReaderIntegrityFailures(t *testing.T) {
	content := []byte("hello streaming world, this is more than four bytes")

	t.Run("digest mismatch is never reported as a clean EOF", func(t *testing.T) {
		t.Parallel()

		wrongDigest := godigest.FromString("not-the-real-content")
		cbr := newTestChunkedBlobReader(t, content, wrongDigest)

		ch, _ := cbr.Subscribe()

		// Drain concurrently so announcements before the failure are consumed.
		lastOffset := int64(-1)
		drained := make(chan struct{})

		go func() {
			defer close(drained)
			for offset := range ch {
				lastOffset = offset
			}
		}()

		err := readAllChunks(cbr)
		<-drained

		require.Error(t, err)
		// regclient wraps the mismatch around io.EOF, so it still matches io.EOF; the reader must
		// check for the mismatch first.
		assert.True(t, errors.Is(err, errs.ErrDigestMismatch), "expected ErrDigestMismatch, got %v", err)

		// The client must see the stream fail, never an offset claiming the full blob arrived.
		assert.Less(t, lastOffset, int64(len(content)), "offset must never reach the full size on a failed stream")
	})

	t.Run("short read is never reported as a clean EOF", func(t *testing.T) {
		t.Parallel()

		// A descriptor larger than the content triggers ErrShortRead, also wrapped around EOF.
		desc := descriptor.Descriptor{Digest: godigest.FromBytes(content), Size: int64(len(content) + 16)}

		onDiskPath := filepath.Join(t.TempDir(), "blob")
		cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
		require.NoError(t, err)

		upstream := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))
		require.True(t, cbr.InitReader(upstream, desc))

		readErr := readAllChunks(cbr)
		require.Error(t, readErr)
		assert.True(t, errors.Is(readErr, errs.ErrShortRead), "expected ErrShortRead, got %v", readErr)
	})

	t.Run("normal completion still announces the final offset and closes the file", func(t *testing.T) {
		t.Parallel()

		cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

		err := readAllChunks(cbr)
		require.ErrorIs(t, err, io.EOF)
		assert.Equal(t, int64(len(content)), cbr.numBytesReadToDisk)
		assert.True(t, cbr.diskFileClosed)

		written, err := os.ReadFile(cbr.OnDiskPath())
		require.NoError(t, err)
		assert.Equal(t, content, written)
	})
}

func TestChunkedBlobReaderSubscribeUnsubscribe(t *testing.T) {
	t.Parallel()

	content := []byte("subscribe test content, more than four bytes long")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	ch1, id1 := cbr.Subscribe()
	ch2, id2 := cbr.Subscribe()

	done := make(chan error, 1)
	go func() { done <- readAllChunks(cbr) }()

	// Both clients must see the full size. A successful stream never closes their channels; only a
	// failure does.
	total := int64(len(content))
	drain := func(ch chan int64) int64 {
		last := int64(0)
		for last < total {
			offset, ok := <-ch
			if !ok {
				break
			}

			last = offset
		}

		return last
	}

	// Drain both concurrently, as two real clients would.
	results := make(chan int64, 2)
	go func() { results <- drain(ch1) }()
	go func() { results <- drain(ch2) }()

	last1 := <-results
	last2 := <-results

	assert.Equal(t, total, last1)
	assert.Equal(t, total, last2)
	require.ErrorIs(t, <-done, io.EOF)

	// Unsubscribing a still-open channel must not panic.
	cbr.Unsubscribe(id1)
	cbr.Unsubscribe(id2)
}

// TestChunkedBlobReaderReadNeverBlocksOnStalledClient: a client that never reads must not block
// Read; announcements coalesce to the latest offset.
func TestChunkedBlobReaderReadNeverBlocksOnStalledClient(t *testing.T) {
	t.Parallel()

	// Several small reads, so a stalled client's one-slot channel fills after the first.
	content := bytes.Repeat([]byte("x"), 64)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	// A stalled client: subscribed, never reads.
	_, _ = cbr.Subscribe()

	done := make(chan error, 1)
	go func() { done <- readAllChunks(cbr) }()

	select {
	case err := <-done:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("Read blocked indefinitely notifying a stalled client's undrained channel")
	}
}

// signalingReader closes entered on its first Read, so a test knows the producer is blocked inside
// the upstream read.
type signalingReader struct {
	io.Reader
	entered chan struct{}
	once    sync.Once
}

func (sr *signalingReader) Read(p []byte) (int, error) {
	sr.once.Do(func() { close(sr.entered) })

	return sr.Reader.Read(p)
}

// TestChunkedBlobReaderStalledUpstreamDoesNotBlockLookups: while the producer is blocked reading a
// stalled upstream body, Descriptor, Err and Subscribe (which the stream manager calls under its
// manager-wide streamLock) still return promptly.
func TestChunkedBlobReaderStalledUpstreamDoesNotBlockLookups(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("x"), 64)
	pipeReader, pipeWriter := io.Pipe()

	cbr, err := NewChunkedBlobReader(filepath.Join(t.TempDir(), "blob"), log.NewTestLogger())
	require.NoError(t, err)

	desc := descriptor.Descriptor{Digest: godigest.FromBytes(content), Size: int64(len(content))}
	upstream := &signalingReader{Reader: pipeReader, entered: make(chan struct{})}
	require.True(t, cbr.InitReader(blob.NewReader(blob.WithDesc(desc), blob.WithReader(upstream)), desc))

	// The producer blocks in Read: the pipe has no data yet.
	done := make(chan error, 1)
	go func() { done <- readAllChunks(cbr) }()

	<-upstream.entered

	lookups := make(chan struct{})
	go func() {
		defer close(lookups)

		_, _ = cbr.DescriptorWithTimeout(time.Second)
		_ = cbr.Err()
		_, id := cbr.Subscribe()
		cbr.Unsubscribe(id)
	}()

	select {
	case <-lookups:
	case <-time.After(2 * time.Second):
		t.Fatal("a stalled upstream read blocked Descriptor/Err/Subscribe")
	}

	// Unblock the producer and let it finish cleanly.
	_, err = pipeWriter.Write(content)
	require.NoError(t, err)
	require.NoError(t, pipeWriter.Close())
	require.ErrorIs(t, <-done, io.EOF)
}

// TestChunkedBlobReaderDescriptorTimeout: waiting for a download that never starts returns an error
// instead of hanging.
func TestChunkedBlobReaderDescriptorTimeout(t *testing.T) {
	t.Parallel()

	onDiskPath := filepath.Join(t.TempDir(), "blob")
	cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
	require.NoError(t, err)

	// InitReader deliberately never called.
	start := time.Now()
	_, descErr := cbr.DescriptorWithTimeout(50 * time.Millisecond)
	elapsed := time.Since(start)

	require.Error(t, descErr)
	assert.ErrorIs(t, descErr, zerr.ErrStreamInitTimeout)
	assert.Less(t, elapsed, 2*time.Second, "DescriptorWithTimeout must not block far past its timeout")
}

func TestChunkedBlobReaderDescriptorSucceedsOnceInitialized(t *testing.T) {
	t.Parallel()

	content := []byte("descriptor success test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	desc, err := cbr.Descriptor()
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), desc.Size)
}

func TestChunkedBlobReaderWaitForClientEmptyTimeout(t *testing.T) {
	t.Parallel()

	content := []byte("wait for client empty timeout test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	// A stalled client that never unsubscribes.
	_, _ = cbr.Subscribe()

	start := time.Now()
	cbr.WaitForClientEmpty(200 * time.Millisecond)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 2*time.Second, "WaitForClientEmpty must not block far past its timeout")

	cbr.clientMu.Lock()
	remaining := len(cbr.clients)
	cbr.clientMu.Unlock()

	assert.Equal(t, 0, remaining, "a stalled client must be force-unsubscribed once the timeout elapses")
}

func TestChunkedBlobReaderWaitForClientEmptyReturnsEarly(t *testing.T) {
	t.Parallel()

	content := []byte("returns early test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	_, id := cbr.Subscribe()

	go func() {
		time.Sleep(20 * time.Millisecond)
		cbr.Unsubscribe(id)
	}()

	start := time.Now()
	cbr.WaitForClientEmpty(5 * time.Second)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, time.Second, "WaitForClientEmpty must return promptly once clients drain on their own")
}

// erroringAfterReader serves content, then returns err: an upstream failure partway through.
type erroringAfterReader struct {
	content []byte
	pos     int
	err     error
}

func (r *erroringAfterReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.content) {
		return 0, r.err
	}

	n := copy(p, r.content[r.pos:])
	r.pos += n

	return n, nil
}

// TestChunkedBlobReaderFailureClosesFileImmediatelyAndEndsRetriesForGood: a failed stream closes
// its temp file right away, and no later producer can claim the blob (see InitReader).
func TestChunkedBlobReaderFailureClosesFileImmediatelyAndEndsRetriesForGood(t *testing.T) {
	t.Parallel()

	content := []byte("this is more than four bytes of content")
	digest := godigest.FromBytes(content)

	onDiskPath := filepath.Join(t.TempDir(), "blob")
	cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
	require.NoError(t, err)

	desc := descriptor.Descriptor{Digest: digest, Size: int64(len(content))}
	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	require.True(t, cbr.InitReader(producer, desc))

	readErr := readAllChunks(cbr)
	require.ErrorIs(t, readErr, wantErr)

	cbr.bytesMu.RLock()
	closedAfterFailure := cbr.diskFileClosed
	readerClosedAfterFailure := cbr.readerClosed
	cbr.bytesMu.RUnlock()

	assert.True(t, closedAfterFailure, "a failed stream must close its temp file immediately, not leak the descriptor")
	assert.True(t, readerClosedAfterFailure, "a failed digest must not accept a later producer - see InitReader's doc comment")

	_, writeErr := cbr.onDiskFile.Write([]byte("x"))
	assert.Error(t, writeErr, "the underlying file descriptor must actually be closed, not just flagged")

	// A second producer (e.g. another sync sharing this layer) is turned away.
	secondProducer := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))
	assert.False(t, cbr.InitReader(secondProducer, desc), "a second producer must not be able to claim a failed digest")
}

// TestChunkedBlobReaderLateSubscriberAfterFailure: a client arriving after the producer failed
// learns of it at once, instead of waiting for the forced drain.
func TestChunkedBlobReaderLateSubscriberAfterFailure(t *testing.T) {
	t.Parallel()

	content := []byte("this is more than four bytes of content")
	digest := godigest.FromBytes(content)

	cbr, err := NewChunkedBlobReader(filepath.Join(t.TempDir(), "blob"), log.NewTestLogger())
	require.NoError(t, err)

	desc := descriptor.Descriptor{Digest: digest, Size: int64(len(content))}
	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	require.True(t, cbr.InitReader(producer, desc))
	require.NoError(t, cbr.Err())
	require.ErrorIs(t, readAllChunks(cbr), wantErr)

	assert.ErrorIs(t, cbr.Err(), wantErr)

	_, descErr := cbr.DescriptorWithTimeout(time.Second)
	assert.ErrorIs(t, descErr, wantErr, "a failed stream must not report a usable descriptor")
	assert.ErrorIs(t, descErr, zerr.ErrSyncUpstreamDownloadFailed)

	ch, id := cbr.Subscribe()
	assert.Equal(t, -1, id)

	select {
	case _, ok := <-ch:
		assert.False(t, ok, "a late subscriber's channel must already be closed")
	case <-time.After(time.Second):
		t.Fatal("a late subscriber to a failed stream must not wait for an announcement")
	}

	cbr.clientMu.RLock()
	registered := len(cbr.clients)
	cbr.clientMu.RUnlock()
	assert.Zero(t, registered, "a late subscriber to a failed stream must not be registered")

	cbr.Unsubscribe(id) // must be a harmless no-op
}

// TestChunkedBlobReaderAbortClosesOnDiskFile: a blob whose download never started still has its
// temp file closed on teardown.
func TestChunkedBlobReaderAbortClosesOnDiskFile(t *testing.T) {
	t.Parallel()

	onDiskPath := filepath.Join(t.TempDir(), "blob")
	cbr, err := NewChunkedBlobReader(onDiskPath, log.NewTestLogger())
	require.NoError(t, err)

	// InitReader deliberately never called.
	cbr.Abort()

	cbr.bytesMu.RLock()
	closed := cbr.diskFileClosed
	cbr.bytesMu.RUnlock()

	assert.True(t, closed)

	_, writeErr := cbr.onDiskFile.Write([]byte("x"))
	assert.Error(t, writeErr, "the underlying file descriptor must actually be closed")
}

// TestChunkedBlobReaderAbortFailsIncompleteDownload: at teardown, a download the sync cut short is
// failed: its temp file is closed and attached clients are released now, not at the drain timeout.
func TestChunkedBlobReaderAbortFailsIncompleteDownload(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("x"), 64)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	// Part of the blob arrives, then the sync stops reading.
	_, err := cbr.Read(make([]byte, 8))
	require.NoError(t, err)

	announce, _ := cbr.Subscribe()

	cbr.Abort()

	require.ErrorIs(t, cbr.Err(), zerr.ErrStreamIncomplete)

	_, err = cbr.Descriptor()
	require.ErrorIs(t, err, zerr.ErrStreamIncomplete)

	cbr.bytesMu.RLock()
	closed := cbr.diskFileClosed
	cbr.bytesMu.RUnlock()
	assert.True(t, closed)

	_, writeErr := cbr.onDiskFile.Write([]byte("x"))
	assert.Error(t, writeErr, "the underlying file descriptor must actually be closed")

	// The client's channel is closed (after any offset still buffered from Subscribe).
	deadline := time.After(2 * time.Second)

	for closedChan := false; !closedChan; {
		select {
		case _, ok := <-announce:
			closedChan = !ok
		case <-deadline:
			t.Fatal("an incomplete download's client was not released at teardown")
		}
	}

	// A late subscriber is turned away too.
	late, id := cbr.Subscribe()
	assert.Equal(t, -1, id)

	_, ok := <-late
	assert.False(t, ok)
}

// TestChunkedBlobReaderAbortLeavesCompleteDownload: a finished download stays readable at teardown
// so its clients can drain it.
func TestChunkedBlobReaderAbortLeavesCompleteDownload(t *testing.T) {
	t.Parallel()

	content := bytes.Repeat([]byte("x"), 64)
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	require.ErrorIs(t, readAllChunks(cbr), io.EOF)

	announce, id := cbr.Subscribe()
	require.GreaterOrEqual(t, id, 0)

	cbr.Abort()

	require.NoError(t, cbr.Err())

	desc, err := cbr.Descriptor()
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), desc.Size)

	select {
	case offset, ok := <-announce:
		require.True(t, ok, "a complete download's client must not be disconnected")
		assert.Equal(t, int64(len(content)), offset)
	default:
		t.Fatal("subscriber should have been sent the final offset")
	}

	cbr.Unsubscribe(id)
}
