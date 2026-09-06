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
	"github.com/regclient/regclient/types/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/log"
)

// readAllChunks drains cbr with a small buffer (mimicking a real io.Copy loop, whose buffer is
// almost always far smaller than a blob), returning the final error once Read stops advancing.
func readAllChunks(cbr *ChunkedBlobReader) error {
	buf := make([]byte, 4)

	for {
		_, err := cbr.Read(buf)
		if err != nil {
			return err
		}
	}
}

// newTestChunkedBlobReader builds a ChunkedBlobReader whose upstream is content, with desc.Digest
// set to expectedDigest (which may deliberately not match content, to exercise the mismatch
// path) and desc.Size set to content's length.
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

		// Drain concurrently: the reader announces every successful chunk to subscribers before
		// the eventual failure, and the channel is only buffer-1, so nothing must block it.
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
		// regclient wraps the mismatch around the underlying io.EOF (errors.Is(err, io.EOF) is
		// legitimately still true), which is exactly the conflation this fix defeats - not by
		// breaking that wrap chain, but by checking ErrDigestMismatch before treating anything as
		// a plain EOF. What matters is that this reader's own classification never lets the
		// mismatch read as success (asserted below), not that the wrapping itself changes.
		assert.True(t, errors.Is(err, errs.ErrDigestMismatch), "expected ErrDigestMismatch, got %v", err)

		// The subscriber must observe the stream ending in failure, never a final offset
		// announcement claiming the blob completed.
		assert.Less(t, lastOffset, cbr.numBytesTotal, "offset must never reach the full size on a failed stream")
	})

	t.Run("short read is never reported as a clean EOF", func(t *testing.T) {
		t.Parallel()

		// A descriptor claiming more bytes than are actually available triggers ErrShortRead
		// once the real content is exhausted, wrapped (like ErrDigestMismatch) around an
		// underlying io.EOF/io.ErrUnexpectedEOF - the same conflation this fix guards against.
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

	// Both subscribers must see the offset reach the full size. Mirrors how
	// InFlightBlobCopier.Copy actually decides it's done (offset >= blobSize), rather than
	// relying on channel closure - a successful stream never closes subscriber channels, only
	// an aborted one does (see abortAllClients).
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

	// Drain both subscribers concurrently: each cbr.Read() call fans announcements out to every
	// subscriber and waits for all of those sends before returning (see the wg.Wait() in Read),
	// so draining them one at a time here would itself deadlock the producer as soon as the
	// second channel's 1-slot buffer fills - exactly as two real concurrent clients never would,
	// since each has its own goroutine.
	results := make(chan int64, 2)
	go func() { results <- drain(ch1) }()
	go func() { results <- drain(ch2) }()

	last1 := <-results
	last2 := <-results

	assert.Equal(t, total, last1)
	assert.Equal(t, total, last2)
	require.ErrorIs(t, <-done, io.EOF)

	// Unsubscribing a still-open channel (a successful stream never closes it) must not panic.
	cbr.Unsubscribe(id1)
	cbr.Unsubscribe(id2)
}

func TestChunkedBlobReaderWaitForClientEmptyTimeout(t *testing.T) {
	t.Parallel()

	content := []byte("wait for client empty timeout test content")
	cbr := newTestChunkedBlobReader(t, content, godigest.FromBytes(content))

	// A client subscribes and never unsubscribes (simulating a stalled/abandoned connection).
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
