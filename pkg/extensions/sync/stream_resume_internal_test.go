//go:build sync

package sync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

var errResumeUpstream = errors.New("simulated upstream connection reset")

// failingReader serves content[:failAfter], then err.
type failingReader struct {
	content   []byte
	failAfter int
	err       error
	offset    int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.offset >= r.failAfter {
		return 0, r.err
	}

	n := copy(p, r.content[r.offset:r.failAfter])
	r.offset += n

	return n, nil
}

// resumeFetcher is a BlobFetcher over content: its first len(failAfter) opens fail after the given
// number of bytes (-n for a body truncated to n bytes instead of an error), and later opens serve
// the whole blob. With corruptFirst, the first open serves a wrong byte before it is cut short;
// with oversized, every open serves an extra byte past the descriptor's size.
type resumeFetcher struct {
	content      []byte
	desc         descriptor.Descriptor
	failAfter    []int
	corruptFirst bool
	oversized    bool
	opens        atomic.Int32
	openErr      error
}

func (f *resumeFetcher) fetch(_ context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
	open := int(f.opens.Add(1)) - 1

	if f.openErr != nil {
		return nil, f.openErr
	}

	if f.oversized {
		body := append(bytes.Clone(f.content), 'x')

		return blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(body))), nil
	}

	if open < len(f.failAfter) {
		after := f.failAfter[open]
		if after < 0 {
			return blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(f.content[:-after]))), nil
		}

		content := f.content

		if open == 0 && f.corruptFirst {
			content = bytes.Clone(content)
			content[10] ^= 0xff
		}

		return blob.NewReader(blob.WithDesc(desc), blob.WithReader(
			&failingReader{content: content, failAfter: after, err: errResumeUpstream})), nil
	}

	return blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(f.content))), nil
}

// newResumeTestBlob returns a blob spanning several fill chunks, and a stream initialized with the
// first open of fetcher.
func newResumeTestBlob(t *testing.T, fetcher *resumeFetcher) *ChunkedBlobReader {
	t.Helper()

	fetcher.content = bytes.Repeat([]byte("0123456789abcdef"), 6*fillChunkSize/16)
	fetcher.desc = descriptor.Descriptor{Digest: godigest.FromBytes(fetcher.content), Size: int64(len(fetcher.content))}

	cbr, err := NewChunkedBlobReader(filepath.Join(t.TempDir(), "blob"), log.NewTestLogger())
	require.NoError(t, err)

	first, err := fetcher.fetch(context.Background(), fetcher.desc)
	require.NoError(t, err)

	require.True(t, cbr.InitReader(first, fetcher.desc))

	return cbr
}

func resumeOf(fetcher *resumeFetcher, maxAttempts int) *fillResume {
	return &fillResume{fetch: fetcher.fetch, maxAttempts: maxAttempts, delay: time.Millisecond}
}

// TestChunkedBlobReaderFillResumable: a blob upstream cut short is reopened and continued from the
// bytes on disk, so clients see one complete, verified blob and never a failure.
func TestChunkedBlobReaderFillResumable(t *testing.T) {
	t.Parallel()

	for name, failAfter := range map[string][]int{
		"error mid-chunk":                {fillChunkSize + fillChunkSize/2},
		"error on a chunk boundary":      {2 * fillChunkSize},
		"error before the first chunk":   {100},
		"truncated body mid-chunk":       {-(fillChunkSize + fillChunkSize/2)},
		"truncated body on a boundary":   {-(2 * fillChunkSize)},
		"two interruptions":              {fillChunkSize + 7, 3*fillChunkSize + 7},
		"error in the final chunk":       {5*fillChunkSize + 100},
		"error after the last byte only": {6 * fillChunkSize},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fetcher := &resumeFetcher{failAfter: failAfter}
			cbr := newResumeTestBlob(t, fetcher)

			announce, id := cbr.Subscribe()
			require.GreaterOrEqual(t, id, 0)

			require.NoError(t, cbr.FillResumable(context.Background(), resumeOf(fetcher, 3)))
			require.NoError(t, cbr.Err())
			require.NoError(t, cbr.Wait(context.Background()))

			onDisk, err := os.ReadFile(cbr.OnDiskPath())
			require.NoError(t, err)
			assert.Equal(t, fetcher.content, onDisk)
			assert.Equal(t, int32(len(failAfter)+1), fetcher.opens.Load())

			// The channel holds the latest offset only.
			select {
			case offset, ok := <-announce:
				require.True(t, ok, "a resumed download must not disconnect its clients")
				assert.Equal(t, int64(len(fetcher.content)), offset)
			default:
				t.Fatal("the final offset was not announced")
			}

			cbr.Unsubscribe(id)
		})
	}
}

// TestChunkedBlobReaderFillResumableGivesUp: the blob fails, and its clients with it, once the
// reopens are used up or can't open the blob.
func TestChunkedBlobReaderFillResumableGivesUp(t *testing.T) {
	t.Parallel()

	t.Run("every reopen is cut short again", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{100, 100, 100, 100}}
		cbr := newResumeTestBlob(t, fetcher)

		announce, _ := cbr.Subscribe()

		require.ErrorIs(t, cbr.FillResumable(context.Background(), resumeOf(fetcher, 2)), errResumeUpstream)
		require.ErrorIs(t, cbr.Err(), errResumeUpstream)
		assert.Equal(t, int32(3), fetcher.opens.Load(), "the first open and two reopens")

		for range announce {
		}
	})

	t.Run("reopening fails", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{100}}
		cbr := newResumeTestBlob(t, fetcher)

		fetcher.openErr = errors.New("upstream refused the GET")

		require.ErrorIs(t, cbr.FillResumable(context.Background(), resumeOf(fetcher, 2)), fetcher.openErr)
		require.ErrorIs(t, cbr.Err(), fetcher.openErr)
		assert.Equal(t, int32(3), fetcher.opens.Load())
	})

	t.Run("no resume", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{100}}
		cbr := newResumeTestBlob(t, fetcher)

		require.ErrorIs(t, cbr.Fill(), errResumeUpstream)
		require.ErrorIs(t, cbr.Err(), errResumeUpstream)
		assert.Equal(t, int32(1), fetcher.opens.Load())
	})

	t.Run("context ended", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{100}}
		cbr := newResumeTestBlob(t, fetcher)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		require.ErrorIs(t, cbr.FillResumable(ctx, resumeOf(fetcher, 2)), errResumeUpstream)
		assert.Equal(t, int32(1), fetcher.opens.Load())
	})

	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{oversized: true}
		cbr := newResumeTestBlob(t, fetcher)

		require.ErrorIs(t, cbr.FillResumable(context.Background(), resumeOf(fetcher, 3)), errs.ErrSizeLimitExceeded)
		require.ErrorIs(t, cbr.Err(), errs.ErrSizeLimitExceeded)
		assert.Equal(t, int32(1), fetcher.opens.Load(), "a size check failure is not resumed")
	})

	t.Run("the cut-short response was corrupt", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{fillChunkSize + 7}, corruptFirst: true}
		cbr := newResumeTestBlob(t, fetcher)

		announce, _ := cbr.Subscribe()

		// The retry serves the correct blob, which passes its own digest check; the bytes clients
		// already received don't match it.
		require.ErrorIs(t, cbr.FillResumable(context.Background(), resumeOf(fetcher, 3)), zerr.ErrStreamCorruptPrefix)
		require.ErrorIs(t, cbr.Err(), zerr.ErrStreamCorruptPrefix)
		require.ErrorIs(t, cbr.Wait(context.Background()), zerr.ErrStreamCorruptPrefix)
		assert.Equal(t, int32(2), fetcher.opens.Load(), "a corrupt prefix is not retried")

		for range announce {
		}
	})

	t.Run("the reopened blob differs", func(t *testing.T) {
		t.Parallel()

		fetcher := &resumeFetcher{failAfter: []int{fillChunkSize + 7}}
		cbr := newResumeTestBlob(t, fetcher)

		changed := bytes.Repeat([]byte("x"), len(fetcher.content))
		reopen := func(_ context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
			return blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(changed))), nil
		}

		resume := &fillResume{fetch: reopen, maxAttempts: 3, delay: time.Millisecond}

		// Caught at the first differing byte of the replayed prefix, before its digest check.
		require.ErrorIs(t, cbr.FillResumable(context.Background(), resume), zerr.ErrStreamCorruptPrefix)
		require.ErrorIs(t, cbr.Err(), zerr.ErrStreamCorruptPrefix)
	})
}

// flakyBlobFetcher is a storeBlobFetcher whose first open of one digest fails with an upstream
// error after serving the first half of the blob.
type flakyBlobFetcher struct {
	*storeBlobFetcher
	flaky godigest.Digest
	opens atomic.Int32
}

func (f *flakyBlobFetcher) fetch(ctx context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
	if desc.Digest != f.flaky || f.opens.Add(1) > 1 {
		return f.storeBlobFetcher.fetch(ctx, desc)
	}

	content, err := f.imgStore.GetBlobContent(f.repo, desc.Digest)
	if err != nil {
		return nil, err
	}

	cut := &failingReader{content: content, failAfter: len(content) / 2, err: errResumeUpstream}

	return blob.NewReader(blob.WithDesc(desc), blob.WithReader(cut)), nil
}

// TestChunkingStreamManagerDownloadResumesInterruptedBlob: a blob whose download is cut short is
// reopened by the sync, the client already reading it gets the whole blob, and the blob is still
// handed to the sync's layout.
func TestChunkingStreamManagerDownloadResumesInterruptedBlob(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)
	sm.resumeDelay = time.Millisecond

	_, layer := priorityTestImage(t, sm, regClient, root)

	fetcher := &flakyBlobFetcher{storeBlobFetcher: newStoreBlobFetcher(storeCtrl, "repo-a"), flaky: layer.Digest}

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
	require.NoError(t, err)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy() }()

	files := sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch, nil)

	require.Contains(t, files, layer.Digest)
	assert.Equal(t, int32(2), fetcher.opens.Load(), "the blob is opened again after the cut")

	require.NoError(t, <-clientDone)
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))

	onDisk, err := os.ReadFile(files[layer.Digest])
	require.NoError(t, err)
	assert.Equal(t, layer.Digest, godigest.FromBytes(onDisk))

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerDownloadInterruptedWithoutResume: with no reopens left the blob is left
// out for ImageCopy, and clients are turned away.
func TestChunkingStreamManagerDownloadInterruptedWithoutResume(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)
	sm.resumeAttempts = 0

	_, layer := priorityTestImage(t, sm, regClient, root)

	fetcher := &flakyBlobFetcher{storeBlobFetcher: newStoreBlobFetcher(storeCtrl, "repo-a"), flaky: layer.Digest}

	files := sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch, nil)

	assert.NotContains(t, files, layer.Digest)
	assert.NotEmpty(t, files)

	_, err := sm.ConnectClient("repo-a", layer.Digest.String(), io.Discard)
	require.Error(t, err)

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)
}
