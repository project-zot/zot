//go:build sync

package sync

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// gatedFetcher is a storeBlobFetcher whose fetch of one digest waits for release, as a blob queued
// behind regclient's per-host throttle does.
type gatedFetcher struct {
	*storeBlobFetcher
	gated   godigest.Digest
	release chan struct{}
	// gatedCtxs receives the context of each gated fetch.
	gatedCtxs chan context.Context
}

func newGatedFetcher(storeCtrl stypes.StoreController, repo string, gated godigest.Digest) *gatedFetcher {
	return &gatedFetcher{
		storeBlobFetcher: newStoreBlobFetcher(storeCtrl, repo),
		gated:            gated,
		release:          make(chan struct{}),
		gatedCtxs:        make(chan context.Context, 8),
	}
}

func (g *gatedFetcher) fetch(ctx context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
	if desc.Digest == g.gated {
		g.gatedCtxs <- ctx

		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return g.storeBlobFetcher.fetch(ctx, desc)
}

// priorityTestImage stages repo-a's image and returns it with its first layer.
func priorityTestImage(t *testing.T, sm *ChunkingStreamManager, regClient *regclient.RegClient, root string,
) (*StreamableManifest, descriptor.Descriptor) {
	t.Helper()

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	t.Cleanup(closeManifest)

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	imager, ok := streamable.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	layers, err := imager.GetLayers()
	require.NoError(t, err)
	require.NotEmpty(t, layers)

	return streamable, layers[0]
}

// startPriorityDownload runs the sync's download of streamable in the background and returns once
// priority downloads are enabled.
func startPriorityDownload(t *testing.T, sm *ChunkingStreamManager, streamable *StreamableManifest,
	bulk, priority BlobFetcher,
) chan map[godigest.Digest]string {
	t.Helper()

	downloaded := make(chan map[godigest.Digest]string, 1)

	go func() {
		downloaded <- sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, bulk, priority)
	}()

	require.Eventually(t, func() bool {
		sm.streamLock.Lock()
		defer sm.streamLock.Unlock()

		return streamable.priority != nil
	}, 5*time.Second, time.Millisecond)

	return downloaded
}

// TestChunkingStreamManagerPriorityDownload: a client connecting to a blob whose download is queued
// behind the throttle is served by a priority download. The queued download then drops its reader
// and waits for it, so the blob is fed once.
func TestChunkingStreamManagerPriorityDownload(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
	require.NoError(t, err)

	require.NoError(t, copier.Copy())
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))
	assert.Equal(t, map[godigest.Digest]int{layer.Digest: 1}, priority.counts(),
		"only the blob a client waits on is downloaded with priority")

	close(bulk.release)

	files := <-downloaded
	require.Contains(t, files, layer.Digest)

	content, err := os.ReadFile(files[layer.Digest])
	require.NoError(t, err)
	assert.Equal(t, layer.Digest, godigest.FromBytes(content))
	assert.Equal(t, 1, bulk.counts()[layer.Digest], "the queued download still opens the blob, then drops it")

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityDownloadEarlyClient: a client that connected before the sync
// reached its download is served with priority once it does, rather than left queued behind the
// throttle.
func TestChunkingStreamManagerPriorityDownloadEarlyClient(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
	require.NoError(t, err)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy() }()

	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	select {
	case err := <-clientDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the client stayed queued behind the gated download")
	}

	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))
	assert.Equal(t, map[godigest.Digest]int{layer.Digest: 1}, priority.counts())

	close(bulk.release)

	files := <-downloaded
	require.Contains(t, files, layer.Digest)

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityDownloadCancelledWhenBulkWins: a priority download still queued
// at its throttle when the sync's download starts the blob is cancelled, rather than left holding
// upstream capacity, and losing that way does not fail the blob or its client.
func TestChunkingStreamManagerPriorityDownloadCancelledWhenBulkWins(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
	require.NoError(t, err)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy() }()

	// Both gated: the bulk download must not finish, and clear the priority fetch, before the
	// priority download has been seen queued. The priority gate is never released.
	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	var priorityCtx context.Context

	select {
	case priorityCtx = <-priority.gatedCtxs:
	case <-time.After(5 * time.Second):
		t.Fatal("no priority download was started for the waiting client")
	}

	close(bulk.release)

	require.NoError(t, <-clientDone)
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))

	files := <-downloaded
	require.Contains(t, files, layer.Digest)
	assert.Equal(t, 1, bulk.counts()[layer.Digest])

	require.ErrorIs(t, priorityCtx.Err(), context.Canceled, "the losing priority download must be cancelled")
	require.NoError(t, activeStream(t, sm, streamable.source, layer.Digest.String()).Err())

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityDownloadOpenFails: a priority download that can't open the blob
// leaves it to the sync's download, which then feeds the waiting client.
func TestChunkingStreamManagerPriorityDownloadOpenFails(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")
	priority.failDigest, priority.failErr = layer.Digest, errors.New("simulated priority client failure")

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
	require.NoError(t, err)

	require.Eventually(t, func() bool { return priority.counts()[layer.Digest] == 1 }, 5*time.Second, time.Millisecond)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy() }()

	close(bulk.release)

	require.NoError(t, <-clientDone)
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))

	assert.Contains(t, <-downloaded, layer.Digest)

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityDownloadOnlyOnce: only the first client to connect starts a
// priority download of a blob, and once the blob is started none does.
func TestChunkingStreamManagerPriorityDownloadOnlyOnce(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	for range 3 {
		var clientBuf bytes.Buffer

		copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &clientBuf)
		require.NoError(t, err)

		require.NoError(t, copier.Copy())
		assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))
	}

	assert.Equal(t, 1, priority.counts()[layer.Digest])

	close(bulk.release)
	<-downloaded

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerNoPriorityDownloadOutsideSync: a client connecting before the sync's
// download starts, or after it ended, starts no priority download.
func TestChunkingStreamManagerNoPriorityDownloadOutsideSync(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), &bytes.Buffer{})
	require.NoError(t, err)

	copier.Close()

	stream := activeStream(t, sm, streamable.source, layer.Digest.String())
	assert.False(t, stream.Started())

	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")

	assert.NotEmpty(t, sm.DownloadStreamedBlobs(
		context.Background(), "repo-a", predictTestTag, fetcher.fetch, priority.fetch))

	sm.streamLock.Lock()
	assert.Nil(t, streamable.priority)
	sm.streamLock.Unlock()

	copier, err = sm.ConnectClient("repo-a", layer.Digest.String(), &bytes.Buffer{})
	require.NoError(t, err)

	copier.Close()

	assert.Empty(t, priority.counts())

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkedBlobReaderFailStartWithPendingOpen: a failed open only fails the blob once no other
// producer is still opening it.
func TestChunkedBlobReaderFailStartWithPendingOpen(t *testing.T) {
	t.Parallel()

	cbr, err := NewChunkedBlobReader(filepath.Join(t.TempDir(), "blob"), log.NewTestLogger())
	require.NoError(t, err)

	require.True(t, cbr.Claim())
	require.True(t, cbr.ClaimPriority(func() {}))
	assert.False(t, cbr.ClaimPriority(func() {}))

	assert.False(t, cbr.FailStart(zerr.ErrSyncUpstreamDownloadFailed))
	assert.False(t, cbr.Started())
	require.NoError(t, cbr.Err())

	assert.True(t, cbr.FailStart(zerr.ErrSyncUpstreamDownloadFailed))
	assert.True(t, cbr.Started())
	require.ErrorIs(t, cbr.Err(), zerr.ErrSyncUpstreamDownloadFailed)
	assert.False(t, cbr.ClaimPriority(func() {}))
}
