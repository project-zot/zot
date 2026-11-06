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
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
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
	// served receives a value once a released gated fetch has returned its reader.
	served chan struct{}
	// ignoreCtx keeps a gated fetch waiting for release even once its ctx is done, as an upstream
	// request already past the client's control does.
	ignoreCtx bool
}

func newGatedFetcher(storeCtrl stypes.StoreController, repo string, gated godigest.Digest) *gatedFetcher {
	return &gatedFetcher{
		storeBlobFetcher: newStoreBlobFetcher(storeCtrl, repo),
		gated:            gated,
		release:          make(chan struct{}),
		gatedCtxs:        make(chan context.Context, 8),
		served:           make(chan struct{}, 8),
	}
}

func (g *gatedFetcher) fetch(ctx context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
	if desc.Digest != g.gated {
		return g.storeBlobFetcher.fetch(ctx, desc)
	}

	g.gatedCtxs <- ctx

	if g.ignoreCtx {
		<-g.release
	} else {
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	reader, err := g.storeBlobFetcher.fetch(ctx, desc)
	g.served <- struct{}{}

	return reader, err
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

	require.NoError(t, copier.Copy(context.Background()))
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

	go func() { clientDone <- copier.Copy(context.Background()) }()

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

	go func() { clientDone <- copier.Copy(context.Background()) }()

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

	go func() { clientDone <- copier.Copy(context.Background()) }()

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

		require.NoError(t, copier.Copy(context.Background()))
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

// TestChunkingStreamManagerBulkOpenFailsWhilePriorityFeeds: a bulk open that fails while a priority
// download is queued for the blob doesn't fail it; the bulk side waits for the priority download.
func TestChunkingStreamManagerBulkOpenFailsWhilePriorityFeeds(t *testing.T) {
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

	go func() { clientDone <- copier.Copy(context.Background()) }()

	bulk := newStoreBlobFetcher(storeCtrl, "repo-a")
	bulk.failDigest, bulk.failErr = layer.Digest, errors.New("simulated bulk open failure")
	priority := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	select {
	case <-priority.gatedCtxs:
	case <-time.After(5 * time.Second):
		t.Fatal("no priority download was started for the waiting client")
	}

	close(priority.release)

	require.NoError(t, <-clientDone)
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))

	files := <-downloaded
	require.Contains(t, files, layer.Digest, "the bulk side must wait for the priority download")
	assert.Equal(t, 1, bulk.counts()[layer.Digest])

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityDownloadUnstagedReference: a download of an unstaged reference
// has nothing to enable priority for.
func TestChunkingStreamManagerPriorityDownloadUnstagedReference(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")
	priority := newStoreBlobFetcher(storeCtrl, "repo-a")

	assert.Empty(t, sm.DownloadStreamedBlobs(context.Background(), "repo-a", "unstaged", fetcher.fetch, priority.fetch))
	assert.Empty(t, priority.counts())
}

// TestChunkingStreamManagerSecondClientJoinsClaimedPriority: a second client connecting while a
// priority download is still queued for the blob joins it instead of starting another.
func TestChunkingStreamManagerSecondClientJoinsClaimedPriority(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, layer := priorityTestImage(t, sm, regClient, root)

	bulk := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	clients := make([]*bytes.Buffer, 2)
	clientDone := make(chan error, len(clients))

	for i := range clients {
		clients[i] = &bytes.Buffer{}

		copier, err := sm.ConnectClient("repo-a", layer.Digest.String(), clients[i])
		require.NoError(t, err)

		go func() { clientDone <- copier.Copy(context.Background()) }()

		if i == 0 {
			select {
			case <-priority.gatedCtxs:
			case <-time.After(5 * time.Second):
				t.Fatal("no priority download was started for the first client")
			}
		}
	}

	close(priority.release)

	for range clients {
		require.NoError(t, <-clientDone)
	}

	for _, buf := range clients {
		assert.Equal(t, layer.Digest, godigest.FromBytes(buf.Bytes()))
	}

	assert.Empty(t, priority.gatedCtxs, "the second client must not start a priority download")

	close(bulk.release)
	require.Contains(t, <-downloaded, layer.Digest)

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerPriorityOpensAfterBulkStarted: a priority download whose open returns
// only after the sync's download started the blob drops its reader without touching the stream.
func TestChunkingStreamManagerPriorityOpensAfterBulkStarted(t *testing.T) {
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

	go func() { clientDone <- copier.Copy(context.Background()) }()

	// The bulk download is gated on the config, not the layer: it starts the layer at once, but
	// can't finish (and clear the priority fetch) before the test has seen the priority download.
	bulk := newGatedFetcher(storeCtrl, "repo-a", streamConfigDesc(t, streamable).Digest)
	priority := newGatedFetcher(storeCtrl, "repo-a", layer.Digest)
	priority.ignoreCtx = true

	downloaded := startPriorityDownload(t, sm, streamable, bulk.fetch, priority.fetch)

	select {
	case <-priority.gatedCtxs:
	case <-time.After(5 * time.Second):
		t.Fatal("no priority download was started for the waiting client")
	}

	require.NoError(t, <-clientDone)
	assert.Equal(t, layer.Digest, godigest.FromBytes(clientBuf.Bytes()))

	close(bulk.release)

	files := <-downloaded
	require.Contains(t, files, layer.Digest)

	close(priority.release)
	<-priority.served

	stream := activeStream(t, sm, streamable.source, layer.Digest.String())
	require.NoError(t, stream.Wait(context.Background()))

	content, err := os.ReadFile(files[layer.Digest])
	require.NoError(t, err)
	assert.Equal(t, layer.Digest, godigest.FromBytes(content))

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestBaseServiceInitClientPriorityClient: a streaming registry gets a second client for priority
// downloads; any other registry doesn't.
func TestBaseServiceInitClientPriorityClient(t *testing.T) {
	t.Parallel()

	stream := true
	service := &BaseService{
		config: syncconf.RegistryConfig{URLs: []string{"https://upstream.example"}, Stream: &stream},
		log:    log.NewTestLogger(),
	}

	require.NoError(t, service.initClient())
	assert.NotNil(t, service.rc)
	assert.NotNil(t, service.priorityRC)
	assert.NotSame(t, service.rc, service.priorityRC)

	service.config.Stream = nil

	require.NoError(t, service.initClient())
	assert.Nil(t, service.priorityRC)
}

// TestBaseServiceDownloadStreamedBlobsWithPriorityClient: with a priority client, a blob a client
// is already waiting on is also opened through it.
func TestBaseServiceDownloadStreamedBlobsWithPriorityClient(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-x", predictTestTag, streamable)
	require.NoError(t, err)

	imager, ok := streamable.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	layers, err := imager.GetLayers()
	require.NoError(t, err)
	require.NotEmpty(t, layers)

	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-x", layers[0].Digest.String(), &clientBuf)
	require.NoError(t, err)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy(context.Background()) }()

	service := &BaseService{rc: regClient, priorityRC: regclient.New(), streamManager: sm, log: log.NewTestLogger()}

	remoteImageRef := mustOCIDirRef(t, repoPath(root, "repo-a"), predictTestTag).
		SetDigest(streamable.referenceManifest.GetDescriptor().Digest.String())
	layoutDir := filepath.Join(t.TempDir(), "repo-x")
	localImageRef := mustOCIDirRef(t, layoutDir, predictTestTag)

	service.downloadStreamedBlobs(context.Background(), "repo-x", predictTestTag, remoteImageRef, localImageRef)

	require.NoError(t, <-clientDone)
	assert.Equal(t, layers[0].Digest, godigest.FromBytes(clientBuf.Bytes()))

	layoutFile := filepath.Join(layoutDir, "blobs", layers[0].Digest.Algorithm().String(), layers[0].Digest.Encoded())

	content, err := os.ReadFile(layoutFile)
	require.NoError(t, err)
	assert.Equal(t, layers[0].Digest, godigest.FromBytes(content))

	sm.RemoveStreamingImage("repo-x", predictTestTag, true)
}
