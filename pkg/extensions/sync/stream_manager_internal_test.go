//go:build sync

package sync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// newTestStreamManager builds a stream manager over newTestStore's store controller.
func newTestStreamManager(t *testing.T, storeCtrl stypes.StoreController, maxConcurrentStreams int) *ChunkingStreamManager {
	t.Helper()

	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok, "newTestStore must return a storage.StoreController")

	sm := NewChunkingStreamManager(concrete, maxConcurrentStreams, log.NewTestLogger())
	// These tests stage images read from the store itself, so every blob would count as already
	// local and get no stream. Blank the store used for that check (staging still uses the real
	// one) so they stage as for a remote image; TestChunkingStreamManagerSkipsLocalBlobs covers it.
	sm.storeController = storage.StoreController{}

	return sm
}

// newTestStreamableManifest fetches repo:tag (written by a writeOCI* helper) as a streamable
// manifest. Call the returned closer when done.
func newTestStreamableManifest(t *testing.T, regClient *regclient.RegClient, root, repo, tag string,
) (*StreamableManifest, func()) {
	t.Helper()

	srcRef := mustOCIDirRef(t, repoPath(root, repo), tag)

	man, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	return NewStreamableManifest(man), func() { regClient.Close(context.Background(), man.GetRef()) }
}

func TestChunkingStreamManagerStoreAndRemove(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)
	assert.Same(t, streamable, staged, "a fresh stage must return the caller's own manifest")

	cached, ok := sm.StreamingImageManifest("repo-a", predictTestTag)
	require.True(t, ok)
	assert.Equal(t, streamable.referenceManifest.GetDescriptor().Digest, cached.referenceManifest.GetDescriptor().Digest)

	configDigest := streamConfigDesc(t, streamable).Digest.String()

	sm.streamLock.Lock()
	_, isActive := sm.activeStreams[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the config must become an active stream")

	sm.streamLock.Lock()
	_, manifestActive := sm.activeStreams[streamKey("", streamable.referenceManifest.GetDescriptor().Digest.String())]
	sm.streamLock.Unlock()
	assert.False(t, manifestActive, "the manifest itself must get no stream: nothing would feed it")

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	_, ok = sm.StreamingImageManifest("repo-a", predictTestTag)
	assert.False(t, ok, "manifest must no longer be staged for streaming after removal")

	sm.streamLock.Lock()
	_, isActive = sm.activeStreams[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.False(t, isActive, "the config's stream must be gone after removal")
}

// TestChunkingStreamManagerStoreDockerManifest: Docker schema2 manifests (served as-is, since sync
// never converts) must stage like OCI ones.
func TestChunkingStreamManagerStoreDockerManifest(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeDockerSingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	require.Equal(t, manifest.MediaTypeDocker2Manifest, manifest.GetMediaType(streamable.referenceManifest),
		"test setup: must actually produce a Docker schema2 manifest, not OCI")

	staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)
	assert.Same(t, streamable, staged)

	configDigest := streamConfigDesc(t, streamable).Digest.String()

	sm.streamLock.Lock()
	_, isActive := sm.activeStreams[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the Docker image's config must become an active stream")
}

// TestChunkingStreamManagerRemoveDoesNotBlockOtherBlobs: RemoveStreamingImage must not hold
// streamLock while draining a stalled client, or every other blob would freeze.
func TestChunkingStreamManagerRemoveDoesNotBlockOtherBlobs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")
	writeOCISingleManifest(t, storeCtrl, "repo-b")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamableA, closeA := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeA()
	streamableB, closeB := newTestStreamableManifest(t, regClient, root, "repo-b", predictTestTag)
	defer closeB()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamableA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, streamableB)
	require.NoError(t, err)

	digestA := streamConfigDesc(t, streamableA).Digest.String()
	digestB := streamConfigDesc(t, streamableB).Digest.String()

	sm.streamLock.Lock()
	readerA := sm.activeStreams[streamKey("", digestA)]
	sm.streamLock.Unlock()
	require.NotNil(t, readerA)

	// A stalled client that never unsubscribes.
	_, clientID := readerA.Subscribe()

	removeDone := make(chan struct{})

	go func() {
		defer close(removeDone)
		sm.RemoveStreamingImage("repo-a", predictTestTag, false)
	}()

	// Let RemoveStreamingImage reach its drain wait first.
	time.Sleep(50 * time.Millisecond)

	bResult := make(chan error, 1)

	go func() {
		_, _, err := sm.CachedBlobInfo("repo-b", digestB)
		bResult <- err
	}()

	select {
	case err := <-bResult:
		assert.NoError(t, err, "repo-b's blob must still be reachable while repo-a's is draining")
	case <-time.After(2 * time.Second):
		t.Fatal("CachedBlobInfo for an unrelated blob was blocked by RemoveStreamingImage draining a different blob")
	}

	// Unblock the drain so the test doesn't wait out streamDrainTimeout.
	readerA.Unsubscribe(clientID)

	select {
	case <-removeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("RemoveStreamingImage did not finish after its stalled client was unsubscribed")
	}
}

// TestChunkingStreamManagerDrainSharesOneDeadline: an image whose every blob has a stalled client
// is torn down in about one drain timeout, not one per blob. Teardown runs inside the reference's
// on-demand flight, so a per-blob wait would hold that flight for minutes.
func TestChunkingStreamManagerDrainSharesOneDeadline(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	const drainTimeout = 500 * time.Millisecond

	sm.drainTimeout = drainTimeout

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	// A stalled client that never unsubscribes, on every blob of the image.
	sm.streamLock.Lock()
	readers := make([]*ChunkedBlobReader, 0, len(sm.activeStreams))

	for _, reader := range sm.activeStreams {
		reader.Subscribe()
		readers = append(readers, reader)
	}
	sm.streamLock.Unlock()
	require.GreaterOrEqual(t, len(readers), 3, "test setup: config and layers must each have a stream")

	start := time.Now()

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, drainTimeout, "stalled clients must get the drain timeout")
	assert.Less(t, elapsed, 2*drainTimeout,
		"%d stalled blobs took %s to drain: the timeout must be shared, not applied per blob", len(readers), elapsed)

	for _, reader := range readers {
		reader.clientMu.Lock()
		remaining := len(reader.clients)
		reader.clientMu.Unlock()
		assert.Zero(t, remaining, "stalled clients must be force-disconnected at the deadline")

		_, err := os.Stat(reader.OnDiskPath())
		assert.True(t, os.IsNotExist(err), "each blob's temp file must be deleted")
	}
}

func TestChunkingStreamManagerMaxConcurrentStreams(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	// The config and layers are separate streams, so a cap of 1 is hit partway.
	sm := newTestStreamManager(t, storeCtrl, 1)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.Error(t, err)
	// The cap error must stay distinct so callers can fall back to a plain sync.
	assert.ErrorIs(t, err, zerr.ErrTooManyConcurrentStreams)

	// A partial stage must roll back the streams it created; nothing would ever remove them
	// otherwise.
	sm.streamLock.Lock()
	activeCount := len(sm.activeStreams)
	blobInfoCount := len(sm.blobInfoMap)
	refCount := len(sm.refCounts)
	_, staged := sm.streamingRefs["repo-a:"+predictTestTag]
	sm.streamLock.Unlock()

	assert.Equal(t, 0, activeCount, "a failed StoreImageForStreaming must roll back every stream it created")
	assert.Equal(t, 0, blobInfoCount)
	assert.Equal(t, 0, refCount)
	assert.False(t, staged, "a failed StoreImageForStreaming must not register in streamingRefs")
}

// TestChunkingStreamManagerSetMaxConcurrentStreams: a config reload that reuses the manager
// resizes its cap, with n <= 0 meaning the default as in NewChunkingStreamManager.
func TestChunkingStreamManagerSetMaxConcurrentStreams(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 1)

	sm.SetMaxConcurrentStreams(5)
	assert.Equal(t, 5, sm.maxConcurrentStreams)

	sm.SetMaxConcurrentStreams(0)
	assert.Equal(t, syncConstants.DefaultMaxConcurrentStreams, sm.maxConcurrentStreams)
}

// TestChunkingStreamManagerSharedBlobAcrossRepos: a blob staged by two repos is torn down only
// after both are removed.
func TestChunkingStreamManagerSharedBlobAcrossRepos(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	// Write the same image to both repos so their digests really match (writeOCISingleManifest
	// randomizes layers).
	image := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
	require.NoError(t, WriteImageToFileSystem(image, "repo-a", predictTestTag, storeCtrl))
	require.NoError(t, WriteImageToFileSystem(image, "repo-b", predictTestTag, storeCtrl))

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamableA, closeA := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeA()
	streamableB, closeB := newTestStreamableManifest(t, regClient, root, "repo-b", predictTestTag)
	defer closeB()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamableA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, streamableB)
	require.NoError(t, err)

	configDigest := streamConfigDesc(t, streamableA).Digest.String()
	require.Equal(t, configDigest, streamConfigDesc(t, streamableB).Digest.String(),
		"test setup: both repos must reference the identical manifest digest")

	sm.streamLock.Lock()
	refCount := sm.refCounts[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.Equal(t, 2, refCount, "both repo:reference registrations must be counted")

	// repo-b still needs the shared blob.
	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	sm.streamLock.Lock()
	_, stillActive := sm.activeStreams[streamKey("", configDigest)]
	refCount = sm.refCounts[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.True(t, stillActive, "a blob still referenced by repo-b must survive repo-a's removal")
	assert.Equal(t, 1, refCount)

	copier, err := sm.ConnectClient("repo-b", configDigest, nil)
	require.NoError(t, err, "repo-b's clients must still be able to attach to the shared blob")
	copier.Close()

	// Now nothing needs it.
	sm.RemoveStreamingImage("repo-b", predictTestTag, false)

	sm.streamLock.Lock()
	_, stillActive = sm.activeStreams[streamKey("", configDigest)]
	_, refExists := sm.refCounts[streamKey("", configDigest)]
	sm.streamLock.Unlock()
	assert.False(t, stillActive, "the blob must be torn down once every referencing repo:reference is removed")
	assert.False(t, refExists)
}

func TestChunkingStreamManagerConnectClientUnknownDigest(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	_, err := sm.ConnectClient("repo", "sha256:"+strings.Repeat("0", 64), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)
}

// TestChunkingStreamManagerConnectClientCrossRepoDenied: a client of another repo can't attach to a
// stream just by knowing its digest.
func TestChunkingStreamManagerConnectClientCrossRepoDenied(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	configDigest := streamConfigDesc(t, streamable).Digest.String()

	// The repo it is staged under works.
	_, err = sm.ConnectClient("repo-a", configDigest, nil)
	require.NoError(t, err)

	// Another repo gets the same error as an unknown digest, so it learns nothing.
	_, err = sm.ConnectClient("repo-b", configDigest, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)
}

func TestChunkingStreamManagerCachedBlobInfo(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	desc := streamConfigDesc(t, streamable)

	size, mediaType, err := sm.CachedBlobInfo("repo-a", desc.Digest.String())
	require.NoError(t, err)
	assert.Equal(t, desc.Size, size)
	assert.Equal(t, desc.MediaType, mediaType)

	// Same as ConnectClient: another repo must not learn the blob's size or type.
	_, _, err = sm.CachedBlobInfo("repo-b", desc.Digest.String())
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFound)
}

func TestChunkingStreamManagerRemoveStreamingImageNoOp(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	// Nothing staged: removal must be a harmless no-op.
	require.NotPanics(t, func() { sm.RemoveStreamingImage("repo", predictTestTag, false) })
}

// TestChunkingStreamManagerRemoveStreamingImageDeletesTempFile: removing the last reference to a
// blob deletes its temp file, not just the bookkeeping.
func TestChunkingStreamManagerRemoveStreamingImageDeletesTempFile(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	configDigest := streamConfigDesc(t, streamable).Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[streamKey("", configDigest)].OnDiskPath()
	sm.streamLock.Unlock()

	_, statErr := os.Stat(onDiskPath)
	require.NoError(t, statErr, "prepareActiveStreamForBlob must have created the temp file up front")

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	_, statErr = os.Stat(onDiskPath)
	assert.True(t, os.IsNotExist(statErr), "the temp file must be deleted once the blob has no clients and no referencing repo:reference left")
}

// TestChunkingStreamManagerDownloadUnstaged: with nothing staged there is nothing to download.
func TestChunkingStreamManagerDownloadUnstaged(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")

	assert.Empty(t, sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch))
	assert.Empty(t, fetcher.counts())
}

// TestChunkingStreamManagerDownloadStreamedBlobs: the sync's download fills each config and layer
// stream once, a client attached beforehand gets the whole blob, and the returned temp files are
// the verified blobs. The manifest isn't downloaded: ImageCopy fetches it as a manifest.
func TestChunkingStreamManagerDownloadStreamedBlobs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	imager, ok := streamable.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	layers, err := imager.GetLayers()
	require.NoError(t, err)
	require.NotEmpty(t, layers)

	// A client already waiting on the first layer is fed by the download.
	var clientBuf bytes.Buffer

	copier, err := sm.ConnectClient("repo-a", layers[0].Digest.String(), &clientBuf)
	require.NoError(t, err)

	clientDone := make(chan error, 1)

	go func() { clientDone <- copier.Copy() }()

	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")
	files := sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	want := []godigest.Digest{configDesc.Digest}
	for _, layer := range layers {
		want = append(want, layer.Digest)
	}

	require.Len(t, files, len(want))

	for _, digest := range want {
		content, err := os.ReadFile(files[digest])
		require.NoError(t, err)
		assert.Equal(t, digest, godigest.FromBytes(content))
		assert.Equal(t, 1, fetcher.counts()[digest], "each streamed blob must be fetched once")
	}

	assert.NotContains(t, fetcher.counts(), streamable.referenceManifest.GetDescriptor().Digest)

	require.NoError(t, <-clientDone)
	assert.Equal(t, layers[0].Digest, godigest.FromBytes(clientBuf.Bytes()))

	sm.RemoveStreamingImage("repo-a", predictTestTag, true)
}

// TestChunkingStreamManagerDownloadSharedAcrossSyncs: two staged references sharing streams each
// run a sync, but every blob is downloaded once, and both syncs get the same files.
func TestChunkingStreamManagerDownloadSharedAcrossSyncs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	base, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", "tag-1", NewStreamableManifest(base.referenceManifest))
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-a", "tag-2", NewStreamableManifest(base.referenceManifest))
	require.NoError(t, err)

	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")

	var (
		wg             sync.WaitGroup
		files1, files2 map[godigest.Digest]string
	)

	wg.Go(func() { files1 = sm.DownloadStreamedBlobs(context.Background(), "repo-a", "tag-1", fetcher.fetch) })
	wg.Go(func() { files2 = sm.DownloadStreamedBlobs(context.Background(), "repo-a", "tag-2", fetcher.fetch) })
	wg.Wait()

	require.NotEmpty(t, files1)
	assert.Equal(t, files1, files2)

	for digest, count := range fetcher.counts() {
		assert.Equal(t, 1, count, "blob %s must be downloaded once for both syncs", digest)
	}

	sm.RemoveStreamingImage("repo-a", "tag-1", true)
	sm.RemoveStreamingImage("repo-a", "tag-2", true)
}

// TestChunkingStreamManagerDownloadFailedFetch: a blob whose GET fails is left out for ImageCopy
// to download, its stream is failed so clients are turned away, and a sync waiting on it leaves it
// out too. The other blobs still complete.
func TestChunkingStreamManagerDownloadFailedFetch(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	base, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", "tag-1", NewStreamableManifest(base.referenceManifest))
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-a", "tag-2", NewStreamableManifest(base.referenceManifest))
	require.NoError(t, err)

	imager, ok := base.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	wantErr := errors.New("simulated upstream refusing the blob")
	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")
	fetcher.failDigest, fetcher.failErr = configDesc.Digest, wantErr

	var (
		wg             sync.WaitGroup
		files1, files2 map[godigest.Digest]string
	)

	wg.Go(func() { files1 = sm.DownloadStreamedBlobs(context.Background(), "repo-a", "tag-1", fetcher.fetch) })
	wg.Go(func() { files2 = sm.DownloadStreamedBlobs(context.Background(), "repo-a", "tag-2", fetcher.fetch) })
	wg.Wait()

	assert.NotContains(t, files1, configDesc.Digest)
	assert.NotContains(t, files2, configDesc.Digest)
	assert.NotEmpty(t, files1, "the layers must still complete")
	assert.Equal(t, files1, files2)

	_, err = sm.ConnectClient("repo-a", configDesc.Digest.String(), io.Discard)
	require.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)

	sm.RemoveStreamingImage("repo-a", "tag-1", false)
	sm.RemoveStreamingImage("repo-a", "tag-2", false)
}

// TestChunkingStreamManagerStreamsNamespacedBySource: the same digest from two registries gets two
// streams, so one registry's clients never get the other's unverified bytes.
func TestChunkingStreamManagerStreamsNamespacedBySource(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	base, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	// Same manifest (so same digests) staged under two repos from different registries.
	fromA := NewStreamableManifest(base.referenceManifest)
	fromA.source = "0"
	fromB := NewStreamableManifest(base.referenceManifest)
	fromB.source = "1"

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, fromA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, fromB)
	require.NoError(t, err)

	desc := streamConfigDesc(t, base)
	digest := desc.Digest.String()

	sm.streamLock.Lock()
	streamA := sm.activeStreams[streamKey("0", digest)]
	streamB := sm.activeStreams[streamKey("1", digest)]
	sm.streamLock.Unlock()
	require.NotNil(t, streamA)
	require.NotNil(t, streamB)
	assert.NotSame(t, streamA, streamB, "each source registry must get its own stream for a shared digest")

	// Each repo's sync downloads its own registry's blobs; with digest-only keys, repo-b's sync
	// would find A's streams already claimed and download nothing.
	fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")

	filesA := sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch)
	filesB := sm.DownloadStreamedBlobs(context.Background(), "repo-b", predictTestTag, fetcher.fetch)

	require.NotEmpty(t, filesA)
	require.Len(t, filesB, len(filesA))

	for digest, fileA := range filesA {
		assert.NotEqual(t, fileA, filesB[digest], "each registry's stream must have its own file")
		assert.Equal(t, 2, fetcher.counts()[digest], "each registry's sync must download the blob itself")
	}

	// A repo-b client attaches to B's stream.
	copier, err := sm.ConnectClient("repo-b", digest, io.Discard)
	require.NoError(t, err)

	inflight, ok := copier.(*InFlightBlobCopier)
	require.True(t, ok)
	assert.Same(t, streamB, inflight.Source)
	copier.Close()

	// Removing repo-a leaves B's stream alone.
	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	_, _, err = sm.CachedBlobInfo("repo-b", digest)
	require.NoError(t, err)

	sm.streamLock.Lock()
	_, stillActiveA := sm.activeStreams[streamKey("0", digest)]
	_, stillActiveB := sm.activeStreams[streamKey("1", digest)]
	sm.streamLock.Unlock()
	assert.False(t, stillActiveA)
	assert.True(t, stillActiveB)

	sm.RemoveStreamingImage("repo-b", predictTestTag, false)
}

// TestChunkingStreamManagerConnectClientRejectsFailedStream: ConnectClient refuses a failed stream,
// so the route rechecks storage instead of sending a truncated body.
func TestChunkingStreamManagerConnectClientRejectsFailedStream(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	desc := streamConfigDesc(t, streamable)
	digest := desc.Digest.String()

	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	stream := activeStream(t, sm, "", desc.Digest.String())
	require.True(t, stream.InitReader(producer, desc))
	require.ErrorIs(t, stream.Fill(), wantErr)

	_, err = sm.ConnectClient("repo-a", digest, io.Discard)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)
}

// TestChunkingStreamManagerRejectsIndex: an index is never staged (its on-demand sync is sparse,
// so nothing would feed its platforms' streams); staging one fails and leaves nothing behind.
func TestChunkingStreamManagerRejectsIndex(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCIMultiPlatformIndex(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	require.True(t, streamable.referenceManifest.IsList(), "test setup: must be an index")

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.ErrorIs(t, err, zerr.ErrSyncInvalidManifestMediaType)

	_, ok := sm.StreamingImageManifest("repo-a", predictTestTag)
	assert.False(t, ok)

	sm.streamLock.Lock()
	assert.Empty(t, sm.activeStreams)
	sm.streamLock.Unlock()
}

// TestChunkingStreamManagerDeleteStreamFilePermissionError: a failed os.Remove is logged, not
// propagated.
func TestChunkingStreamManagerDeleteStreamFilePermissionError(t *testing.T) {
	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	configDigest := streamConfigDesc(t, streamable).Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[streamKey("", configDigest)].OnDiskPath()
	sm.streamLock.Unlock()

	// Removing a file needs write permission on its directory, so this makes os.Remove fail while
	// os.Stat still works. Not parallel: it changes a shared permission bit.
	parentDir := filepath.Dir(onDiskPath)
	require.NoError(t, os.Chmod(parentDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(parentDir, 0o755) }) // restore so t.TempDir() can clean up

	require.NotPanics(t, func() { sm.RemoveStreamingImage("repo-a", predictTestTag, false) })

	// Removal really failed, so the file is still there.
	_, statErr := os.Stat(onDiskPath)
	assert.NoError(t, statErr)
}

// TestChunkingStreamManagerAmbiguousSourceNotStreamed: when two references staged under one repo
// get the same blob from different registries, the blob isn't streamed at all, since a client
// can't be matched to the registry whose manifest it followed.
func TestChunkingStreamManagerAmbiguousSourceNotStreamed(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	base, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	fromA := NewStreamableManifest(base.referenceManifest)
	fromA.source = "0"
	fromB := NewStreamableManifest(base.referenceManifest)
	fromB.source = "1"

	_, err := sm.StoreImageForStreaming("repo-a", "tag-a", fromA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-a", "tag-b", fromB)
	require.NoError(t, err)

	digest := streamConfigDesc(t, base).Digest.String()

	_, err = sm.ConnectClient("repo-a", digest, io.Discard)
	require.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)

	_, _, err = sm.CachedBlobInfo("repo-a", digest)
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)

	// Once only one source is left, the blob streams again.
	sm.RemoveStreamingImage("repo-a", "tag-b", false)

	copier, err := sm.ConnectClient("repo-a", digest, io.Discard)
	require.NoError(t, err)

	inflight, ok := copier.(*InFlightBlobCopier)
	require.True(t, ok)

	sm.streamLock.Lock()
	assert.Same(t, sm.activeStreams[streamKey("0", digest)], inflight.Source)
	sm.streamLock.Unlock()
	copier.Close()

	sm.RemoveStreamingImage("repo-a", "tag-a", false)
}

// TestChunkingStreamManagerCachedBlobInfoHidesFailedStream: like ConnectClient, CachedBlobInfo stops
// advertising a blob once its producer failed, so HEAD doesn't claim a blob GET would refuse.
func TestChunkingStreamManagerCachedBlobInfoHidesFailedStream(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	desc := streamConfigDesc(t, streamable)

	_, _, err = sm.CachedBlobInfo("repo-a", desc.Digest.String())
	require.NoError(t, err)

	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	stream := activeStream(t, sm, "", desc.Digest.String())
	require.True(t, stream.InitReader(producer, desc))
	require.ErrorIs(t, stream.Fill(), wantErr)

	_, _, err = sm.CachedBlobInfo("repo-a", desc.Digest.String())
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)
}

// TestChunkingStreamManagerOnSyncedCallbacks: the stager's, each joiner's and a race loser's
// onSynced all run once, with the staged manifest, when the entry is removed after a successful
// sync, and none run after a failed one.
func TestChunkingStreamManagerOnSyncedCallbacks(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	base, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	var calls []string

	record := func(name string) func(manifest.Manifest) {
		return func(synced manifest.Manifest) {
			assert.Same(t, base.referenceManifest, synced)

			calls = append(calls, name)
		}
	}

	for _, synced := range []bool{true, false} {
		calls = nil

		stager := NewStreamableManifest(base.referenceManifest)
		stager.onSynced = []func(manifest.Manifest){record("stager")}

		_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, stager)
		require.NoError(t, err)

		_, ok := sm.JoinStreamingImage("repo-a", predictTestTag, record("joiner"))
		require.True(t, ok)

		loser := NewStreamableManifest(base.referenceManifest)
		loser.onSynced = []func(manifest.Manifest){record("loser")}

		staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, loser)
		require.NoError(t, err)
		require.Same(t, stager, staged)

		sm.RemoveStreamingImage("repo-a", predictTestTag, synced)

		if synced {
			assert.ElementsMatch(t, []string{"stager", "joiner", "loser"}, calls)
		} else {
			assert.Empty(t, calls)
		}

		// Nothing left to join once unstaged.
		_, ok = sm.JoinStreamingImage("repo-a", predictTestTag, record("late"))
		assert.False(t, ok)
	}
}

// TestChunkingStreamManagerSkipsLocalBlobs: blobs the repo already stores get no stream, so they
// neither use up maxConcurrentStreams nor wait for a producer that seeding means never comes.
func TestChunkingStreamManagerSkipsLocalBlobs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok)

	t.Run("all-local image stages under a cap of one", func(t *testing.T) {
		t.Parallel()

		sm := NewChunkingStreamManager(concrete, 1, log.NewTestLogger())

		streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
		defer closeManifest()

		// Config and layers are all in repo-a: before, this needed one slot each.
		staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
		require.NoError(t, err)
		require.Same(t, streamable, staged)

		sm.streamLock.Lock()
		assert.Empty(t, sm.activeStreams)
		assert.Empty(t, streamable.streamKeys)
		sm.streamLock.Unlock()

		configDesc := streamConfigDesc(t, streamable)

		// No client is offered a stream for it; the blob routes serve it from storage.
		_, err = sm.ConnectClient("repo-a", configDesc.Digest.String(), io.Discard)
		require.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)

		// Nothing to download: seeding places them, or ImageCopy downloads any it missed.
		fetcher := newStoreBlobFetcher(storeCtrl, "repo-a")
		assert.Empty(t, sm.DownloadStreamedBlobs(context.Background(), "repo-a", predictTestTag, fetcher.fetch))
		assert.Empty(t, fetcher.counts())

		sm.RemoveStreamingImage("repo-a", predictTestTag, false)
	})

	t.Run("removing an all-local image leaves another repo's streams of the same blobs", func(t *testing.T) {
		t.Parallel()

		sm := NewChunkingStreamManager(concrete, 0, log.NewTestLogger())

		// repo-b stores nothing, so the same image staged there streams every blob.
		forB, closeB := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
		defer closeB()
		forA, closeA := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
		defer closeA()

		_, err := sm.StoreImageForStreaming("repo-b", predictTestTag, forB)
		require.NoError(t, err)
		_, err = sm.StoreImageForStreaming("repo-a", predictTestTag, forA)
		require.NoError(t, err)

		sm.streamLock.Lock()
		streamsBefore := len(sm.activeStreams)
		sm.streamLock.Unlock()
		require.NotZero(t, streamsBefore)

		// repo-a took no references, so its removal must not drop repo-b's.
		sm.RemoveStreamingImage("repo-a", predictTestTag, false)

		sm.streamLock.Lock()
		assert.Len(t, sm.activeStreams, streamsBefore)

		for key := range forB.streamKeys {
			assert.Equal(t, 1, sm.refCounts[key])
		}
		sm.streamLock.Unlock()

		sm.RemoveStreamingImage("repo-b", predictTestTag, false)
	})
}

// activeStream returns source's stream for digest, failing the test if there is none.
func activeStream(t *testing.T, sm *ChunkingStreamManager, source, digest string) *ChunkedBlobReader {
	t.Helper()

	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	stream, ok := sm.activeStreams[streamKey(source, digest)]
	require.True(t, ok, "no active stream for %s", digest)

	return stream
}

// storeBlobFetcher is a BlobFetcher serving repo's blobs from a test store, as regclient's BlobGet
// would from upstream (digest-verified), and counting fetches per digest.
type storeBlobFetcher struct {
	imgStore stypes.ImageStore
	repo     string
	// failDigest's fetch fails with failErr.
	failDigest godigest.Digest
	failErr    error

	mu      sync.Mutex
	fetches map[godigest.Digest]int
}

func newStoreBlobFetcher(storeCtrl stypes.StoreController, repo string) *storeBlobFetcher {
	return &storeBlobFetcher{
		imgStore: storeCtrl.GetDefaultImageStore(),
		repo:     repo,
		fetches:  map[godigest.Digest]int{},
	}
}

func (f *storeBlobFetcher) fetch(_ context.Context, desc descriptor.Descriptor) (*blob.BReader, error) {
	f.mu.Lock()
	f.fetches[desc.Digest]++
	f.mu.Unlock()

	if desc.Digest == f.failDigest {
		return nil, f.failErr
	}

	content, err := f.imgStore.GetBlobContent(f.repo, desc.Digest)
	if err != nil {
		return nil, err
	}

	return blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content))), nil
}

// counts returns a copy of the fetch count per digest.
func (f *storeBlobFetcher) counts() map[godigest.Digest]int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return maps.Clone(f.fetches)
}

// TestBaseServiceDownloadStreamedBlobsLinksIntoLayout: the streaming sync's blobs are downloaded
// once, through regclient, into their stream files, which are hard-linked into the sync's temp
// layout; the ImageCopy that follows finds them there and leaves them alone, so each blob is held
// on disk once.
func TestBaseServiceDownloadStreamedBlobsLinksIntoLayout(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	// Staged under repo-x, which stores nothing, so every blob streams. Its upstream is repo-a's
	// OCI layout in the test store.
	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-x", predictTestTag, streamable)
	require.NoError(t, err)

	service := &BaseService{rc: regClient, streamManager: sm, log: log.NewTestLogger()}

	remoteImageRef := mustOCIDirRef(t, repoPath(root, "repo-a"), predictTestTag).
		SetDigest(streamable.referenceManifest.GetDescriptor().Digest.String())
	layoutDir := filepath.Join(t.TempDir(), "repo-x")
	localImageRef := mustOCIDirRef(t, layoutDir, predictTestTag)

	service.downloadStreamedBlobs(context.Background(), "repo-x", predictTestTag, remoteImageRef, localImageRef)

	imager, ok := streamable.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	layers, err := imager.GetLayers()
	require.NoError(t, err)

	descs := append([]descriptor.Descriptor{configDesc}, layers...)

	layoutFile := func(digest godigest.Digest) string {
		return filepath.Join(layoutDir, "blobs", digest.Algorithm().String(), digest.Encoded())
	}

	inodes := map[godigest.Digest]os.FileInfo{}

	for _, desc := range descs {
		streamInfo, err := os.Stat(activeStream(t, sm, "", desc.Digest.String()).OnDiskPath())
		require.NoError(t, err)

		layoutInfo, err := os.Stat(layoutFile(desc.Digest))
		require.NoError(t, err, "streamed blob %s must be in the layout", desc.Digest)
		require.True(t, os.SameFile(streamInfo, layoutInfo), "blob %s must be linked, not copied", desc.Digest)

		inodes[desc.Digest] = layoutInfo
	}

	require.NoError(t, regClient.ImageCopy(context.Background(), remoteImageRef, localImageRef))

	for _, desc := range descs {
		info, err := os.Stat(layoutFile(desc.Digest))
		require.NoError(t, err)
		assert.True(t, os.SameFile(inodes[desc.Digest], info),
			"ImageCopy must skip blob %s, not download and rewrite it", desc.Digest)
	}

	sm.RemoveStreamingImage("repo-x", predictTestTag, true)

	// The layout keeps its blobs after the stream files are deleted.
	for _, desc := range descs {
		content, err := os.ReadFile(layoutFile(desc.Digest))
		require.NoError(t, err)
		assert.Equal(t, desc.Digest, godigest.FromBytes(content))
	}
}

// streamConfigDesc returns streamable's config descriptor: a blob staging gives a stream (unless
// the repo already stores it), unlike the manifest itself.
func streamConfigDesc(t *testing.T, streamable *StreamableManifest) descriptor.Descriptor {
	t.Helper()

	imager, ok := streamable.referenceManifest.(manifest.Imager)
	require.True(t, ok)

	configDesc, err := imager.GetConfig()
	require.NoError(t, err)

	return configDesc
}

// TestChunkingStreamManagerRejectsInvalidDigest: an upstream manifest whose blob digest isn't valid
// (here, an algorithm that would climb out of _stream) is not staged, and nothing is written.
func TestChunkingStreamManagerRejectsInvalidDigest(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	for name, badDigest := range map[string]string{
		"escaping algorithm": "../../../escaped:" + strings.Repeat("a", 64),
		"bad encoding":       "sha256:not-hex",
	} {
		raw := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
			`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + badDigest +
			`","size":2},"layers":[]}`)

		man, err := manifest.New(manifest.WithRaw(raw))
		require.NoError(t, err, "%s: regclient accepts the descriptor as-is", name)

		_, err = sm.StoreImageForStreaming("repo-a", predictTestTag, NewStreamableManifest(man))
		require.ErrorIs(t, err, zerr.ErrSyncFailedToPrepareManifest, name)

		_, staged := sm.StreamingImageManifest("repo-a", predictTestTag)
		assert.False(t, staged, name)
	}

	sm.streamLock.Lock()
	assert.Empty(t, sm.activeStreams)
	sm.streamLock.Unlock()

	escaped, err := filepath.Glob(filepath.Join(filepath.Dir(root), "escaped*"))
	require.NoError(t, err)
	assert.Empty(t, escaped)

	_, err = os.Stat(filepath.Join(root, streamTempSubdir))
	assert.True(t, os.IsNotExist(err), "no stream dir should be created for a rejected manifest")
}

// TestChunkingStreamManagerHasStreamsForRepo: true only while a manifest staged under that exact
// repo has blob streams.
func TestChunkingStreamManagerHasStreamsForRepo(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	assert.False(t, sm.HasStreamsForRepo("repo-a"))

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	assert.True(t, sm.HasStreamsForRepo("repo-a"))
	assert.False(t, sm.HasStreamsForRepo("repo"), "a repo name that is a prefix of another must not match")
	assert.False(t, sm.HasStreamsForRepo("repo-b"))

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)
	assert.False(t, sm.HasStreamsForRepo("repo-a"))

	t.Run("an all-local image has no streams", func(t *testing.T) {
		concrete, ok := storeCtrl.(storage.StoreController)
		require.True(t, ok)

		// The real store: every blob is already in repo-a, so staging creates no stream.
		local := NewChunkingStreamManager(concrete, 0, log.NewTestLogger())

		_, err := local.StoreImageForStreaming("repo-a", predictTestTag, NewStreamableManifest(streamable.referenceManifest))
		require.NoError(t, err)

		_, staged := local.StreamingImageManifest("repo-a", predictTestTag)
		require.True(t, staged)
		assert.False(t, local.HasStreamsForRepo("repo-a"))

		local.RemoveStreamingImage("repo-a", predictTestTag, false)
	})
}

// TestChunkingStreamManagerCapCountsDrainingStreams: a torn-down stream whose clients are still
// draining keeps its temp file, so it keeps its cap slot until the file is deleted. Otherwise churn
// could leave more than maxConcurrentStreams files on staging disk.
func TestChunkingStreamManagerCapCountsDrainingStreams(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	// Exactly one image's worth of streams.
	sizing := newTestStreamManager(t, storeCtrl, 0)
	_, err := sizing.StoreImageForStreaming("repo-a", predictTestTag, NewStreamableManifest(streamable.referenceManifest))
	require.NoError(t, err)

	streamCount := len(sizing.activeStreams)
	require.Positive(t, streamCount)
	sizing.RemoveStreamingImage("repo-a", predictTestTag, false)

	sm := newTestStreamManager(t, storeCtrl, streamCount)
	sm.drainTimeout = time.Minute

	_, err = sm.StoreImageForStreaming("repo-a", predictTestTag, NewStreamableManifest(streamable.referenceManifest))
	require.NoError(t, err)

	// A client of the config's stream that won't finish on its own.
	stalled := activeStream(t, sm, "", streamConfigDesc(t, streamable).Digest.String())
	_, clientID := stalled.Subscribe()

	removed := make(chan struct{})

	go func() {
		defer close(removed)
		sm.RemoveStreamingImage("repo-a", predictTestTag, false)
	}()

	// Teardown has unmapped every stream; the stalled one is still draining.
	require.Eventually(t, func() bool {
		sm.streamLock.Lock()
		defer sm.streamLock.Unlock()

		return len(sm.activeStreams) == 0
	}, 5*time.Second, 10*time.Millisecond)

	require.Eventually(t, func() bool {
		sm.streamLock.Lock()
		defer sm.streamLock.Unlock()

		return sm.draining == 1
	}, 5*time.Second, 10*time.Millisecond, "only the stalled stream should still be draining")

	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, NewStreamableManifest(streamable.referenceManifest))
	require.ErrorIs(t, err, zerr.ErrTooManyConcurrentStreams, "a draining stream must still hold its cap slot")

	_, statErr := os.Stat(stalled.OnDiskPath())
	require.NoError(t, statErr, "the draining stream's temp file still exists")

	stalled.Unsubscribe(clientID)

	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("teardown must finish once the stalled client leaves")
	}

	sm.streamLock.Lock()
	assert.Zero(t, sm.draining)
	sm.streamLock.Unlock()

	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, NewStreamableManifest(streamable.referenceManifest))
	require.NoError(t, err, "the slot frees once the file is deleted")

	sm.RemoveStreamingImage("repo-b", predictTestTag, false)
}
