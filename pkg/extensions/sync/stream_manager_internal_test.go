//go:build sync

package sync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	"zotregistry.dev/zot/v2/pkg/storage"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// newTestStreamManager builds a stream manager over newTestStore's store controller.
func newTestStreamManager(t *testing.T, storeCtrl stypes.StoreController, maxConcurrentStreams int) *ChunkingStreamManager {
	t.Helper()

	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok, "newTestStore must return a storage.StoreController")

	return NewChunkingStreamManager(concrete, maxConcurrentStreams, log.NewTestLogger())
}

// newTestStreamableManifest fetches repo:tag (written by a writeOCI* helper) as a streamable
// manifest. Call the returned closer when done.
func newTestStreamableManifest(t *testing.T, regClient *regclient.RegClient, root, repo, tag string,
) (*StreamableManifest, func()) {
	t.Helper()

	srcRef := mustOCIDirRef(t, repoPath(root, repo), tag)

	man, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	return NewStreamableManifest(man, nil), func() { regClient.Close(context.Background(), man.GetRef()) }
}

// newTestStreamableMultiArchManifest fetches an index and each of its platform manifests, the way
// FetchManifest does. Call the returned closer when done.
func newTestStreamableMultiArchManifest(t *testing.T, regClient *regclient.RegClient, root, repo, tag string,
) (*StreamableManifest, func()) {
	t.Helper()

	srcRef := mustOCIDirRef(t, repoPath(root, repo), tag)

	indexManifest, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	closers := []func(){func() { regClient.Close(context.Background(), indexManifest.GetRef()) }}

	indexer, ok := indexManifest.(manifest.Indexer)
	require.True(t, ok, "test setup: must actually produce an index manifest")

	childDescs, err := indexer.GetManifestList()
	require.NoError(t, err)
	require.NotEmpty(t, childDescs, "test setup: index must have at least one platform child")

	subManifests := make([]manifest.Manifest, 0, len(childDescs))

	for _, desc := range childDescs {
		childRef := srcRef.SetDigest(desc.Digest.String())

		childManifest, err := regClient.ManifestGet(context.Background(), childRef)
		require.NoError(t, err)

		subManifests = append(subManifests, childManifest)
		closers = append(closers, func() { regClient.Close(context.Background(), childManifest.GetRef()) })
	}

	return NewStreamableManifest(indexManifest, subManifests), func() {
		for _, closeFn := range closers {
			closeFn()
		}
	}
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

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	_, isActive := sm.activeStreams[streamKey("", manifestDigest)]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the manifest's own digest must become an active stream")

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	_, ok = sm.StreamingImageManifest("repo-a", predictTestTag)
	assert.False(t, ok, "manifest must no longer be staged for streaming after removal")

	sm.streamLock.Lock()
	_, isActive = sm.activeStreams[streamKey("", manifestDigest)]
	sm.streamLock.Unlock()
	assert.False(t, isActive, "the manifest's blob stream must be gone after removal")
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

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	_, isActive := sm.activeStreams[streamKey("", manifestDigest)]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the Docker manifest's own digest must become an active stream")
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

	digestA := streamableA.referenceManifest.GetDescriptor().Digest.String()
	digestB := streamableB.referenceManifest.GetDescriptor().Digest.String()

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

func TestChunkingStreamManagerMaxConcurrentStreams(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	// The manifest, config and layers are separate streams, so a cap of 1 is hit partway.
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

	manifestDigest := streamableA.referenceManifest.GetDescriptor().Digest.String()
	require.Equal(t, manifestDigest, streamableB.referenceManifest.GetDescriptor().Digest.String(),
		"test setup: both repos must reference the identical manifest digest")

	sm.streamLock.Lock()
	refCount := sm.refCounts[streamKey("", manifestDigest)]
	sm.streamLock.Unlock()
	assert.Equal(t, 2, refCount, "both repo:reference registrations must be counted")

	// repo-b still needs the shared blob.
	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	sm.streamLock.Lock()
	_, stillActive := sm.activeStreams[streamKey("", manifestDigest)]
	refCount = sm.refCounts[streamKey("", manifestDigest)]
	sm.streamLock.Unlock()
	assert.True(t, stillActive, "a blob still referenced by repo-b must survive repo-a's removal")
	assert.Equal(t, 1, refCount)

	copier, err := sm.ConnectClient("repo-b", manifestDigest, nil)
	require.NoError(t, err, "repo-b's clients must still be able to attach to the shared blob")
	copier.Close()

	// Now nothing needs it.
	sm.RemoveStreamingImage("repo-b", predictTestTag, false)

	sm.streamLock.Lock()
	_, stillActive = sm.activeStreams[streamKey("", manifestDigest)]
	_, refExists := sm.refCounts[streamKey("", manifestDigest)]
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

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	// The repo it is staged under works.
	_, err = sm.ConnectClient("repo-a", manifestDigest, nil)
	require.NoError(t, err)

	// Another repo gets the same error as an unknown digest, so it learns nothing.
	_, err = sm.ConnectClient("repo-b", manifestDigest, nil)
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

	desc := streamable.referenceManifest.GetDescriptor()

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

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[streamKey("", manifestDigest)].OnDiskPath()
	sm.streamLock.Unlock()

	_, statErr := os.Stat(onDiskPath)
	require.NoError(t, statErr, "prepareActiveStreamForBlob must have created the temp file up front")

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	_, statErr = os.Stat(onDiskPath)
	assert.True(t, os.IsNotExist(statErr), "the temp file must be deleted once the blob has no clients and no referencing repo:reference left")
}

func TestChunkingStreamManagerStreamingBlobReaderUnknownDigest(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	content := []byte("streaming blob reader test content")
	desc := descriptor.Descriptor{Digest: godigest.FromBytes(content), Size: int64(len(content))}
	reader := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	_, err := sm.StreamingBlobReader("repo-a", predictTestTag, reader)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobReaderMissing)
}

// TestChunkingStreamManagerStreamingBlobReaderSkipsDoubleInit: a second reader for a blob that
// already has a producer is returned unwrapped, so the file isn't written twice.
func TestChunkingStreamManagerStreamingBlobReaderSkipsDoubleInit(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	desc := streamable.referenceManifest.GetDescriptor()

	content := []byte("first init wins this blob's stream")
	firstReader := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	wrapped, err := sm.StreamingBlobReader("repo-a", predictTestTag, firstReader)
	require.NoError(t, err)
	require.NotNil(t, wrapped)
	assert.NotSame(t, firstReader, wrapped, "the first call must wrap the reader for streaming")

	secondReader := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	unwrapped, err := sm.StreamingBlobReader("repo-a", predictTestTag, secondReader)
	require.NoError(t, err)
	assert.Same(t, secondReader, unwrapped, "a digest already initialized must return the reader unmodified")
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
	fromA := NewStreamableManifest(base.referenceManifest, nil)
	fromA.source = "0"
	fromB := NewStreamableManifest(base.referenceManifest, nil)
	fromB.source = "1"

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, fromA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-b", predictTestTag, fromB)
	require.NoError(t, err)

	desc := base.referenceManifest.GetDescriptor()
	digest := desc.Digest.String()

	sm.streamLock.Lock()
	streamA := sm.activeStreams[streamKey("0", digest)]
	streamB := sm.activeStreams[streamKey("1", digest)]
	sm.streamLock.Unlock()
	require.NotNil(t, streamA)
	require.NotNil(t, streamB)
	assert.NotSame(t, streamA, streamB, "each source registry must get its own stream for a shared digest")

	content := []byte("bytes downloaded by registry A's background sync")

	readerA := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))
	wrappedA, err := sm.StreamingBlobReader("repo-a", predictTestTag, readerA)
	require.NoError(t, err)
	assert.NotSame(t, readerA, wrappedA, "repo-a's sync must feed registry A's stream")

	// B's stream is still unclaimed; with digest-only keys this would come back unwrapped.
	readerB := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))
	wrappedB, err := sm.StreamingBlobReader("repo-b", predictTestTag, readerB)
	require.NoError(t, err)
	assert.NotSame(t, readerB, wrappedB, "repo-b's sync must feed registry B's own stream")

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

	desc := streamable.referenceManifest.GetDescriptor()
	digest := desc.Digest.String()

	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	wrapped, err := sm.StreamingBlobReader("repo-a", predictTestTag, producer)
	require.NoError(t, err)

	_, err = io.Copy(io.Discard, wrapped)
	require.ErrorIs(t, err, wantErr)

	_, err = sm.ConnectClient("repo-a", digest, io.Discard)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)
}

// TestChunkingStreamManagerStoreMultiArchManifest: staging, lookup and removal of a multi-arch
// index, whose blobs belong to its platform manifests.
func TestChunkingStreamManagerStoreMultiArchManifest(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCIMultiPlatformIndex(t, storeCtrl, "repo-a")

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableMultiArchManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	require.NotEmpty(t, streamable.subManifests,
		"test setup: must have platform children to exercise the multi-arch branch")

	staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)
	assert.Same(t, streamable, staged)

	// Each platform's blobs are streams too, and ConnectClient finds a digest that only a platform
	// manifest references.
	for _, subManifest := range streamable.subManifests {
		imager, ok := subManifest.(manifest.Imager)
		require.True(t, ok)

		layers, err := imager.GetLayers()
		require.NoError(t, err)
		require.NotEmpty(t, layers)

		layerDigest := layers[0].Digest.String()

		sm.streamLock.Lock()
		_, isActive := sm.activeStreams[streamKey("", layerDigest)]
		sm.streamLock.Unlock()
		assert.True(t, isActive, "a platform child's layer must become an active stream")

		copier, err := sm.ConnectClient("repo-a", layerDigest, nil)
		assert.NoError(t, err)

		if copier != nil {
			copier.Close()
		}
	}

	indexDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.RemoveStreamingImage("repo-a", predictTestTag, false)

	sm.streamLock.Lock()
	_, stillActive := sm.activeStreams[streamKey("", indexDigest)]
	sm.streamLock.Unlock()
	assert.False(t, stillActive, "the index and its children's streams must all be torn down on removal")
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

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[streamKey("", manifestDigest)].OnDiskPath()
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

	fromA := NewStreamableManifest(base.referenceManifest, nil)
	fromA.source = "0"
	fromB := NewStreamableManifest(base.referenceManifest, nil)
	fromB.source = "1"

	_, err := sm.StoreImageForStreaming("repo-a", "tag-a", fromA)
	require.NoError(t, err)
	_, err = sm.StoreImageForStreaming("repo-a", "tag-b", fromB)
	require.NoError(t, err)

	digest := base.referenceManifest.GetDescriptor().Digest.String()

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

	desc := streamable.referenceManifest.GetDescriptor()

	_, _, err = sm.CachedBlobInfo("repo-a", desc.Digest.String())
	require.NoError(t, err)

	wantErr := errors.New("simulated upstream network failure")
	producer := blob.NewReader(blob.WithDesc(desc),
		blob.WithReader(&erroringAfterReader{content: []byte("this"), err: wantErr}))

	wrapped, err := sm.StreamingBlobReader("repo-a", predictTestTag, producer)
	require.NoError(t, err)

	_, err = io.Copy(io.Discard, wrapped)
	require.ErrorIs(t, err, wantErr)

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

		stager := NewStreamableManifest(base.referenceManifest, nil)
		stager.onSynced = []func(manifest.Manifest){record("stager")}

		_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, stager)
		require.NoError(t, err)

		_, ok := sm.JoinStreamingImage("repo-a", predictTestTag, record("joiner"))
		require.True(t, ok)

		loser := NewStreamableManifest(base.referenceManifest, nil)
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
