//go:build sync

package sync

import (
	"bytes"
	"context"
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

// newTestStreamManager adapts newTestStore's stypes.StoreController (an interface) back to the
// concrete storage.StoreController NewChunkingStreamManager expects - the same concrete type
// newTestStore itself constructs internally, just returned through the narrower interface.
func newTestStreamManager(t *testing.T, storeCtrl stypes.StoreController, maxConcurrentStreams int) *ChunkingStreamManager {
	t.Helper()

	concrete, ok := storeCtrl.(storage.StoreController)
	require.True(t, ok, "newTestStore must return a storage.StoreController")

	return NewChunkingStreamManager(concrete, maxConcurrentStreams, log.NewTestLogger())
}

// newTestStreamableManifest fetches repo:tag (written under storeCtrl's root by one of
// oci_digest_predict_internal_test.go's writeOCI* helpers) as a real regclient manifest.Manifest,
// wrapped for streaming. The caller must regClient.Close(ctx, ref) via the returned closer.
func newTestStreamableManifest(t *testing.T, regClient *regclient.RegClient, root, repo, tag string,
) (*StreamableManifest, func()) {
	t.Helper()

	srcRef := mustOCIDirRef(t, repoPath(root, repo), tag)

	man, err := regClient.ManifestGet(context.Background(), srcRef)
	require.NoError(t, err)

	return NewStreamableManifest(man, nil), func() { regClient.Close(context.Background(), man.GetRef()) }
}

// newTestStreamableMultiArchManifest fetches repo:tag (written by writeOCIMultiPlatformIndex or
// writeDockerMultiPlatformIndex) as a real regclient index manifest, plus each of its platform
// children fetched individually via SetDigest - mirroring how service.go's real FetchManifest
// populates subManifests for a multi-arch image (see service.go's per-platform fetch loop) -
// wrapped for streaming. The caller must call the returned closer to release every fetched ref
// (the index and each child).
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

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

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
	_, isActive := sm.activeStreams[manifestDigest]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the manifest's own digest must become an active stream")

	sm.RemoveStreamingImage("repo-a", predictTestTag)

	_, ok = sm.StreamingImageManifest("repo-a", predictTestTag)
	assert.False(t, ok, "manifest must no longer be staged for streaming after removal")

	sm.streamLock.Lock()
	_, isActive = sm.activeStreams[manifestDigest]
	sm.streamLock.Unlock()
	assert.False(t, isActive, "the manifest's blob stream must be gone after removal")
}

// TestChunkingStreamManagerStoreDockerManifest is the regression test for Docker schema2 support:
// PreserveDigest (required by every streaming registry) keeps a manifest in whatever media type
// upstream actually served, and Docker registries commonly serve schema2, not OCI -
// StoreImageForStreaming must accept that media type the same way it already accepts OCI's,
// rather than rejecting it with ErrSyncInvalidManifestMediaType.
func TestChunkingStreamManagerStoreDockerManifest(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeDockerSingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

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
	_, isActive := sm.activeStreams[manifestDigest]
	sm.streamLock.Unlock()
	assert.True(t, isActive, "the Docker manifest's own digest must become an active stream")
}

// TestChunkingStreamManagerRemoveDoesNotBlockOtherBlobs is the regression test for the
// streamLock-scoping fix: RemoveStreamingImage must never hold the manager-wide lock while
// waiting for a slow/abandoned client on ONE blob to drain, since that lock also guards every
// other repo/blob's active streams. Before the fix, a stalled client on repo-a's manifest would
// freeze CachedBlobInfo (and ConnectClient/StreamingBlobReader/StoreImageForStreaming) for
// repo-b's completely unrelated blob for as long as the stall lasted.
func TestChunkingStreamManagerRemoveDoesNotBlockOtherBlobs(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)
	writeOCISingleManifest(t, storeCtrl, root, "repo-b", predictTestTag)

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
	readerA := sm.activeStreams[digestA]
	sm.streamLock.Unlock()
	require.NotNil(t, readerA)

	// Simulate a stalled/abandoned client on repo-a's manifest blob: subscribed, never
	// unsubscribing on its own.
	_, clientID := readerA.Subscribe()

	removeDone := make(chan struct{})

	go func() {
		defer close(removeDone)
		sm.RemoveStreamingImage("repo-a", predictTestTag)
	}()

	// Give the goroutine a moment to actually enter WaitForClientEmpty for repo-a's blob before
	// exercising repo-b.
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

	// Let repo-a's drain finish so the test doesn't leak the goroutine or hold up teardown for
	// the full streamDrainTimeout.
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

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	// A single manifest registers itself, its config, and each layer as separate active
	// streams (see collectManifestDescriptorsForStream) - several blobs, comfortably exceeding
	// a cap of 1, so registering it must hit the cap before finishing.
	sm := newTestStreamManager(t, storeCtrl, 1)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.Error(t, err)
	// The specific cap error must survive (not be masked as a generic failure) so callers like
	// FetchManifestForStream can fall back to a non-streaming on-demand sync.
	assert.ErrorIs(t, err, zerr.ErrTooManyConcurrentStreams)

	// Regression test: a mid-way failure must roll back every stream this call created, not
	// just stay under the cap - otherwise the entry created before hitting the cap leaks
	// forever (nothing will ever call RemoveStreamingImage for a repo:reference that never made
	// it into streamingRefs).
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

// TestChunkingStreamManagerSharedBlobAcrossRepos is the regression test for the reference-
// counting fix: a blob shared by two different repo:reference entries must only be torn down
// once BOTH have been removed, since it's the same shared ChunkedBlobReader/temp file serving
// clients for either one (see activeStreams' doc comment).
func TestChunkingStreamManagerSharedBlobAcrossRepos(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	// Both repos get the exact same manifest/config/layer content (the same built Image written
	// to each), so every digest they reference is identical - i.e. genuinely shared, not just
	// coincidentally similar. writeOCISingleManifest can't be reused for this: each call builds
	// a fresh Image with its own randomized layer content, which would give repo-a and repo-b
	// different digests.
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
	refCount := sm.refCounts[manifestDigest]
	sm.streamLock.Unlock()
	assert.Equal(t, 2, refCount, "both repo:reference registrations must be counted")

	// Removing repo-a must NOT tear down the shared blob - repo-b still needs it.
	sm.RemoveStreamingImage("repo-a", predictTestTag)

	sm.streamLock.Lock()
	_, stillActive := sm.activeStreams[manifestDigest]
	refCount = sm.refCounts[manifestDigest]
	sm.streamLock.Unlock()
	assert.True(t, stillActive, "a blob still referenced by repo-b must survive repo-a's removal")
	assert.Equal(t, 1, refCount)

	copier, err := sm.ConnectClient("repo-b", manifestDigest, nil)
	require.NoError(t, err, "repo-b's clients must still be able to attach to the shared blob")
	copier.Close()

	// Removing repo-b too must finally tear it down.
	sm.RemoveStreamingImage("repo-b", predictTestTag)

	sm.streamLock.Lock()
	_, stillActive = sm.activeStreams[manifestDigest]
	_, refExists := sm.refCounts[manifestDigest]
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

// TestChunkingStreamManagerConnectClientCrossRepoDenied is the regression test for the
// stream-client-scoping fix: activeStreams is shared across repos that happen to reference the
// same digest (see its doc comment), but a caller authorized only for a DIFFERENT repo must not
// be able to attach to it merely by knowing (or guessing) the digest.
func TestChunkingStreamManagerConnectClientCrossRepoDenied(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	// Sanity check: the same digest, requested under the repo it is actually staged for, works.
	_, err = sm.ConnectClient("repo-a", manifestDigest, nil)
	require.NoError(t, err)

	// The same digest, requested under an unrelated repo, must be reported exactly like an
	// unknown digest - not a distinguishable "forbidden" response that would confirm the digest
	// is streaming for someone else.
	_, err = sm.ConnectClient("repo-b", manifestDigest, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)
}

func TestChunkingStreamManagerCachedBlobInfo(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

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

	// Same denial semantics as ConnectClient: a digest that IS staged, but under a different
	// repo, must report not-found rather than leaking its size/media type.
	_, _, err = sm.CachedBlobInfo("repo-b", desc.Digest.String())
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFound)
}

func TestChunkingStreamManagerRemoveStreamingImageNoOp(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	// Nothing was ever staged for repo:reference - syncImage calls this unconditionally after
	// every sync on any registry sharing this stream manager, so this must be a harmless no-op,
	// not a panic or error.
	require.NotPanics(t, func() { sm.RemoveStreamingImage("repo", predictTestTag) })
}

// TestChunkingStreamManagerRemoveStreamingImageDeletesTempFile is the regression test for
// deleteStreamFile actually being reached: once a blob's last referencing repo:reference is
// removed and it has no connected clients, its on-disk staging file must be deleted, not just its
// in-memory bookkeeping.
func TestChunkingStreamManagerRemoveStreamingImageDeletesTempFile(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[manifestDigest].OnDiskPath()
	sm.streamLock.Unlock()

	_, statErr := os.Stat(onDiskPath)
	require.NoError(t, statErr, "prepareActiveStreamForBlob must have created the temp file up front")

	sm.RemoveStreamingImage("repo-a", predictTestTag)

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

	_, err := sm.StreamingBlobReader(reader)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobReaderMissing)
}

// TestChunkingStreamManagerStreamingBlobReaderSkipsDoubleInit is the regression test for the
// shared-layer fix: when a blob is already wired up for streaming (e.g. a layer shared by two
// platforms of the same multi-arch image, both reaching this hook), a second regclient reader for
// the identical digest must not be wrapped again - that would mean two independent readers both
// trying to drive the one on-disk file - and must be returned completely unmodified instead.
func TestChunkingStreamManagerStreamingBlobReaderSkipsDoubleInit(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	desc := streamable.referenceManifest.GetDescriptor()

	content := []byte("first init wins this blob's stream")
	firstReader := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	wrapped, err := sm.StreamingBlobReader(firstReader)
	require.NoError(t, err)
	require.NotNil(t, wrapped)
	assert.NotSame(t, firstReader, wrapped, "the first call must wrap the reader for streaming")

	secondReader := blob.NewReader(blob.WithDesc(desc), blob.WithReader(bytes.NewReader(content)))

	unwrapped, err := sm.StreamingBlobReader(secondReader)
	require.NoError(t, err)
	assert.Same(t, secondReader, unwrapped, "a digest already initialized must return the reader unmodified")
}

// TestChunkingStreamManagerStoreMultiArchManifest is the regression test for multi-arch
// (manifest-list/index) support: StoreImageForStreaming, digestBelongsToRepo, and
// RemoveStreamingImage each branch separately on whether a manifest is a single image or an
// index, and none of that branch was previously exercised by any test - every other test in this
// file uses a single-platform manifest.
func TestChunkingStreamManagerStoreMultiArchManifest(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCIMultiPlatformIndex(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableMultiArchManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	require.NotEmpty(t, streamable.subManifests,
		"test setup: must have platform children to exercise the multi-arch branch")

	staged, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)
	assert.Same(t, streamable, staged)

	// Every platform child's own layers must have become active streams too, not just the
	// top-level index - and digestBelongsToRepo (exercised here via ConnectClient) must recognize
	// a digest that belongs only to a sub-manifest, not just the index itself.
	for _, subManifest := range streamable.subManifests {
		imager, ok := subManifest.(manifest.Imager)
		require.True(t, ok)

		layers, err := imager.GetLayers()
		require.NoError(t, err)
		require.NotEmpty(t, layers)

		layerDigest := layers[0].Digest.String()

		sm.streamLock.Lock()
		_, isActive := sm.activeStreams[layerDigest]
		sm.streamLock.Unlock()
		assert.True(t, isActive, "a platform child's layer must become an active stream")

		copier, err := sm.ConnectClient("repo-a", layerDigest, nil)
		assert.NoError(t, err)

		if copier != nil {
			copier.Close()
		}
	}

	indexDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.RemoveStreamingImage("repo-a", predictTestTag)

	sm.streamLock.Lock()
	_, stillActive := sm.activeStreams[indexDigest]
	sm.streamLock.Unlock()
	assert.False(t, stillActive, "the index and its children's streams must all be torn down on removal")
}

// TestChunkingStreamManagerDeleteStreamFilePermissionError exercises deleteStreamFile's error
// path (os.Remove failing on an existing file, e.g. a read-only filesystem or a permissions
// issue) - distinct from the common, harmless case of the file already being gone. Must not
// panic or propagate the error: cleanup here is logged, best-effort.
func TestChunkingStreamManagerDeleteStreamFilePermissionError(t *testing.T) {
	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	_, err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.NoError(t, err)

	manifestDigest := streamable.referenceManifest.GetDescriptor().Digest.String()

	sm.streamLock.Lock()
	onDiskPath := sm.activeStreams[manifestDigest].OnDiskPath()
	sm.streamLock.Unlock()

	// Removing a file requires write permission on its containing directory, not the file
	// itself - stripping it here makes os.Remove fail with a permission error while os.Stat
	// (a read) still succeeds, exercising deleteStreamFile's actual error-logging branch rather
	// than its "already gone" fast path. Not t.Parallel(): this mutates a shared filesystem
	// permission bit for its duration.
	parentDir := filepath.Dir(onDiskPath)
	require.NoError(t, os.Chmod(parentDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(parentDir, 0o755) }) // restore so t.TempDir() can clean up

	require.NotPanics(t, func() { sm.RemoveStreamingImage("repo-a", predictTestTag) })

	// The file must still be there, since removal genuinely failed rather than being skipped.
	_, statErr := os.Stat(onDiskPath)
	assert.NoError(t, statErr)
}
