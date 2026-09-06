//go:build sync

package sync

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/regclient/regclient"
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

func TestChunkingStreamManagerStoreAndRemove(t *testing.T) {
	t.Parallel()

	root, storeCtrl := newTestStore(t)
	regClient := regclient.New()

	writeOCISingleManifest(t, storeCtrl, root, "repo-a", predictTestTag)

	sm := newTestStreamManager(t, storeCtrl, 0)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	require.NoError(t, sm.StoreImageForStreaming("repo-a", predictTestTag, streamable))

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

	require.NoError(t, sm.StoreImageForStreaming("repo-a", predictTestTag, streamableA))
	require.NoError(t, sm.StoreImageForStreaming("repo-b", predictTestTag, streamableB))

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
		_, _, err := sm.CachedBlobInfo(digestB)
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

	err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrSyncFailedToPrepareManifest)

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

	require.NoError(t, sm.StoreImageForStreaming("repo-a", predictTestTag, streamableA))
	require.NoError(t, sm.StoreImageForStreaming("repo-b", predictTestTag, streamableB))

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

	_, err := sm.ConnectClient(manifestDigest, nil)
	assert.NoError(t, err, "repo-b's clients must still be able to attach to the shared blob")

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

	_, err := sm.ConnectClient("sha256:"+strings.Repeat("0", 64), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)
}
