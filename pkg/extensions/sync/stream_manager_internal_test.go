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
	// streams (see prepareManifestAndContentsForStream) - several blobs, comfortably exceeding
	// a cap of 1, so registering it must hit the cap before finishing.
	sm := newTestStreamManager(t, storeCtrl, 1)

	streamable, closeManifest := newTestStreamableManifest(t, regClient, root, "repo-a", predictTestTag)
	defer closeManifest()

	err := sm.StoreImageForStreaming("repo-a", predictTestTag, streamable)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrSyncFailedToPrepareManifest)

	sm.streamLock.Lock()
	activeCount := len(sm.activeStreams)
	sm.streamLock.Unlock()
	assert.LessOrEqual(t, activeCount, 1, "must never exceed the configured concurrent-stream cap")
}

func TestChunkingStreamManagerConnectClientUnknownDigest(t *testing.T) {
	t.Parallel()

	_, storeCtrl := newTestStore(t)
	sm := newTestStreamManager(t, storeCtrl, 0)

	_, err := sm.ConnectClient("sha256:"+strings.Repeat("0", 64), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, zerr.ErrBlobNotFoundInActiveStreams)
}
