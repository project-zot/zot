package sync

import (
	"context"
	"io"

	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
)

// OnDemand pulls images and referrers from upstream registries on client request.
type OnDemand interface {
	// SyncImage syncs a single image (repo:tag or repo:digest) into local storage.
	SyncImage(ctx context.Context, repo, reference string) error
	// SyncReferrers syncs referrers for the given subject digest into local storage.
	SyncReferrers(ctx context.Context, repo string, subjectDigestStr string, referenceTypes []string) error
	// ShouldCheckUpstreamManifest reports whether repo:reference still needs an upstream check.
	ShouldCheckUpstreamManifest(repo, reference string) bool
	// ShouldQueueOnDemandSync reports whether a missing local manifest for repo should
	// return immediately while a background sync copies the image into storage.
	ShouldQueueOnDemandSync(repo string) bool
	// QueueImage schedules at most one background SyncImage for repo:reference from
	// onDemandInBackground registries that match the repo. The request context is detached.
	QueueImage(ctx context.Context, repo, reference string)
	// FetchManifestForStream returns repo:reference's manifest straight from upstream and syncs
	// the full image in the background. onSynced, if non-nil, runs once that sync commits (e.g.
	// to count a download whose metadata didn't exist yet), whether this call started the sync or
	// joined one another caller started. It doesn't run if the sync fails.
	FetchManifestForStream(ctx context.Context, repo, reference string,
		onSynced func(manifest.Manifest)) (manifest.Manifest, error)
	// StreamManager returns the shared stream manager, or nil when no registry streams.
	StreamManager() StreamManager
	// IsStreamingEnabledForRepo reports whether any on-demand service streams blobs for repo.
	IsStreamingEnabledForRepo(repo string) bool
}

// StreamManager tracks manifests staged for streaming and the blobs being streamed to clients
// while they download.
type StreamManager interface {
	// ConnectClient attaches a client to blobDigest's stream. blobDigest must belong to a
	// manifest staged under repo, so access stays scoped to repos the caller may read.
	ConnectClient(repo, blobDigest string, writer io.Writer) (BlobCopier, error)
	// StreamingBlobReader is the regclient reader hook for repo:reference's background sync. It
	// wraps each blob's reader so the bytes also feed that blob's stream.
	StreamingBlobReader(repo, reference string, reader *blob.BReader) (*blob.BReader, error)
	// StoreImageForStreaming stages a manifest and creates a stream for each of its blobs. If a
	// concurrent caller already staged repo:reference, that manifest is returned instead; callers
	// must use the returned one, since only its blobs have streams.
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest) (*StreamableManifest, error)
	// StreamingImageManifest returns the manifest staged for repo:reference, if any.
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	// JoinStreamingImage returns the manifest staged for repo:reference, if any, and registers
	// onSynced (if non-nil) to run once its background sync commits, like the stager's own.
	JoinStreamingImage(repo, reference string, onSynced func(manifest.Manifest)) (*StreamableManifest, bool)
	// RemoveStreamingImage unstages repo:reference once its background sync has finished. If
	// synced, every onSynced registered for it runs with the staged manifest.
	RemoveStreamingImage(repo, reference string, synced bool)
	// CachedBlobInfo returns a staged blob's size and media type (scoped to repo like
	// ConnectClient), available before its download starts.
	CachedBlobInfo(repo, blobDigest string) (size int64, mediaType string, err error)
}

// BlobCopier copies one streamed blob (or a range of it) to one client.
type BlobCopier interface {
	// Copy streams the whole blob, returning when done or when the download fails.
	Copy() error
	// CopyRange streams bytes [start, end] (inclusive), returning as soon as end has arrived. The
	// caller validates the range first (e.g. via CachedBlobInfo).
	CopyRange(start, end int64) error
	// Descriptor waits (bounded) for the blob's download to start and returns its descriptor, or
	// an error if it never starts or already failed.
	Descriptor() (descriptor.Descriptor, error)
	// Close releases the subscription when Copy will never run. Harmless after Copy.
	Close()
}

// StreamableManifest is a manifest staged for streaming, plus, for a multi-arch image, its
// per-platform manifests (their blobs are what actually gets streamed).
type StreamableManifest struct {
	referenceManifest manifest.Manifest
	subManifests      []manifest.Manifest
	// source is the registry that supplied this manifest; streams are keyed by it so clients of
	// one registry never get unverified bytes downloaded from another.
	source string //nolint:unused // only read/written by sync-tagged files (stream_manager.go, on_demand.go)
	// onSynced are the callbacks of every request served this manifest (the stager's and each
	// joiner's), run once its background sync commits. Guarded by the stream manager's lock.
	onSynced []func(manifest.Manifest) //nolint:unused // only used by sync-tagged files
}

// NewStreamableManifest wraps a manifest and its child manifests (if multi-arch) for staging.
func NewStreamableManifest(mainManifest manifest.Manifest, subManifests []manifest.Manifest) *StreamableManifest {
	return &StreamableManifest{
		referenceManifest: mainManifest,
		subManifests:      subManifests,
	}
}
