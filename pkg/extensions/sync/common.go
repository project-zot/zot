package sync

import (
	"context"
	"io"

	godigest "github.com/opencontainers/go-digest"
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
	// the image in the background. onSynced, if non-nil, runs once that sync commits (e.g. to
	// count a download). If the image is not streamed (e.g. an index, or the stream cap), it waits
	// for a plain sync and returns ErrSyncNotStreamed, wrapping that sync's error if it failed;
	// the caller then serves from storage.
	FetchManifestForStream(ctx context.Context, repo, reference string,
		onSynced func(manifest.Manifest)) (manifest.Manifest, error)
	// StreamManager returns the shared stream manager, or nil when no registry streams.
	StreamManager() StreamManager
	// IsStreamingEnabledForRepo reports whether any on-demand service streams blobs for repo.
	IsStreamingEnabledForRepo(repo string) bool
}

// StreamManager tracks manifests staged for streaming and their blobs' streams.
type StreamManager interface {
	// ConnectClient attaches a client to blobDigest's stream. The blob must belong to a manifest
	// staged under repo, so access stays scoped to repos the caller may read.
	ConnectClient(repo, blobDigest string, writer io.Writer) (BlobCopier, error)
	// DownloadStreamedBlobs downloads repo:reference's streamed blobs with fetch, for its
	// background sync, and returns each completed blob's temp file by digest, for the sync to link
	// into its layout.
	DownloadStreamedBlobs(ctx context.Context, repo, reference string, fetch BlobFetcher) map[godigest.Digest]string
	// StoreImageForStreaming stages a manifest and creates a stream per blob the repo lacks. If
	// repo:reference is already staged, that manifest is returned instead; use the returned one,
	// since only its blobs have streams.
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest) (*StreamableManifest, error)
	// StreamingImageManifest returns the manifest staged for repo:reference, if any.
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	// JoinStreamingImage returns repo:reference's staged manifest, if any, and registers onSynced
	// (if non-nil) to run once its sync commits.
	JoinStreamingImage(repo, reference string, onSynced func(manifest.Manifest)) (*StreamableManifest, bool)
	// RemoveStreamingImage unstages repo:reference after its sync. If synced, its onSynced
	// callbacks run.
	RemoveStreamingImage(repo, reference string, synced bool)
	// HasStreamsForRepo reports whether any manifest staged under repo has blob streams.
	HasStreamsForRepo(repo string) bool
	// CachedBlobInfo returns a staged blob's size and media type before its download starts
	// (scoped to repo like ConnectClient).
	CachedBlobInfo(repo, blobDigest string) (size int64, mediaType string, err error)
}

// BlobFetcher opens a blob at the upstream a staged image was fetched from. The sync passes
// regclient's BlobGet, pinned to its remote repo, so auth, mirrors, throttling and resumed reads
// all stay regclient's.
type BlobFetcher func(ctx context.Context, desc descriptor.Descriptor) (*blob.BReader, error)

// BlobCopier copies one streamed blob (or a range of it) to one client.
type BlobCopier interface {
	// Copy streams the whole blob, returning when done or when the download fails.
	Copy() error
	// CopyRange streams bytes [start, end] (inclusive), returning as soon as end has arrived. The
	// caller validates the range first (e.g. via CachedBlobInfo).
	CopyRange(start, end int64) error
	// Descriptor waits (bounded) for the download to start, or errors if it never starts, failed,
	// or ctx (the request's) ends first. On error the caller must Close.
	Descriptor(ctx context.Context) (descriptor.Descriptor, error)
	// Close releases the subscription when Copy will never run. Harmless after Copy.
	Close()
}

// StreamableManifest is an image manifest staged for streaming. Indexes are never staged: their
// sync is sparse, so nothing would feed the streams.
type StreamableManifest struct {
	referenceManifest manifest.Manifest
	// source names the registry that supplied this manifest (BaseOnDemand.streamSource). Streams
	// are keyed by it, so clients never get another registry's unverified bytes.
	source string //nolint:unused // only read/written by sync-tagged files (stream_manager.go, on_demand.go)
	// onSynced holds every served request's callback, run once the sync commits. Guarded by
	// streamLock.
	onSynced []func(manifest.Manifest) //nolint:unused // only used by sync-tagged files
	// streamKeys are the streams this manifest references: its blobs minus those already local.
	// Set at staging; guarded by streamLock.
	streamKeys map[string]struct{} //nolint:unused // only used by sync-tagged files
	// done is closed when RemoveStreamingImage unstages it, after its onSynced callbacks; synced
	// then reports whether its sync succeeded. Lets a flight that joined it wait for its sync.
	done   chan struct{} //nolint:unused // only used by sync-tagged files
	synced bool          //nolint:unused // only used by sync-tagged files
}

// NewStreamableManifest wraps an image manifest for staging.
func NewStreamableManifest(mainManifest manifest.Manifest) *StreamableManifest {
	return &StreamableManifest{
		referenceManifest: mainManifest,
		done:              make(chan struct{}),
	}
}
