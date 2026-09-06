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
	// FetchManifestForStream fetches repo:reference directly from upstream and prepares it for
	// streaming, returning the manifest immediately while the full image syncs in the background.
	FetchManifestForStream(ctx context.Context, repo, reference string) (manifest.Manifest, error)
	// StreamManager returns the manager tracking active blob streams, or nil when streaming is
	// not configured for any registry.
	StreamManager() StreamManager
	// IsStreamingEnabledForRepo reports whether any on-demand service streams blobs for repo.
	IsStreamingEnabledForRepo(repo string) bool
}

// StreamManager tracks blobs that are being downloaded from upstream and streamed to clients
// concurrently with that download, plus the manifests that are staged for streaming.
type StreamManager interface {
	// ConnectClient attaches a client to the active stream for blobDigest, returning a copier
	// that forwards bytes already on disk and new bytes as they arrive.
	ConnectClient(blobDigest string, writer io.Writer) (BlobCopier, error)
	// StreamingBlobReader is invoked by regclient as each blob is read from upstream; it wraps
	// the reader so bytes are simultaneously written to disk and made available to clients.
	StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error)
	// StoreImageForStreaming registers a manifest (and, for multi-arch images, its child
	// manifests) as streamable, pre-creating active streams for the manifest, config, and layers.
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest) error
	// StreamingImageManifest returns the manifest staged for repo:reference, if any.
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	// RemoveStreamingImage purges repo:reference and its blobs from the stream cache once the
	// background sync into real storage has finished.
	RemoveStreamingImage(repo, reference string)
	// CachedBlobInfo returns the size and media type of a blob known to the stream cache.
	CachedBlobInfo(blobDigest string) (size int64, mediaType string, err error)
}

// BlobCopier copies a single streamed blob to one connected client.
type BlobCopier interface {
	// Copy streams the blob to the client, returning once the blob is fully copied or an error
	// (including an upstream download failure) ends the stream.
	Copy() error
	// Descriptor returns the descriptor of the blob being streamed.
	Descriptor() descriptor.Descriptor
}

// StreamableManifest holds a manifest staged for streaming, plus (for a multi-arch image) the
// per-platform manifests nested inside it, since each of those must be pre-staged individually.
type StreamableManifest struct {
	referenceManifest manifest.Manifest
	subManifests      []manifest.Manifest
}

// NewStreamableManifest wraps a manifest (and, for a multi-arch image, its child manifests) for
// registration with a StreamManager.
func NewStreamableManifest(mainManifest manifest.Manifest, subManifests []manifest.Manifest) *StreamableManifest {
	return &StreamableManifest{
		referenceManifest: mainManifest,
		subManifests:      subManifests,
	}
}
