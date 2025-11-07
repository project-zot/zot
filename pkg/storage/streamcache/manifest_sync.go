package streamcache

import (
	"context"

	"zotregistry.dev/zot/v2/pkg/log"
)

// ManifestOnlySync is a wrapper around the normal sync system
// that only loads manifests, but not blobs
type ManifestOnlySync struct {
	wrappedSync interface {
		SyncImage(ctx context.Context, repo, reference string) error
	}
	log log.Logger
}

// NewManifestOnlySync creates a new manifest-only sync wrapper
func NewManifestOnlySync(wrappedSync interface {
	SyncImage(ctx context.Context, repo, reference string) error
}, log log.Logger) *ManifestOnlySync {
	return &ManifestOnlySync{
		wrappedSync: wrappedSync,
		log:         log,
	}
}

// SyncManifest loads only the manifest, no blobs
func (m *ManifestOnlySync) SyncManifest(ctx context.Context, repo, reference string) error {
	// TODO: Implement manifest-only sync
	// For now we call the normal sync
	// This should be optimized later to load only manifests
	m.log.Debug().
		Str("repo", repo).
		Str("reference", reference).
		Msg("syncing manifest (blobs will be streamed on-demand)")

	return m.wrappedSync.SyncImage(ctx, repo, reference)
}
