package streamcache

import (
	"context"

	"zotregistry.dev/zot/v2/pkg/log"
)

// ManifestOnlySync ist ein Wrapper um das normale Sync-System
// der nur Manifests lädt, aber keine Blobs
type ManifestOnlySync struct {
	wrappedSync interface {
		SyncImage(ctx context.Context, repo, reference string) error
	}
	log log.Logger
}

// NewManifestOnlySync erstellt einen neuen Manifest-Only Sync Wrapper
func NewManifestOnlySync(wrappedSync interface {
	SyncImage(ctx context.Context, repo, reference string) error
}, log log.Logger) *ManifestOnlySync {
	return &ManifestOnlySync{
		wrappedSync: wrappedSync,
		log:         log,
	}
}

// SyncManifest lädt nur das Manifest, keine Blobs
func (m *ManifestOnlySync) SyncManifest(ctx context.Context, repo, reference string) error {
	// TODO: Implementiere Manifest-only Sync
	// Für jetzt rufen wir das normale Sync auf
	// Dies sollte später optimiert werden, um nur Manifests zu laden
	m.log.Debug().
		Str("repo", repo).
		Str("reference", reference).
		Msg("syncing manifest (blobs will be streamed on-demand)")

	return m.wrappedSync.SyncImage(ctx, repo, reference)
}
