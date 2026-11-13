package storage

import (
	"context"

	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type Lint interface {
	Lint(ctx context.Context, repo string, manifestDigest godigest.Digest,
		imageStore storageTypes.ImageStore) (bool, error)
}

type syncedContentKey struct{}

// WithSyncedContent marks ctx as carrying a write of content that the sync extension copied from an
// upstream registry, so that a linter can tell it apart from content pushed by a client.
func WithSyncedContent(ctx context.Context) context.Context {
	return context.WithValue(ctx, syncedContentKey{}, true)
}

// IsSyncedContent reports whether ctx was marked by WithSyncedContent.
func IsSyncedContent(ctx context.Context) bool {
	if ctx == nil {
		return false
	}

	synced, _ := ctx.Value(syncedContentKey{}).(bool)

	return synced
}
