package types

import (
	"context"

	godigest "github.com/opencontainers/go-digest"
)

// RepoLock is a held repository lock. Release frees it. StillHeld revalidates
// the fence against the store and extends the lock on success, so a writer can
// check immediately before committing that it still holds exclusive access —
// the lock is TTL-based mutual exclusion, and this check is what keeps a holder
// that lost the lock from clobbering another writer's commit.
type RepoLock interface {
	Release()
	StillHeld(ctx context.Context) bool
}

// RepoLocker serializes writes to one repository's index across processes.
// The image store's own mutex covers a single process only, so instances
// sharing a storage backend can otherwise overwrite each other's tags.
type RepoLocker interface {
	// LockRepo blocks until it holds the lock for repo or ctx is done.
	// It errors rather than proceeding unlocked.
	LockRepo(ctx context.Context, repo string) (RepoLock, error)
}

type Cache interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(digest godigest.Digest) (string, error)

	// Retrieves all blobs matching provided digest.
	GetAllBlobs(digest godigest.Digest) ([]string, error)

	// Uploads blob to cachedb.
	PutBlob(digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlob(digest godigest.Digest, path string) bool

	// Delete a blob from the cachedb.
	DeleteBlob(digest godigest.Digest, path string) error

	// UsesRelativePaths returns if cache is storing blobs relative to cache rootDir
	UsesRelativePaths() bool
}
