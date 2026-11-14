package types

import (
	godigest "github.com/opencontainers/go-digest"
)

type Cache interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(digest godigest.Digest) (string, error)

	// Retrieves all blobs matching provided digest.
	GetAllBlobs(digest godigest.Digest) ([]string, error)

	// Uploads blob to cachedb.
	PutBlob(digest godigest.Digest, path string) error

	// PutDuplicate records path as another copy of digest. Unlike PutBlob, it never creates the
	// record or an origin: it returns a cache-miss error when digest has no origin, so a copy
	// that holds no content cannot become the origin because the record was removed meanwhile.
	PutDuplicate(digest godigest.Digest, path string) error

	// ReplaceBlob makes newPath the origin of digest if oldPath still is, and newPath is one of
	// the tracked paths. It returns ErrCacheConflict otherwise. oldPath stays tracked.
	ReplaceBlob(digest godigest.Digest, oldPath, newPath string) error

	// Check if blob exists in cachedb.
	HasBlob(digest godigest.Digest, path string) bool

	// DeleteBlob removes path from the paths tracked for digest. It is idempotent: it returns
	// nil, not a cache-miss error, when the digest or the path is already untracked.
	DeleteBlob(digest godigest.Digest, path string) error

	// SetOrigin makes the origin record for digest match path. Unlike PutBlob, which
	// never replaces an existing origin, SetOrigin overwrites the origin while keeping
	// the duplicate set.
	SetOrigin(digest godigest.Digest, path string) error

	// UsesRelativePaths returns if cache is storing blobs relative to cache rootDir
	UsesRelativePaths() bool
}
