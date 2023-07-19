package cache

import (
	godigest "github.com/opencontainers/go-digest"
)

type Cache interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(digest godigest.Digest) (string, error)

	// Uploads blob to cachedb.
	PutBlob(digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlob(digest godigest.Digest, path string) bool

	// Delete a blob from the cachedb.
	DeleteBlob(digest godigest.Digest, path string) error

	// UsesRelativePaths returns if cache is storing blobs relative to cache rootDir
	UsesRelativePaths() bool
}
