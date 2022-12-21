package cache

import (
	godigest "github.com/opencontainers/go-digest"
)

type Cache interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(bucket string, digest godigest.Digest) (string, error)

	// Uploads blob to cachedb.
	PutBlob(bucket string, digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlob(bucket string, digest godigest.Digest, path string) bool

	// Delete a blob from the cachedb.
	DeleteBlob(bucket string, digest godigest.Digest, path string) error

	// Create bucket/table for each substore
	CreateBucket(name string) error

	// Release resources
	Close() error
}
