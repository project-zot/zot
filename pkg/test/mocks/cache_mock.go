package mocks

import godigest "github.com/opencontainers/go-digest"

type CacheMock struct {
	// Returns the human-readable "name" of the driver.
	NameFn func() string

	// Retrieves the blob matching provided digest.
	GetBlobFn func(digest godigest.Digest) (string, error)

	// Uploads blob to cachedb.
	PutBlobFn func(digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlobFn func(digest godigest.Digest, path string) bool

	// Delete a blob from the cachedb.
	DeleteBlobFn func(digest godigest.Digest, path string) error

	UsesRelativePathsFn func() bool
}

func (cacheMock CacheMock) UsesRelativePaths() bool {
	if cacheMock.UsesRelativePathsFn != nil {
		return cacheMock.UsesRelativePaths()
	}

	return false
}

func (cacheMock CacheMock) Name() string {
	if cacheMock.NameFn != nil {
		return cacheMock.NameFn()
	}

	return "mock"
}

func (cacheMock CacheMock) GetBlob(digest godigest.Digest) (string, error) {
	if cacheMock.GetBlobFn != nil {
		return cacheMock.GetBlobFn(digest)
	}

	return "", nil
}

func (cacheMock CacheMock) PutBlob(digest godigest.Digest, path string) error {
	if cacheMock.PutBlobFn != nil {
		return cacheMock.PutBlobFn(digest, path)
	}

	return nil
}

func (cacheMock CacheMock) HasBlob(digest godigest.Digest, path string) bool {
	if cacheMock.HasBlobFn != nil {
		return cacheMock.HasBlobFn(digest, path)
	}

	return true
}

func (cacheMock CacheMock) DeleteBlob(digest godigest.Digest, path string) error {
	if cacheMock.DeleteBlobFn != nil {
		return cacheMock.DeleteBlobFn(digest, path)
	}

	return nil
}
