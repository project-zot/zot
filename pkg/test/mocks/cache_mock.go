package mocks

import (
	"errors"
	"path"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
)

type CacheMock struct {
	// Returns the human-readable "name" of the driver.
	NameFn func() string

	GetAllBlobsFn func(digest godigest.Digest) ([]string, error)

	// Retrieves the blob matching provided digest.
	GetBlobFn func(digest godigest.Digest) (string, error)

	// Uploads blob to cachedb.
	PutBlobFn func(digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlobFn func(digest godigest.Digest, path string) bool

	// Delete a blob from the cachedb.
	DeleteBlobFn func(digest godigest.Digest, path string) error

	// SetOrigin makes the origin record match path.
	SetOriginFn func(digest godigest.Digest, path string) error

	UsesRelativePathsFn func() bool
}

func (cacheMock CacheMock) UsesRelativePaths() bool {
	if cacheMock.UsesRelativePathsFn != nil {
		return cacheMock.UsesRelativePathsFn()
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

func (cacheMock CacheMock) SetOrigin(digest godigest.Digest, originPath string) error {
	if cacheMock.SetOriginFn != nil {
		return cacheMock.SetOriginFn(digest, originPath)
	}

	// Default mirrors real drivers for tests that stub Get/Put/Delete. An empty
	// successful GetBlob is treated as a miss (zero-value mock returns "", nil).
	cached, err := cacheMock.GetBlob(digest)
	if err != nil {
		if errors.Is(err, zerr.ErrCacheMiss) {
			return cacheMock.PutBlob(digest, originPath)
		}

		return err
	}

	if cached == "" {
		return cacheMock.PutBlob(digest, originPath)
	}

	if path.Clean(cached) == path.Clean(originPath) {
		// Match Redis/Bolt: keep set membership even when the origin already matches.
		return cacheMock.PutBlob(digest, originPath)
	}

	if err := cacheMock.DeleteBlob(digest, cached); err != nil {
		return err
	}

	return cacheMock.PutBlob(digest, originPath)
}

func (cacheMock CacheMock) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	if cacheMock.GetAllBlobsFn != nil {
		return cacheMock.GetAllBlobsFn(digest)
	}

	return []string{}, nil
}
