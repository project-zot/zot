//nolint:testpackage // Tests exercise the unexported isDigestReferencedAcrossRepos directly.
package imagestore

import (
	"errors"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// isDigestReferencedAcrossRepos is the function whose regression (a fallback to
// manifest-only scanning) caused TestS3PullRange's CI failure - the bug that started
// this session's storage work. It had zero direct unit coverage: every existing test
// only reached it indirectly through a real S3/GCS backend's deleteBlob/CleanupRepo
// path. These tests exercise its actual logic (path normalization, the _blobstore
// exclusion, and blobRefsForDigest's cache-miss/error/fallback handling) directly
// against a mock cache, independent of any real backend.

var errInjectedCacheFailure = errors.New("injected cache failure")

func TestIsDigestReferencedAcrossRepos(t *testing.T) {
	const rootDir = "/rootDir"

	digest := godigest.FromString("test-digest")

	t.Run("cache miss returns not referenced, no error", func(t *testing.T) {
		imgStore := &ImageStore{
			rootDir: rootDir,
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return nil, zerr.ErrCacheMiss
				},
			},
		}

		referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if referenced {
			t.Fatalf("expected not referenced")
		}
	})

	t.Run("non-cache-miss error propagates", func(t *testing.T) {
		imgStore := &ImageStore{
			rootDir: rootDir,
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return nil, errInjectedCacheFailure
				},
			},
		}

		referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
		if !errors.Is(err, errInjectedCacheFailure) {
			t.Fatalf("expected injected error, got %v", err)
		}

		if referenced {
			t.Fatalf("expected not referenced on error")
		}
	})

	t.Run("only _blobstore paths referenced is not cross-repo referenced", func(t *testing.T) {
		globalBlobPath := path.Join(rootDir, storageConstants.GlobalBlobsRepo, "blobs/sha256", digest.Encoded())

		imgStore := &ImageStore{
			rootDir: rootDir,
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return []string{globalBlobPath}, nil
				},
			},
		}

		referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if referenced {
			t.Fatalf("expected not referenced when only _blobstore holds the digest")
		}
	})

	t.Run("a real repo path alongside the _blobstore copy is cross-repo referenced", func(t *testing.T) {
		globalBlobPath := path.Join(rootDir, storageConstants.GlobalBlobsRepo, "blobs/sha256", digest.Encoded())
		repoBlobPath := path.Join(rootDir, "myrepo/blobs/sha256", digest.Encoded())

		imgStore := &ImageStore{
			rootDir: rootDir,
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return []string{globalBlobPath, repoBlobPath}, nil
				},
			},
		}

		referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if !referenced {
			t.Fatalf("expected referenced when a real repo also holds the digest")
		}
	})

	t.Run("relative and dot-prefixed paths normalize the same as absolute ones", func(t *testing.T) {
		repoBlobPath := "./myrepo/blobs/sha256/" + digest.Encoded()

		imgStore := &ImageStore{
			rootDir: rootDir,
			cache: mocks.CacheMock{
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return []string{repoBlobPath}, nil
				},
			},
		}

		referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if !referenced {
			t.Fatalf("expected referenced for a dot-relative repo path")
		}
	})
}
