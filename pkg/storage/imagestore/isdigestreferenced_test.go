//nolint:testpackage // Tests exercise the unexported isDigestReferencedAcrossRepos directly.
package imagestore

import (
	"errors"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// isDigestReferencedAcrossRepos previously had no direct unit coverage - existing
// tests only reached it indirectly through a real S3/GCS backend's deleteBlob/
// CleanupRepo path. These tests exercise its logic directly (path normalization,
// the _blobstore exclusion, and cache-miss/error/fallback handling) against a
// mock cache, independent of any real backend.

var errInjectedCacheFailure = errors.New("injected cache failure")

func TestIsDigestReferencedAcrossRepos(t *testing.T) {
	const rootDir = "/rootDir"

	digest := godigest.FromString("test-digest")

	Convey("isDigestReferencedAcrossRepos", t, func() {
		Convey("cache miss returns not referenced, no error", func() {
			imgStore := &ImageStore{
				rootDir: rootDir,
				cache: mocks.CacheMock{
					GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
						return nil, zerr.ErrCacheMiss
					},
				},
			}

			referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("non-cache-miss error propagates", func() {
			imgStore := &ImageStore{
				rootDir: rootDir,
				cache: mocks.CacheMock{
					GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
						return nil, errInjectedCacheFailure
					},
				},
			}

			referenced, err := imgStore.isDigestReferencedAcrossRepos(digest)
			So(errors.Is(err, errInjectedCacheFailure), ShouldBeTrue)
			So(referenced, ShouldBeFalse)
		})

		Convey("only _blobstore paths referenced is not cross-repo referenced", func() {
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
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("a real repo path alongside the _blobstore copy is cross-repo referenced", func() {
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
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)
		})

		Convey("relative and dot-prefixed paths normalize the same as absolute ones", func() {
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
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)
		})
	})
}
