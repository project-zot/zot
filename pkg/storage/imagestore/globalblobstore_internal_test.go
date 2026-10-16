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

var errInjectedGetAllBlobs = errors.New("injected GetAllBlobs failure")

// globalBlobReferencedInCache is the reclaim check where the platform reports no hardlink count
// (Windows), so the cache decides whether a repo still uses the global blobstore copy.
func TestGlobalBlobReferencedInCache(t *testing.T) {
	Convey("globalBlobReferencedInCache", t, func() {
		rootDir := "/root"
		digest := godigest.FromString("global-blob")
		globalBlobPath := path.Join(rootDir, storageConstants.GlobalBlobsRepo, "blobs", "sha256", digest.Encoded())
		relGlobalBlobPath := path.Join(storageConstants.GlobalBlobsRepo, "blobs", "sha256", digest.Encoded())
		relRepoBlobPath := path.Join("repo", "blobs", "sha256", digest.Encoded())

		storeWithRecords := func(records []string, err error) *ImageStore {
			return &ImageStore{rootDir: rootDir, cache: mocks.CacheMock{
				UsesRelativePathsFn: func() bool { return true },
				GetAllBlobsFn: func(godigest.Digest) ([]string, error) {
					return records, err
				},
			}}
		}

		Convey("without a cache the copy counts as used", func() {
			referenced, err := (&ImageStore{rootDir: rootDir}).globalBlobReferencedInCache(digest, globalBlobPath)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)
		})

		Convey("a repo record means the copy is used", func() {
			imgStore := storeWithRecords([]string{relGlobalBlobPath, relRepoBlobPath}, nil)

			referenced, err := imgStore.globalBlobReferencedInCache(digest, globalBlobPath)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeTrue)
		})

		Convey("only the blobstore's own record means the copy is unused", func() {
			imgStore := storeWithRecords([]string{relGlobalBlobPath}, nil)

			referenced, err := imgStore.globalBlobReferencedInCache(digest, globalBlobPath)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("no record at all means the copy is unused", func() {
			imgStore := storeWithRecords(nil, zerr.ErrCacheMiss)

			referenced, err := imgStore.globalBlobReferencedInCache(digest, globalBlobPath)
			So(err, ShouldBeNil)
			So(referenced, ShouldBeFalse)
		})

		Convey("other cache errors propagate", func() {
			imgStore := storeWithRecords(nil, errInjectedGetAllBlobs)

			_, err := imgStore.globalBlobReferencedInCache(digest, globalBlobPath)
			So(errors.Is(err, errInjectedGetAllBlobs), ShouldBeTrue)
		})
	})
}
