package cache

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
)

func TestBoltDriverErrors(t *testing.T) {
	Convey("Make a new cache", t, func() {
		tmpDir := t.TempDir()

		boltDB, err := bbolt.Open(filepath.Join(tmpDir, "bolt.db"), 0o644, bbolt.DefaultOptions)
		So(err, ShouldBeNil)

		driver := BoltDBDriver{
			db:  boltDB,
			log: log.NewLoggerWithWriter("debug", io.Discard),
		}

		Convey("Empty boltdb", func() {
			// bucket not found
			err = driver.PutBlob(digest.FromString("s"), "path")
			So(err, ShouldNotBeNil)

			_, err = driver.GetBlob(digest.FromString("s"))
			So(err, ShouldNotBeNil)

			has := driver.HasBlob(digest.FromString("s"), "blob")
			So(has, ShouldBeFalse)

			err = driver.DeleteBlob(digest.FromString("s"), "blob")
			So(err, ShouldNotBeNil)
		})

		Convey("cache miss", func() {
			goodDigest := digest.FromString("s")

			err := driver.db.Update(func(tx *bbolt.Tx) error {
				buck, err := tx.CreateBucketIfNotExists([]byte(constants.BlobsCache))
				So(err, ShouldBeNil)

				_, err = buck.CreateBucket([]byte(goodDigest))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			// digest bucket not found
			err = driver.DeleteBlob(digest.FromString("bad-digest"), "path")
			So(err, ShouldNotBeNil)

			// duplicate bucket not exist
			err = driver.DeleteBlob(goodDigest, "path")
			So(err, ShouldNotBeNil)
		})
	})
}

// blobRefIndexer mirrors imagestore's unexported interface of the same name, duplicated
// here so this package can assert BoltDBDriver satisfies it without a cache<->imagestore
// import cycle.
type blobRefIndexer interface {
	PutBlobRef(digest digest.Digest, path string) error
	DeleteBlobRef(digest digest.Digest, path string) error
	GetBlobRefs(digest digest.Digest) ([]string, error)
	GetAllBlobRefs() (map[digest.Digest][]string, error)
}

var _ blobRefIndexer = (*BoltDBDriver)(nil)

// PutBlobRef/DeleteBlobRef are no-ops here since PutBlob/DeleteBlob already maintain the
// BlobRefs bucket directly; this exercises the GetBlobRefs read path.
func TestBoltDBGetBlobRefs(t *testing.T) {
	Convey("GetBlobRefs", t, func() {
		tmpDir := t.TempDir()

		cacheDriver, err := NewBoltDBCache(BoltDBDriverParameters{
			RootDir: tmpDir,
			Name:    "cache",
		}, log.NewLoggerWithWriter("debug", io.Discard))
		So(err, ShouldBeNil)

		Convey("UsesRelativePaths reflects the configured parameter", func() {
			So(cacheDriver.UsesRelativePaths(), ShouldBeFalse)

			relPathDriver, err := NewBoltDBCache(BoltDBDriverParameters{
				RootDir:     t.TempDir(),
				Name:        "cache",
				UseRelPaths: true,
			}, log.NewLoggerWithWriter("debug", io.Discard))
			So(err, ShouldBeNil)
			So(relPathDriver.UsesRelativePaths(), ShouldBeTrue)
		})

		Convey("cache miss for a digest with no refs", func() {
			refs, err := cacheDriver.GetBlobRefs(digest.FromString("missing"))
			So(err, ShouldEqual, zerr.ErrCacheMiss)
			So(refs, ShouldBeEmpty)
		})

		Convey("PutBlobRef/DeleteBlobRef are no-ops that don't disturb BlobRefs", func() {
			testDigest := digest.FromString("d")

			err := cacheDriver.PutBlob(testDigest, "/repo1/blob")
			So(err, ShouldBeNil)

			So(cacheDriver.PutBlobRef(testDigest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.DeleteBlobRef(testDigest, "/repo1/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(testDigest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo1/blob")
		})

		Convey("PutBlob populates the BlobRefs bucket, readable via GetBlobRefs", func() {
			testDigest := digest.FromString("d")

			err := cacheDriver.PutBlob(testDigest, "/repo1/blob")
			So(err, ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(testDigest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo1/blob")

			allRefs, err := cacheDriver.GetAllBlobRefs()
			So(err, ShouldBeNil)
			So(allRefs[testDigest], ShouldContain, "/repo1/blob")

			Convey("a second PutBlob for the same digest adds another ref", func() {
				err := cacheDriver.PutBlob(testDigest, "/repo2/blob")
				So(err, ShouldBeNil)

				refs, err := cacheDriver.GetBlobRefs(testDigest)
				So(err, ShouldBeNil)
				So(refs, ShouldContain, "/repo1/blob")
				So(refs, ShouldContain, "/repo2/blob")
			})

			Convey("DeleteBlob removes the corresponding ref", func() {
				err := cacheDriver.DeleteBlob(testDigest, "/repo1/blob")
				So(err, ShouldBeNil)

				refs, err := cacheDriver.GetBlobRefs(testDigest)
				So(err, ShouldEqual, zerr.ErrCacheMiss)
				So(refs, ShouldBeEmpty)
			})

			// The BlobRefs bucket is a plain set, so the first-inserted ref carries no
			// special status: deleting it must drop it and leave the other repo's ref,
			// matching what redis and dynamodb achieve by promoting a duplicate to origin.
			Convey("deleting the first repo's ref leaves only the second repo's ref", func() {
				err := cacheDriver.PutBlob(testDigest, "/repo2/blob")
				So(err, ShouldBeNil)

				err = cacheDriver.DeleteBlob(testDigest, "/repo1/blob")
				So(err, ShouldBeNil)

				refs, err := cacheDriver.GetBlobRefs(testDigest)
				So(err, ShouldBeNil)
				So(refs, ShouldContain, "/repo2/blob")
				So(refs, ShouldNotContain, "/repo1/blob")
				So(len(refs), ShouldEqual, 1)

				allRefs, err := cacheDriver.GetAllBlobRefs()
				So(err, ShouldBeNil)
				So(allRefs[testDigest], ShouldContain, "/repo2/blob")
				So(allRefs[testDigest], ShouldNotContain, "/repo1/blob")
			})
		})

		Convey("blob refs root bucket missing surfaces ErrCacheRootBucket", func() {
			err := cacheDriver.db.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(constants.BlobRefs))
			})
			So(err, ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest.FromString("d"))
			So(err, ShouldEqual, zerr.ErrCacheRootBucket)
			So(refs, ShouldBeEmpty)
		})

		Convey("PutBlob surfaces ErrCacheRootBucket when the blob refs bucket is missing", func() {
			err := cacheDriver.db.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(constants.BlobRefs))
			})
			So(err, ShouldBeNil)

			err = cacheDriver.PutBlob(digest.FromString("d"), "/repo1/blob")
			So(err, ShouldEqual, zerr.ErrCacheRootBucket)
		})

		Convey("DeleteBlob propagates deleteBlobRef's ErrCacheRootBucket instead of swallowing it", func() {
			testDigest := digest.FromString("d")

			err := cacheDriver.PutBlob(testDigest, "/repo1/blob")
			So(err, ShouldBeNil)

			err = cacheDriver.db.Update(func(tx *bbolt.Tx) error {
				return tx.DeleteBucket([]byte(constants.BlobRefs))
			})
			So(err, ShouldBeNil)

			// the BlobsCache-side delete succeeds; only the BlobRefs bucket is missing
			err = cacheDriver.DeleteBlob(testDigest, "/repo1/blob")
			So(err, ShouldEqual, zerr.ErrCacheRootBucket)
		})
	})
}
