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

			err = driver.SetOrigin(digest.FromString("s"), "path")
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

			// digest bucket not found: nothing is tracked, so there is nothing to delete
			err = driver.DeleteBlob(digest.FromString("bad-digest"), "path")
			So(err, ShouldBeNil)

			// duplicate bucket not exist: same, the delete is a no-op
			err = driver.DeleteBlob(goodDigest, "path")
			So(err, ShouldBeNil)
		})
	})
}

func TestBoltDriverPutDuplicateAndReplaceBlobErrors(t *testing.T) {
	Convey("With a database the driver did not set up", t, func() {
		tmpDir := t.TempDir()

		boltDB, err := bbolt.Open(filepath.Join(tmpDir, "bolt.db"), 0o644, bbolt.DefaultOptions)
		So(err, ShouldBeNil)

		driver := BoltDBDriver{
			db:  boltDB,
			log: log.NewLoggerWithWriter("debug", io.Discard),
		}

		dgst := digest.FromString("s")

		Convey("the missing root bucket is reported", func() {
			So(driver.PutDuplicate(dgst, "path"), ShouldEqual, zerr.ErrCacheRootBucket)
			So(driver.ReplaceBlob(dgst, "old", "new"), ShouldEqual, zerr.ErrCacheRootBucket)
		})

		Convey("records whose nested keys are not what the driver wrote are reported", func() {
			// origin holds the key "a" and a nested bucket "b"; duplicates tracks "a" and "b", and is
			// itself a plain value under another digest
			other := digest.FromString("other")

			err := driver.db.Update(func(tx *bbolt.Tx) error {
				root, err := tx.CreateBucketIfNotExists([]byte(constants.BlobsCache))
				So(err, ShouldBeNil)

				bucket, err := root.CreateBucket([]byte(dgst.String()))
				So(err, ShouldBeNil)

				origin, err := bucket.CreateBucket([]byte(constants.OriginalBucket))
				So(err, ShouldBeNil)
				So(origin.Put([]byte("a"), nil), ShouldBeNil)

				_, err = origin.CreateBucket([]byte("b"))
				So(err, ShouldBeNil)

				deduped, err := bucket.CreateBucket([]byte(constants.DuplicatesBucket))
				So(err, ShouldBeNil)
				So(deduped.Put([]byte("a"), nil), ShouldBeNil)
				So(deduped.Put([]byte("b"), nil), ShouldBeNil)

				otherBucket, err := root.CreateBucket([]byte(other.String()))
				So(err, ShouldBeNil)

				otherOrigin, err := otherBucket.CreateBucket([]byte(constants.OriginalBucket))
				So(err, ShouldBeNil)
				So(otherOrigin.Put([]byte("origin"), nil), ShouldBeNil)
				So(otherBucket.Put([]byte(constants.DuplicatesBucket), []byte("not a bucket")), ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			// the origin "a" cannot be replaced by "b", which is a bucket, not a key
			So(driver.ReplaceBlob(dgst, "a", "b"), ShouldEqual, bbolt.ErrIncompatibleValue)

			// nor can a nested bucket be deleted as if it were the origin key
			err = driver.db.Update(func(tx *bbolt.Tx) error {
				origin := tx.Bucket([]byte(constants.BlobsCache)).Bucket([]byte(dgst.String())).
					Bucket([]byte(constants.OriginalBucket))

				return origin.Delete([]byte("a"))
			})
			So(err, ShouldBeNil)

			So(driver.ReplaceBlob(dgst, "b", "a"), ShouldEqual, bbolt.ErrIncompatibleValue)

			// a duplicates entry that is not a bucket cannot take a path
			So(driver.PutDuplicate(other, "copy"), ShouldEqual, bbolt.ErrIncompatibleValue)
		})
	})
}
