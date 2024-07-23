package cache

import (
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.dev/zot/pkg/storage/constants"
)

func TestBoltDriverErrors(t *testing.T) {
	Convey("Make a new cache", t, func() {
		tmpDir := t.TempDir()

		boltDB, err := bbolt.Open(filepath.Join(tmpDir, "bolt.db"), 0o644, bbolt.DefaultOptions)
		So(err, ShouldBeNil)

		driver := BoltDBDriver{
			db: boltDB,
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
