package cache

import (
	"io"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

func TestBoltBlobRefIndexErrors(t *testing.T) {
	digest := godigest.FromString("bolt-blob-refs")
	claim := storageTypes.ReclaimClaim{Digest: digest, ID: "claim"}

	newDriver := func() *BoltDBDriver {
		boltDB, err := bbolt.Open(filepath.Join(t.TempDir(), "bolt.db"), 0o600, bbolt.DefaultOptions)
		So(err, ShouldBeNil)

		return &BoltDBDriver{
			db:         boltDB,
			log:        log.NewLoggerWithWriter("debug", io.Discard),
			claimLease: constants.DefaultReclaimClaimLease,
		}
	}

	Convey("Without the blob refs root bucket every operation fails", t, func() {
		driver := newDriver()

		So(driver.AddReference(digest, "/repo/blob"), ShouldNotBeNil)

		_, err := driver.RemoveReference(digest, "/repo/blob")
		So(err, ShouldNotBeNil)

		_, err = driver.GetReferences(digest)
		So(err, ShouldNotBeNil)

		So(driver.RecordGlobal(digest), ShouldNotBeNil)

		_, err = driver.ClaimReclaim(digest)
		So(err, ShouldNotBeNil)

		So(driver.FinishReclaim(claim), ShouldNotBeNil)
		So(driver.AbandonReclaim(claim), ShouldNotBeNil)
	})

	Convey("A claim that cannot be decoded fails the operations that read it", t, func() {
		driver := newDriver()

		So(driver.db.Update(func(tx *bbolt.Tx) error {
			root, err := tx.CreateBucketIfNotExists([]byte(constants.BlobRefsBucket))
			if err != nil {
				return err
			}

			record, err := root.CreateBucket([]byte(digest.String()))
			if err != nil {
				return err
			}

			if err := record.Put([]byte(boltGlobalKey), []byte("1")); err != nil {
				return err
			}

			return record.Put([]byte(boltClaimKey), []byte("not json"))
		}), ShouldBeNil)

		So(driver.AddReference(digest, "/repo/blob"), ShouldNotBeNil)

		_, err := driver.ClaimReclaim(digest)
		So(err, ShouldNotBeNil)

		So(driver.FinishReclaim(claim), ShouldNotBeNil)
		So(driver.AbandonReclaim(claim), ShouldNotBeNil)
	})
}
