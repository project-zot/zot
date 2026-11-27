package cache_test

import (
	"errors"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

var errBatchAborted = errors.New("batch aborted")

func TestBoltDBWriteBatch(t *testing.T) {
	Convey("A BoltDB batch commits its writes together, or none of them", t, func() {
		dir := t.TempDir()

		driver, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{RootDir: dir, Name: "cache"},
			zlog.NewTestLogger())
		So(err, ShouldBeNil)

		var batcher storageTypes.CacheBatchWriter = driver

		digest := godigest.FromString("batched")
		origin := path.Join(dir, "repo-a", "blobs", "sha256", digest.Encoded())
		other := path.Join(dir, "repo-b", "blobs", "sha256", digest.Encoded())

		Convey("committed once fn returns nil, and seen by the batch's own reads meanwhile", func() {
			So(batcher.WriteBatch(func(batch storageTypes.Cache) error {
				So(batch.PutBlob(digest, origin), ShouldBeNil)
				So(batch.PutBlob(digest, other), ShouldBeNil)
				So(batch.AddReference(digest, other), ShouldBeNil)
				So(batch.RecordGlobal(digest), ShouldBeNil)

				recorded, err := batch.GetBlob(digest)
				So(err, ShouldBeNil)
				So(recorded, ShouldEqual, origin)

				// a nested batch joins this one
				nestedBatcher, ok := batch.(storageTypes.CacheBatchWriter)
				So(ok, ShouldBeTrue)

				return nestedBatcher.WriteBatch(func(nested storageTypes.Cache) error {
					return nested.SetOrigin(digest, other)
				})
			}), ShouldBeNil)

			recorded, err := driver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(recorded, ShouldEqual, other)
			So(driver.HasBlob(digest, origin), ShouldBeTrue)

			refs, err := driver.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldResemble, []string{other})
		})

		Convey("discarded when fn fails", func() {
			err := batcher.WriteBatch(func(batch storageTypes.Cache) error {
				So(batch.PutBlob(digest, origin), ShouldBeNil)
				So(batch.AddReference(digest, origin), ShouldBeNil)

				return errBatchAborted
			})
			So(errors.Is(err, errBatchAborted), ShouldBeTrue)

			_, err = driver.GetBlob(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

			_, err = driver.GetReferences(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})
	})
}
