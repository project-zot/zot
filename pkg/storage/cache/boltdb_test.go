package cache_test

import (
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
)

func TestBoltDBCache(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		_, err := storage.Create("boltdb", "failTypeAssertion", log)
		So(err, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{"/deadBEEF", "cache_test", true}, log)
		So(cacheDriver, ShouldBeNil)

		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{dir, "cache_test", true}, log)
		So(cacheDriver, ShouldNotBeNil)

		name := cacheDriver.Name()
		So(name, ShouldEqual, "boltdb")

		val, err := cacheDriver.GetBlob("key")
		So(err, ShouldEqual, errors.ErrCacheMiss)
		So(val, ShouldBeEmpty)

		exists := cacheDriver.HasBlob("key", "value")
		So(exists, ShouldBeFalse)

		err = cacheDriver.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key", "value")
		So(err, ShouldNotBeNil)

		exists = cacheDriver.HasBlob("key", "value")
		So(exists, ShouldBeTrue)

		val, err = cacheDriver.GetBlob("key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		// DeleteBlob is idempotent: deleting an untracked digest or path is a no-op, not an error.
		err = cacheDriver.DeleteBlob("bogusKey", "bogusValue")
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob("key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cacheDriver.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)

		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{t.TempDir(), "cache_test", false}, log)
		So(cacheDriver, ShouldNotBeNil)

		err = cacheDriver.PutBlob("key1", "originalBlobPath")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key1", "duplicateBlobPath")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key1")
		So(val, ShouldEqual, "originalBlobPath")
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob("key1", "duplicateBlobPath")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key1")
		So(val, ShouldEqual, "originalBlobPath")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key1", "duplicateBlobPath")
		So(err, ShouldBeNil)

		// deleting the origin while a duplicate exists promotes the duplicate to origin
		err = cacheDriver.DeleteBlob("key1", "originalBlobPath")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key1")
		So(val, ShouldEqual, "duplicateBlobPath")
		So(err, ShouldBeNil)

		// no more duplicates left; deleting the (promoted) origin removes the entry
		err = cacheDriver.DeleteBlob("key1", "duplicateBlobPath")
		So(err, ShouldBeNil)

		// should be empty
		val, err = cacheDriver.GetBlob("key1")
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		// try to add three same values
		err = cacheDriver.PutBlob("key2", "duplicate")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key2", "duplicate")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key2", "duplicate")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key2")
		So(val, ShouldEqual, "duplicate")
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob("key2", "duplicate")
		So(err, ShouldBeNil)

		// should be empty
		val, err = cacheDriver.GetBlob("key2")
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		// SetOrigin replaces a stale first-wins origin; PutBlob alone cannot.
		err = cacheDriver.PutBlob("key3", "staleOrigin")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key3", "realOrigin")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key3")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "staleOrigin")

		err = cacheDriver.SetOrigin("key3", "realOrigin")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key3")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "realOrigin")

		err = cacheDriver.SetOrigin("key3", "realOrigin")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key3")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "realOrigin")

		err = cacheDriver.SetOrigin("key4", "")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		// SetOrigin on a relative-path cache: install on miss and keep duplicates.
		relCache, err := storage.Create("boltdb", cache.BoltDBDriverParameters{dir, "set_origin_rel", true}, log)
		So(err, ShouldBeNil)
		So(relCache, ShouldNotBeNil)

		staleAbs := path.Join(dir, "staleAbs")
		realAbs := path.Join(dir, "realAbs")
		otherAbs := path.Join(dir, "otherAbs")

		So(relCache.PutBlob("relKey", staleAbs), ShouldBeNil)
		So(relCache.PutBlob("relKey", realAbs), ShouldBeNil)
		So(relCache.PutBlob("relKey", otherAbs), ShouldBeNil)

		So(relCache.SetOrigin("relKey", realAbs), ShouldBeNil)

		val, err = relCache.GetBlob("relKey")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "realAbs")

		blobs, err := relCache.GetAllBlobs("relKey")
		So(err, ShouldBeNil)
		So(blobs[0], ShouldEqual, "realAbs")
		So(blobs, ShouldContain, "staleAbs")
		So(blobs, ShouldContain, "otherAbs")

		So(relCache.SetOrigin("freshKey", path.Join(dir, "onlyAbs")), ShouldBeNil)

		val, err = relCache.GetBlob("freshKey")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "onlyAbs")

		// Rel failure: reject rather than storing a path GetBlob would mis-join.
		So(relCache.SetOrigin("relFail", "not-under-root/blob"), ShouldNotBeNil)
	})

	Convey("Test cache.GetAllBlos()", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		_, err := storage.Create("boltdb", "failTypeAssertion", log)
		So(err, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{dir, "cache_test", false}, log)
		So(cacheDriver, ShouldNotBeNil)

		err = cacheDriver.PutBlob("digest", "first")
		So(err, ShouldBeNil)

		blobs, err := cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)
		So(blobs, ShouldResemble, []string{"first"})

		err = cacheDriver.PutBlob("digest", "second")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", "third")
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)

		// "first" is the original, "second" and "third" are duplicates
		So(blobs, ShouldResemble, []string{"first", "second", "third"})

		// deleting "first" (the origin) promotes a remaining duplicate to origin
		err = cacheDriver.DeleteBlob("digest", "first")
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)

		So(len(blobs), ShouldEqual, 2)
		So(blobs, ShouldContain, "second")
		So(blobs, ShouldContain, "third")
		So(blobs, ShouldNotContain, "first")

		err = cacheDriver.DeleteBlob("digest", "third")
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)

		So(len(blobs), ShouldEqual, 1)
		So(blobs, ShouldContain, "second")
	})
}

func TestBoltDBDeleteNonOriginDuplicate(t *testing.T) {
	Convey("Deleting a non-origin duplicate must not promote another path to origin", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{dir, "cache_test", false}, log)
		So(cacheDriver, ShouldNotBeNil)

		err := cacheDriver.PutBlob("digest", "zebra")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", "alpha")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", "mango")
		So(err, ShouldBeNil)

		val, err := cacheDriver.GetBlob("digest")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "zebra")

		err = cacheDriver.DeleteBlob("digest", "mango")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("digest")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "zebra")
	})
}
