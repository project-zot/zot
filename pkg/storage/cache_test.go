package storage_test

import (
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/database"
)

func TestCache(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		cache, _ := database.Create("boltdb", storage.BoltDBDriverParameters{"/deadBEEF", "cache_test", true}, log)
		So(cache, ShouldBeNil)

		cache, _ = database.Create("boltdb", storage.BoltDBDriverParameters{dir, "cache_test", true}, log)
		So(cache, ShouldNotBeNil)

		name := cache.Name()
		So(name, ShouldEqual, "boltdb")

		val, err := cache.GetBlob("key")
		So(err, ShouldEqual, errors.ErrCacheMiss)
		So(val, ShouldBeEmpty)

		exists := cache.HasBlob("key", "value")
		So(exists, ShouldBeFalse)

		err = cache.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		err = cache.PutBlob("key", "value")
		So(err, ShouldNotBeNil)

		exists = cache.HasBlob("key", "value")
		So(exists, ShouldBeTrue)

		val, err = cache.GetBlob("key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		err = cache.DeleteBlob("bogusKey", "bogusValue")
		So(err, ShouldEqual, errors.ErrCacheMiss)

		err = cache.DeleteBlob("key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cache.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)
	})
}
