package cache_test

import (
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
)

func TestBoltDBCache(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		cacheDB, err := storage.Create("boltdb", "failTypeAssertion", log)
		So(cacheDB, ShouldBeNil)
		So(err, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{"/deadBEEF", "cache_test"}, log)
		So(cacheDriver, ShouldBeNil)

		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{dir, "cache_test"}, log)
		So(cacheDriver, ShouldNotBeNil)

		tableName := strings.ReplaceAll(dir, "/", "")

		err = cacheDriver.CreateBucket(tableName)
		So(err, ShouldBeNil)

		name := cacheDriver.Name()
		So(name, ShouldEqual, "boltdb")

		val, err := cacheDriver.GetBlob(tableName, "key")
		So(err, ShouldEqual, errors.ErrCacheMiss)
		So(val, ShouldBeEmpty)

		exists := cacheDriver.HasBlob(tableName, "key", "value")
		So(exists, ShouldBeFalse)

		err = cacheDriver.PutBlob(tableName, "key", "value")
		So(err, ShouldBeNil)

		exists = cacheDriver.HasBlob(tableName, "key", "value")
		So(exists, ShouldBeTrue)

		val, err = cacheDriver.GetBlob(tableName, "key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		err = cacheDriver.DeleteBlob(tableName, "bogusKey", "bogusValue")
		So(err, ShouldEqual, errors.ErrCacheMiss)

		err = cacheDriver.DeleteBlob(tableName, "key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cacheDriver.PutBlob(tableName, "key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)

		_, err = cacheDriver.GetBlob("", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		ok := cacheDriver.HasBlob("", "key", "path")
		So(ok, ShouldBeFalse)

		err = cacheDriver.DeleteBlob("", "", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		err = cacheDriver.PutBlob("", "", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		err = cacheDriver.PutBlob(tableName, "digest", "/path/to/blob")
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob(tableName, "digest", "/path/to/blob2")
		So(err, ShouldBeNil)

		ok = cacheDriver.HasBlob(tableName, "digest", "/path/to/blob")
		So(ok, ShouldBeTrue)

		ok = cacheDriver.HasBlob(tableName, "digest", "/path/to/blob2")
		So(ok, ShouldBeTrue)

		ok = cacheDriver.HasBlob(tableName, "digest", "/path/to/blob3")
		So(ok, ShouldBeFalse)

		err = cacheDriver.Close()
		So(err, ShouldBeNil)
	})
}
