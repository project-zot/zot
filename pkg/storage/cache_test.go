package storage_test

import (
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
)

func TestCache(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		_, err := storage.Create("boltdb", "failTypeAssertion", log)
		So(err, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     "/deadBEEF",
			Name:        "cache_test",
			UseRelPaths: true,
		}, log)
		So(cacheDriver, ShouldBeNil)

		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache_test",
			UseRelPaths: true,
		}, log)
		So(cacheDriver, ShouldNotBeNil)

		So(cacheDriver.UsesRelativePaths(), ShouldBeTrue)

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

		err = cacheDriver.DeleteBlob("bogusKey", "bogusValue")
		So(err, ShouldEqual, errors.ErrCacheMiss)

		err = cacheDriver.DeleteBlob("key", "bogusValue")
		//So(err, ShouldBeNil)
		So(err, ShouldEqual, errors.ErrCacheMiss)

		// try to insert empty path
		err = cacheDriver.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)
	})

	Convey("Invalid cache driver dbtype", t, func() {
		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		cacheDriver, err := storage.Create("sometype", map[string]any{}, log)
		So(err, ShouldEqual, errors.ErrBadConfig)
		So(cacheDriver, ShouldBeNil)
	})
}
