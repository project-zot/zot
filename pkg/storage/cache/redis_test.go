package cache_test

import (
	"path"
	"testing"

	"github.com/alicebob/miniredis/v2"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
)

func TestRedisCache(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		_, err := storage.Create("redis", "failTypeAssertion", log)
		So(err, ShouldNotBeNil)

		cacheDriver, _ := storage.Create("redis",
			cache.RedisDriverParameters{dir, "redis://" + miniRedis.Addr(), true}, log)
		So(cacheDriver, ShouldNotBeNil)

		name := cacheDriver.Name()
		So(name, ShouldEqual, "redis")

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
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cacheDriver.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)

		cacheDriver, _ = storage.Create("redis",
			cache.RedisDriverParameters{t.TempDir(), "redis://" + miniRedis.Addr() + "/5", false}, log)
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

		err = cacheDriver.DeleteBlob("key1", "originalBlobPath")
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob("key1")
		So(val, ShouldEqual, "duplicateBlobPath")
		So(err, ShouldBeNil)

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
	})
}
