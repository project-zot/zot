package cache_test

import (
	"errors"
	"path"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	"zotregistry.dev/zot/pkg/storage/constants"
	test "zotregistry.dev/zot/pkg/test/common"
)

var ErrTestError = errors.New("TestError")

func TestRedisCache(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		cacheDriver, err := storage.Create("redis", "failTypeAssertion", log)
		So(cacheDriver, ShouldBeNil)
		So(err, ShouldNotBeNil)

		cacheDriver, err = storage.Create("redis",
			cache.RedisDriverParameters{dir, "failBadAddress", true}, log)
		So(cacheDriver, ShouldBeNil)
		So(err, ShouldNotBeNil)

		cacheDriver, err = storage.Create("redis",
			cache.RedisDriverParameters{dir, "redis://" + miniRedis.Addr(), true}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		name := cacheDriver.Name()
		So(name, ShouldEqual, "redis")

		val, err := cacheDriver.GetBlob("key")
		So(err, ShouldEqual, zerr.ErrCacheMiss)
		So(val, ShouldBeEmpty)

		exists := cacheDriver.HasBlob("key", path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		exists = cacheDriver.HasBlob("key", "value")
		So(exists, ShouldBeFalse)

		err = cacheDriver.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("key", "value")
		So(err, ShouldNotBeNil)

		exists = cacheDriver.HasBlob("key", path.Join(dir, "value"))
		So(exists, ShouldBeTrue)

		val, err = cacheDriver.GetBlob("key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		err = cacheDriver.DeleteBlob("bogusKey", "bogusValue")
		So(err, ShouldEqual, zerr.ErrCacheMiss)

		err = cacheDriver.DeleteBlob("key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cacheDriver.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrEmptyValue)

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

	Convey("Test cache.GetAllBlos()", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{dir, "redis://" + miniRedis.Addr(), true}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		name := cacheDriver.Name()
		So(name, ShouldEqual, "redis")

		blobs, err := cacheDriver.GetAllBlobs("digest")
		So(err, ShouldEqual, zerr.ErrCacheMiss)
		So(blobs, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", path.Join(dir, "first"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", path.Join(dir, "second"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob("digest", path.Join(dir, "third"))
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)

		So(blobs, ShouldResemble, []string{"first", "second", "third"})

		err = cacheDriver.DeleteBlob("digest", path.Join(dir, "first"))
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)
		So(len(blobs), ShouldEqual, 2)
		So(blobs, ShouldContain, "second")
		So(blobs, ShouldContain, "third")

		err = cacheDriver.DeleteBlob("digest", path.Join(dir, "third"))
		So(err, ShouldBeNil)

		blobs, err = cacheDriver.GetAllBlobs("digest")
		So(err, ShouldBeNil)

		So(blobs, ShouldResemble, []string{"second"})
	})
}

func TestRedisCacheError(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()
		redisURL := "redis://127.0.0.1:" + test.GetFreePort()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		// redis server is not running
		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{dir, redisURL, true}, log)
		So(err, ShouldNotBeNil)
		So(cacheDriver, ShouldBeNil)
	})

	Convey("Redis unreachable", t, func() {
		miniRedis := miniredis.RunT(t)
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		redisURL := "redis://127.0.0.1:" + test.GetFreePort() // must not match miniRedis.Addr()
		connOpts, _ := redis.ParseURL(redisURL)
		cacheDB := redis.NewClient(connOpts)

		cacheDriver, err := cache.NewRedisCache(
			cache.RedisDriverParameters{dir, "redis://" + miniRedis.Addr(), false}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// replace the working driver with the broken one
		cacheDriver.SetClient(cacheDB)

		err = cacheDriver.PutBlob("key", "val")
		So(err, ShouldNotBeNil)

		found := cacheDriver.HasBlob("key", "val")
		So(found, ShouldEqual, false)

		_, err = cacheDriver.GetBlob("key")
		So(err, ShouldNotBeNil)

		_, err = cacheDriver.GetAllBlobs("key")
		So(err, ShouldNotBeNil)

		err = cacheDriver.DeleteBlob("key", "val")
		So(err, ShouldNotBeNil)
	})
}

func TestRedisMocked(t *testing.T) {
	Convey("Redis tests using mocks", t, func() {
		miniRedis := miniredis.RunT(t)
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		cacheDriver, err := cache.NewRedisCache(
			cache.RedisDriverParameters{dir, "redis://" + miniRedis.Addr(), true}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("PutBlob HExists error", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetErr(ErrTestError)

			err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
			So(err, ShouldEqual, ErrTestError)
		})

		Convey("PutBlob HSet error", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val").
				SetErr(ErrTestError)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
			So(err, ShouldEqual, ErrTestError)
		})

		Convey("PutBlob SAdd error", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val").
				SetVal(1)
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetErr(ErrTestError)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
			So(err, ShouldEqual, ErrTestError)
		})

		Convey("PutBlob succeeds original bucket is created", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val").
				SetVal(1)
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetVal(1)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
			So(err, ShouldBeNil)
		})

		Convey("PutBlob succeeds original bucket is reused", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(true)
			mock.ExpectTxPipeline()
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetVal(1)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
			So(err, ShouldBeNil)
		})

		Convey("SMembers error in GetAllBlobs", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal("val")
			mock.ExpectSMembers("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
				SetErr(ErrTestError)

			_, err = cacheDriver.GetAllBlobs("key")
			So(err, ShouldEqual, ErrTestError)
		})

		Convey("GetAllBlobs succeeds", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val1").
				SetVal(1)
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
				SetVal(1)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val1"))
			So(err, ShouldBeNil)

			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
				SetVal(1)
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val2").
				SetVal(1)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
			So(err, ShouldBeNil)

			mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal("val1")
			mock.ExpectSMembers("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
				SetVal([]string{"val1", "val2"})

			allBlobs, err := cacheDriver.GetAllBlobs("key")
			So(err, ShouldBeNil)
			So(allBlobs, ShouldResemble, []string{"val1", "val2"})
		})

		Convey("HasBlob HExists returns error", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectSIsMember("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetVal(true)
			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetErr(ErrTestError)

			ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
			So(ok, ShouldBeFalse)
		})

		Convey("HasBlob SIsMember returns error", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectSIsMember("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetErr(ErrTestError)

			ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
			So(ok, ShouldBeFalse)
		})

		Convey("HasBlob HExists returns false", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			mock.ExpectSIsMember("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val").
				SetVal(true)
			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)

			ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
			So(ok, ShouldBeFalse)
		})

		Convey("DeleteBlob tests", func() {
			// initialize mock client
			cacheDB, mock := redismock.NewClientMock()

			// replace the working driver with the mock
			cacheDriver.SetClient(cacheDB)

			// Create entry for 1st path
			mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
				SetVal(false)
			mock.ExpectTxPipeline()
			mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val1").
				SetVal(1)
			mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
				SetVal(1)
			mock.ExpectTxPipelineExec()

			err = cacheDriver.PutBlob("key", path.Join(dir, "val1"))
			So(err, ShouldBeNil)

			Convey("DeleteBlob error in HDel", func() {
				// If the 2nd path does not exist, HDel is callled
				// Error switching to new path
				mock.ExpectSRem("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
					SetVal(1)
				mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal("val1")
				// failed to get new path
				mock.ExpectSRandMember("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					RedisNil()
				mock.ExpectHDel("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetErr(ErrTestError)

				err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
				So(err, ShouldEqual, ErrTestError)
			})

			Convey("DeleteBlob succeeds in deleting all data for original blob", func() {
				// If the 2nd path does not exist, HDel is callled
				// Error switching to new path
				mock.ExpectSRem("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
					SetVal(1)
				mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal("val1")
				// failed to get new path
				mock.ExpectSRandMember("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					RedisNil()
				mock.ExpectHDel("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(1)

				err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
				So(err, ShouldBeNil)
			})

			Convey("DeleteBlob error in SRandMember", func() {
				// Create entry for 2nd path
				mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
					SetVal(1)
				mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val2").
					SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
				So(err, ShouldBeNil)

				// Error switching to new path
				mock.ExpectSRem("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
					SetVal(1)
				mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal("val1")
				// failed to get new path
				mock.ExpectSRandMember("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					SetErr(ErrTestError)

				err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
				So(err, ShouldEqual, ErrTestError)
			})

			Convey("DeleteBlob error in HSet", func() {
				// Create entry for 2nd path
				mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
					SetVal(1)
				mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val2").
					SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
				So(err, ShouldBeNil)

				// Error switching to new path
				mock.ExpectSRem("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
					SetVal(1)
				mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal("val1")
				mock.ExpectSRandMember("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					SetVal("val2")
				mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
					SetErr(ErrTestError)

				err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
				So(err, ShouldEqual, ErrTestError)
			})

			Convey("DeleteBlob succeeds in switching original blob path", func() {
				// Create entry for 2nd path
				mock.ExpectHExists("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
					SetVal(1)
				mock.ExpectSAdd("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val2").
					SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
				So(err, ShouldBeNil)

				// Error switching to new path
				mock.ExpectSRem("zot:"+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", "val1").
					SetVal(1)
				mock.ExpectHGet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal("val1")
				mock.ExpectSRandMember("zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					SetVal("val2")
				mock.ExpectHSet("zot:"+constants.BlobsCache+":"+constants.OriginalBucket, "key", "val2").
					SetVal(1)

				err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
				So(err, ShouldBeNil)
			})
		})
	})
}
