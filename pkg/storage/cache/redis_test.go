package cache_test

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
)

var ErrTestError = errors.New("TestError")

func TestRedisCache(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Make a new cache", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		cacheDriver, err := storage.Create("redis", "failTypeAssertion", log)
		So(cacheDriver, ShouldBeNil)
		So(err, ShouldNotBeNil)

		connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
		client := redis.NewClient(connOpts)

		cacheDriver, err = storage.Create("redis",
			cache.RedisDriverParameters{client, dir, true, "zot"}, log)
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
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob("key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = cacheDriver.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrEmptyValue)

		connOpts, _ = redis.ParseURL("redis://" + miniRedis.Addr() + "/5")
		client = redis.NewClient(connOpts)

		cacheDriver, err = storage.Create("redis",
			cache.RedisDriverParameters{client, t.TempDir(), false, "zot"}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

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
		So(cacheDriver.HasBlob("key3", "realOrigin"), ShouldBeTrue)

		err = cacheDriver.SetOrigin("key4", "")
		So(err, ShouldEqual, zerr.ErrEmptyValue)

		// SetOrigin on miss and duplicate preservation (absolute paths in this driver).
		So(cacheDriver.SetOrigin("freshKey", "onlyOrigin"), ShouldBeNil)

		val, err = cacheDriver.GetBlob("freshKey")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "onlyOrigin")

		So(cacheDriver.PutBlob("dupKey", "staleOrigin"), ShouldBeNil)
		So(cacheDriver.PutBlob("dupKey", "realOrigin"), ShouldBeNil)
		So(cacheDriver.PutBlob("dupKey", "otherPath"), ShouldBeNil)
		So(cacheDriver.SetOrigin("dupKey", "realOrigin"), ShouldBeNil)

		val, err = cacheDriver.GetBlob("dupKey")
		So(err, ShouldBeNil)
		So(val, ShouldEqual, "realOrigin")

		blobs, err := cacheDriver.GetAllBlobs("dupKey")
		So(err, ShouldBeNil)
		So(blobs[0], ShouldEqual, "realOrigin")
		So(blobs, ShouldContain, "staleOrigin")
		So(blobs, ShouldContain, "otherPath")
	})

	Convey("Test cache.GetAllBlos()", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
		client := redis.NewClient(connOpts)

		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{client, dir, true, "zot"}, log)
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

func TestRedisHasBlobLogsNoErrorOnHit(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("HasBlob does not log an error when the lookup succeeds", t, func() {
		dir := t.TempDir()

		var logBuf bytes.Buffer

		log := log.NewLoggerWithWriter("debug", &logBuf)

		connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
		client := redis.NewClient(connOpts)

		cacheDriver, err := cache.NewRedisCache(
			cache.RedisDriverParameters{client, dir, true, "zot"}, log)
		So(err, ShouldBeNil)
		So(cacheDriver, ShouldNotBeNil)

		err = cacheDriver.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		logBuf.Reset()

		So(cacheDriver.HasBlob("key", path.Join(dir, "value")), ShouldBeTrue)
		So(logBuf.String(), ShouldNotContainSubstring, "unable to get record")
		So(logBuf.String(), ShouldNotContainSubstring, `"level":"error"`)
	})
}

func TestRedisCacheError(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()
		// Port 0 is never a bound listener, so a parallel test cannot place a Redis there.
		redisURL := "redis://127.0.0.1:0"
		connOpts, _ := redis.ParseURL(redisURL)
		brokenClient := redis.NewClient(connOpts)

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		// redis server is not running
		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{brokenClient, dir, true, "zot"}, log)
		So(err, ShouldNotBeNil)
		So(cacheDriver, ShouldBeNil)
	})

	Convey("Redis unreachable", t, func() {
		miniRedis := miniredis.RunT(t)
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
		workingClient := redis.NewClient(connOpts)

		// Port 0 is never a bound listener, so a parallel test cannot place a Redis there.
		redisURL := "redis://127.0.0.1:0"
		connOpts, _ = redis.ParseURL(redisURL)
		brokenClient := redis.NewClient(connOpts)

		cacheDriver, err := cache.NewRedisCache(
			cache.RedisDriverParameters{workingClient, dir, false, "zot"}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// replace the working driver with the broken one
		cacheDriver.SetClient(brokenClient)

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
		dir := t.TempDir()

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		tests := []cache.RedisDriverParameters{
			{
				RootDir:     dir,
				UseRelPaths: true,
			}, {
				RootDir:     dir,
				UseRelPaths: false,
			}, {
				RootDir:     dir,
				UseRelPaths: true,
				KeyPrefix:   "someprefix",
			}, {
				RootDir:     dir,
				UseRelPaths: true,
				KeyPrefix:   "zot",
			},
		}

		for i, redisDriverParams := range tests {
			testID := fmt.Sprintf(" %d", i)

			keyPrefix := redisDriverParams.KeyPrefix
			if len(keyPrefix) == 0 {
				// check default
				keyPrefix = "zot"
			}
			keyPrefix += ":"

			// depending on UseRelPaths value we check the relative or absolute value
			// in results using path.Join(pathPrefix, path) in both cases
			pathPrefix := ""
			if !redisDriverParams.UseRelPaths {
				pathPrefix = redisDriverParams.RootDir
			}

			Convey("PutBlob HExists error"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetErr(ErrTestError)

				err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("PutBlob HSet error"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val")).SetErr(ErrTestError)

				err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("PutBlob SAdd error"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val")).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetErr(ErrTestError)

				err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("PutBlob succeeds original bucket is created"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val")).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
				So(err, ShouldBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("PutBlob succeeds original bucket is reused"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(true)
				mock.ExpectTxPipeline()
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val"))
				So(err, ShouldBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SMembers error in GetAllBlobs"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(path.Join(pathPrefix, "val"))
				mock.ExpectSMembers(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					SetErr(ErrTestError)

				_, err = cacheDriver.GetAllBlobs("key")
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("GetAllBlobs succeeds"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val1")).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val1")).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val1"))
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val2")).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val2")).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
				So(err, ShouldBeNil)

				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(path.Join(pathPrefix, "val1"))
				mock.ExpectSMembers(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
					SetVal([]string{path.Join(pathPrefix, "val1"), path.Join(pathPrefix, "val2")})

				allBlobs, err := cacheDriver.GetAllBlobs("key")
				So(err, ShouldBeNil)
				So(allBlobs, ShouldResemble, []string{path.Join(pathPrefix, "val1"), path.Join(pathPrefix, "val2")})

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin replaces stale origin"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(path.Join(pathPrefix, "stale"))
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key", stored).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", stored).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin no-op when origin already matches"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(stored)
				// Still SAdd so membership is restored if DeleteBlob left origin without the set member.
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", stored).SetVal(0)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin SAdd error when origin already matches"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(stored)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", stored).
					SetErr(ErrTestError)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin returns Rel failure"+testID, func() {
				if !redisDriverParams.UseRelPaths {
					return
				}

				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				// Relative input cannot be made relative to RootDir; do not store it
				// (GetBlob would otherwise prepend rootDir and resolve the wrong object).
				err = cacheDriver.SetOrigin("key", "not-under-root/real")
				So(err, ShouldNotBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin installs origin on cache miss"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					RedisNil()
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key", stored).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", stored).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin HGet error"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetErr(ErrTestError)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin HSet error"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(path.Join(pathPrefix, "stale"))
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key", stored).
					SetErr(ErrTestError)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin SAdd error"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				stored := path.Join(pathPrefix, "real")
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(path.Join(pathPrefix, "stale"))
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key", stored).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key", stored).
					SetErr(ErrTestError)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldEqual, ErrTestError)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin empty path"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				err = cacheDriver.SetOrigin("key", "")
				So(err, ShouldEqual, zerr.ErrEmptyValue)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("SetOrigin lock acquire error"+testID, func() {
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetErr(ErrTestError)

				err = cacheDriver.SetOrigin("key", path.Join(dir, "real"))
				So(err, ShouldNotBeNil)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("HasBlob HExists returns error"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.ExpectSIsMember(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetErr(ErrTestError)

				ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
				So(ok, ShouldBeFalse)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("HasBlob SIsMember returns error"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.ExpectSIsMember(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetErr(ErrTestError)

				ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
				So(ok, ShouldBeFalse)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("HasBlob HExists returns false"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				mock.ExpectSIsMember(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val")).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)

				ok := cacheDriver.HasBlob("key", path.Join(dir, "val"))
				So(ok, ShouldBeFalse)

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})

			Convey("DeleteBlob tests"+testID, func() {
				// initialize mock client
				cacheDB, mock := redismock.NewClientMock()
				redisDriverParams.Client = cacheDB

				mock.ExpectPing().SetVal("OK")
				cacheDriver, err := cache.NewRedisCache(redisDriverParams, log)
				So(cacheDriver, ShouldNotBeNil)
				So(err, ShouldBeNil)

				// Create entry for 1st path
				mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
				mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
					SetVal(false)
				mock.ExpectTxPipeline()
				mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
					path.Join(pathPrefix, "val1")).SetVal(1)
				mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
					path.Join(pathPrefix, "val1")).SetVal(1)
				mock.ExpectTxPipelineExec()

				err = cacheDriver.PutBlob("key", path.Join(dir, "val1"))
				So(err, ShouldBeNil)

				Convey("DeleteBlob error in HDel"+testID, func() {
					// If the 2nd path does not exist, HDel is callled
					// Error switching to new path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectSRem(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val1")).SetVal(1)
					mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(path.Join(pathPrefix, "val1"))
					// failed to get new path
					mock.ExpectSRandMember(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
						RedisNil()
					mock.ExpectHDel(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetErr(ErrTestError)

					err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
					So(err, ShouldEqual, ErrTestError)
				})

				Convey("DeleteBlob succeeds in deleting all data for original blob"+testID, func() {
					// If the 2nd path does not exist, HDel is callled
					// Error switching to new path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectSRem(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val1")).SetVal(1)
					mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(path.Join(pathPrefix, "val1"))
					// failed to get new path
					mock.ExpectSRandMember(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
						RedisNil()
					mock.ExpectHDel(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(1)

					err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
					So(err, ShouldBeNil)
				})

				Convey("DeleteBlob error in SRandMember"+testID, func() {
					// Create entry for 2nd path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(false)
					mock.ExpectTxPipeline()
					mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectTxPipelineExec()

					err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
					So(err, ShouldBeNil)

					// Error switching to new path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectSRem(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val1")).SetVal(1)
					mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(path.Join(pathPrefix, "val1"))
					// failed to get new path
					mock.ExpectSRandMember(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
						SetErr(ErrTestError)

					err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
					So(err, ShouldEqual, ErrTestError)
				})

				Convey("DeleteBlob error in HSet"+testID, func() {
					// Create entry for 2nd path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(false)
					mock.ExpectTxPipeline()
					mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectTxPipelineExec()

					err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
					So(err, ShouldBeNil)

					// Error switching to new path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectSRem(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val1")).SetVal(1)
					mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(path.Join(pathPrefix, "val1"))
					mock.ExpectSRandMember(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
						SetVal(path.Join(pathPrefix, "val2"))
					mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
						path.Join(pathPrefix, "val2")).SetErr(ErrTestError)

					err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
					So(err, ShouldEqual, ErrTestError)
				})

				Convey("DeleteBlob succeeds in switching original blob path"+testID, func() {
					// Create entry for 2nd path
					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectHExists(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(false)
					mock.ExpectTxPipeline()
					mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectSAdd(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val2")).SetVal(1)
					mock.ExpectTxPipelineExec()

					err = cacheDriver.PutBlob("key", path.Join(dir, "val2"))
					So(err, ShouldBeNil)

					mock.Regexp().ExpectSetNX(keyPrefix+"locks:key", `.*`, 8*time.Second).SetVal(true)
					mock.ExpectSRem(keyPrefix+constants.BlobsCache+":"+constants.DuplicatesBucket+":key",
						path.Join(pathPrefix, "val1")).SetVal(1)
					mock.ExpectHGet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key").
						SetVal(path.Join(pathPrefix, "val1"))
					mock.ExpectSRandMember(keyPrefix + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key").
						SetVal(path.Join(pathPrefix, "val2"))
					mock.ExpectHSet(keyPrefix+constants.BlobsCache+":"+constants.OriginalBucket, "key",
						path.Join(pathPrefix, "val2")).SetVal(1)

					err = cacheDriver.DeleteBlob("key", path.Join(dir, "val1"))
					So(err, ShouldBeNil)
				})

				err = mock.ExpectationsWereMet()
				So(err, ShouldBeNil)
			})
		}
	})
}

func TestRedisPutDuplicateAndReplaceBlob(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	for _, useRelPaths := range []bool{false, true} {
		Convey("PutDuplicate and ReplaceBlob keep the origin consistent", t, func() {
			miniRedis.FlushAll()

			dir := t.TempDir()

			connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
			client := redis.NewClient(connOpts)

			cacheDriver, err := storage.Create("redis",
				cache.RedisDriverParameters{client, dir, useRelPaths, "zot"}, log.NewTestLogger())
			So(err, ShouldBeNil)

			origin := path.Join(dir, "repo-a", "blobs", "sha256", "abc")
			second := path.Join(dir, "repo-b", "blobs", "sha256", "abc")
			third := path.Join(dir, "repo-c", "blobs", "sha256", "abc")

			So(cacheDriver.PutDuplicate("digest", origin), ShouldEqual, zerr.ErrCacheMiss)
			So(cacheDriver.PutDuplicate("digest", ""), ShouldEqual, zerr.ErrEmptyValue)

			_, err = cacheDriver.GetBlob("digest")
			So(err, ShouldEqual, zerr.ErrCacheMiss)

			So(cacheDriver.PutBlob("digest", origin), ShouldBeNil)
			So(cacheDriver.PutDuplicate("digest", second), ShouldBeNil)
			So(cacheDriver.HasBlob("digest", second), ShouldBeTrue)

			So(cacheDriver.ReplaceBlob("digest", third, second), ShouldEqual, zerr.ErrCacheConflict)
			So(cacheDriver.ReplaceBlob("digest", origin, third), ShouldEqual, zerr.ErrCacheConflict)
			So(cacheDriver.ReplaceBlob("missing", origin, second), ShouldEqual, zerr.ErrCacheConflict)
			So(cacheDriver.ReplaceBlob("digest", "", second), ShouldEqual, zerr.ErrEmptyValue)

			So(cacheDriver.ReplaceBlob("digest", origin, second), ShouldBeNil)

			stored, err := cacheDriver.GetBlob("digest")
			So(err, ShouldBeNil)

			if useRelPaths {
				So(stored, ShouldEqual, path.Join("repo-b", "blobs", "sha256", "abc"))
			} else {
				So(stored, ShouldEqual, second)
			}

			So(cacheDriver.HasBlob("digest", origin), ShouldBeTrue)
		})
	}
}

func TestRedisPutDuplicateAndReplaceBlobErrors(t *testing.T) {
	Convey("Paths that cannot be made relative are rejected", t, func() {
		miniRedis := miniredis.RunT(t)
		dir := t.TempDir()

		connOpts, _ := redis.ParseURL("redis://" + miniRedis.Addr())
		client := redis.NewClient(connOpts)

		cacheDriver, err := storage.Create("redis",
			cache.RedisDriverParameters{client, dir, true, "zot"}, log.NewTestLogger())
		So(err, ShouldBeNil)

		origin := path.Join(dir, "repo-a", "blobs", "sha256", "abc")
		So(cacheDriver.PutBlob("digest", origin), ShouldBeNil)

		So(cacheDriver.PutDuplicate("digest", "relative/copy"), ShouldNotBeNil)
		So(cacheDriver.ReplaceBlob("digest", "relative/origin", origin), ShouldNotBeNil)
		So(cacheDriver.ReplaceBlob("digest", origin, "relative/copy"), ShouldNotBeNil)

		stored, err := cacheDriver.GetBlob("digest")
		So(err, ShouldBeNil)
		So(stored, ShouldEqual, path.Join("repo-a", "blobs", "sha256", "abc"))
	})

	Convey("Failures of each command are returned", t, func() {
		dir := t.TempDir()
		log := log.NewTestLogger()

		params := cache.RedisDriverParameters{RootDir: dir, UseRelPaths: false, KeyPrefix: "zot"}
		lockKey := "zot:locks:key"
		originKey := "zot:" + constants.BlobsCache + ":" + constants.OriginalBucket
		pathSet := "zot:" + constants.BlobsCache + ":" + constants.DuplicatesBucket + ":key"

		newDriver := func() (*cache.RedisDriver, redismock.ClientMock) {
			cacheDB, mock := redismock.NewClientMock()
			params.Client = cacheDB

			mock.ExpectPing().SetVal("OK")

			cacheDriver, err := cache.NewRedisCache(params, log)
			So(err, ShouldBeNil)

			return cacheDriver, mock
		}

		Convey("PutDuplicate cannot take the lock", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetErr(ErrTestError)

			So(cacheDriver.PutDuplicate("key", "/repo/copy"), ShouldNotBeNil)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("PutDuplicate cannot read the origin", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetVal(true)
			mock.ExpectHExists(originKey, "key").SetErr(ErrTestError)

			So(cacheDriver.PutDuplicate("key", "/repo/copy"), ShouldEqual, ErrTestError)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("PutDuplicate cannot add the path", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetVal(true)
			mock.ExpectHExists(originKey, "key").SetVal(true)
			mock.ExpectSAdd(pathSet, "/repo/copy").SetErr(ErrTestError)

			So(cacheDriver.PutDuplicate("key", "/repo/copy"), ShouldEqual, ErrTestError)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("ReplaceBlob cannot take the lock", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetErr(ErrTestError)

			So(cacheDriver.ReplaceBlob("key", "/repo/origin", "/repo/copy"), ShouldNotBeNil)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("ReplaceBlob cannot read the origin", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetVal(true)
			mock.ExpectHGet(originKey, "key").SetErr(ErrTestError)

			So(cacheDriver.ReplaceBlob("key", "/repo/origin", "/repo/copy"), ShouldEqual, ErrTestError)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("ReplaceBlob cannot check the new path", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetVal(true)
			mock.ExpectHGet(originKey, "key").SetVal("/repo/origin")
			mock.ExpectSIsMember(pathSet, "/repo/copy").SetErr(ErrTestError)

			So(cacheDriver.ReplaceBlob("key", "/repo/origin", "/repo/copy"), ShouldEqual, ErrTestError)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})

		Convey("ReplaceBlob cannot write the origin", func() {
			cacheDriver, mock := newDriver()
			mock.Regexp().ExpectSetNX(lockKey, `.*`, 8*time.Second).SetVal(true)
			mock.ExpectHGet(originKey, "key").SetVal("/repo/origin")
			mock.ExpectSIsMember(pathSet, "/repo/copy").SetVal(true)
			mock.ExpectHSet(originKey, "key", "/repo/copy").SetErr(ErrTestError)

			So(cacheDriver.ReplaceBlob("key", "/repo/origin", "/repo/copy"), ShouldEqual, ErrTestError)
			So(mock.ExpectationsWereMet(), ShouldBeNil)
		})
	})
}
