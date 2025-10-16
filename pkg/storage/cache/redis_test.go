package cache_test

import (
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
	test "zotregistry.dev/zot/v2/pkg/test/common"
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
		So(err, ShouldEqual, zerr.ErrCacheMiss)

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

func TestRedisCacheError(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir := t.TempDir()
		redisURL := "redis://127.0.0.1:" + test.GetFreePort()
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

		redisURL := "redis://127.0.0.1:" + test.GetFreePort() // must not match miniRedis.Addr()
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
