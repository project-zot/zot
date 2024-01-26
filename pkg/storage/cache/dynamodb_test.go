package cache_test

import (
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

func TestDynamoDB(t *testing.T) {
	tskip.SkipDynamo(t)
	Convey("Test dynamoDB", t, func(c C) {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()

		// bad params

		_, err := cache.NewDynamoDBCache("bad params", log)
		So(err, ShouldNotBeNil)

		keyDigest := godigest.FromString("key")

		cacheDriver, err := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
			Endpoint:  "http://brokenlink",
			TableName: "BlobTable",
			Region:    "us-east-2",
		}, log)
		So(cacheDriver, ShouldBeNil)
		So(err, ShouldNotBeNil)

		cacheDriver, err = storage.Create("dynamodb", cache.DynamoDBDriverParameters{
			Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			TableName: "BlobTable",
			Region:    "us-east-2",
		}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		returnedName := cacheDriver.Name()
		So(returnedName, ShouldEqual, "dynamodb")

		val, err := cacheDriver.GetBlob(keyDigest)
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cacheDriver.PutBlob(keyDigest, "")
		So(err, ShouldNotBeNil)

		err = cacheDriver.PutBlob(keyDigest, path.Join(dir, "value"))
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob(keyDigest)
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		exists := cacheDriver.HasBlob(keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeTrue)

		err = cacheDriver.DeleteBlob(keyDigest, path.Join(dir, "value"))
		So(err, ShouldBeNil)

		exists = cacheDriver.HasBlob(keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.PutBlob(keyDigest, path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob(keyDigest, path.Join(dir, "value2"))
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob(keyDigest, path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		exists = cacheDriver.HasBlob(keyDigest, path.Join(dir, "value2"))
		So(exists, ShouldBeTrue)

		exists = cacheDriver.HasBlob(keyDigest, path.Join(dir, "value1"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.DeleteBlob(keyDigest, path.Join(dir, "value2"))
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
}

func TestDynamoDBError(t *testing.T) {
	tskip.SkipDynamo(t)
	Convey("Test dynamoDB", t, func(c C) {
		log := log.NewLogger("debug", "")

		cacheDriver, err := cache.NewDynamoDBCache(cache.DynamoDBDriverParameters{
			Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			TableName: "BlobTable",
			Region:    "us-east-2",
		}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		returnedName := cacheDriver.Name()
		So(returnedName, ShouldEqual, "dynamodb")

		cacheDriver.SetTableName("bad-table")

		_, err = cacheDriver.GetBlob(godigest.FromString("str"))
		So(err, ShouldNotBeNil)
		found := cacheDriver.HasBlob(godigest.FromString("str"), "path")
		So(found, ShouldBeFalse)
		_, err = cacheDriver.GetDuplicateBlob(godigest.FromString("str"))
		So(err, ShouldNotBeNil)
		err = cacheDriver.DeleteBlob(godigest.FromString("str"), "path")
		So(err, ShouldNotBeNil)
	})
}
