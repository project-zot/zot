package cache_test

import (
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	tskip "zotregistry.io/zot/pkg/test/skip"
)

func TestDynamoDB(t *testing.T) {
	tskip.SkipDynamo(t)
	Convey("Test dynamoDB", t, func(c C) {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()

		// bad params

		So(func() {
			_ = cache.NewDynamoDBCache("bad params", log)
		}, ShouldPanic)

		keyDigest := godigest.FromString("key")

		cacheDriver, err := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
			Endpoint:  "http://brokenlink",
			TableName: "BlobTable",
			Region:    "us-east-2",
		}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		val, err := cacheDriver.GetBlob(keyDigest)
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cacheDriver.PutBlob(keyDigest, path.Join(dir, "value"))
		So(err, ShouldNotBeNil)

		exists := cacheDriver.HasBlob(keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.DeleteBlob(keyDigest, path.Join(dir, "value"))
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

		val, err = cacheDriver.GetBlob(keyDigest)
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cacheDriver.PutBlob(keyDigest, "")
		So(err, ShouldNotBeNil)

		err = cacheDriver.PutBlob(keyDigest, path.Join(dir, "value"))
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob(keyDigest)
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		exists = cacheDriver.HasBlob(keyDigest, path.Join(dir, "value"))
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
	})
}
