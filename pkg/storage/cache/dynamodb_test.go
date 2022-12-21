package cache_test

import (
	"os"
	"path"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
)

func skipIt(t *testing.T) {
	t.Helper()

	if os.Getenv("DYNAMODBMOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS DynamoDB mock server")
	}
}

func TestDynamoDB(t *testing.T) {
	skipIt(t)
	Convey("Test dynamoDB", t, func(c C) {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()

		// bad params
		cacheDB, err := cache.NewDynamoDBCache("bad params", log)
		So(err, ShouldNotBeNil)
		So(cacheDB, ShouldBeNil)

		keyDigest := godigest.FromString("key")

		cacheDriver, err := storage.Create("dynamodb", cache.DynamoDBDriverParameters{
			Endpoint: "http://localhost:999999",
			Region:   "us-east-2",
		}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		tableName := strings.ReplaceAll(dir, "/", "")

		err = cacheDriver.CreateBucket(tableName)
		So(err, ShouldNotBeNil)

		val, err := cacheDriver.GetBlob(tableName, keyDigest)
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cacheDriver.PutBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(err, ShouldNotBeNil)

		exists := cacheDriver.HasBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.DeleteBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(err, ShouldNotBeNil)

		cacheDriver, err = storage.Create("dynamodb", cache.DynamoDBDriverParameters{
			Endpoint: os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:   "us-east-2",
		}, log)
		So(cacheDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = cacheDriver.CreateBucket(tableName)
		So(err, ShouldBeNil)

		err = cacheDriver.CreateBucket("/") // invalid name
		So(err, ShouldNotBeNil)

		returnedName := cacheDriver.Name()
		So(returnedName, ShouldEqual, "dynamodb")

		val, err = cacheDriver.GetBlob(tableName, keyDigest)
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cacheDriver.PutBlob(tableName, keyDigest, "")
		So(err, ShouldNotBeNil)

		err = cacheDriver.PutBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(err, ShouldBeNil)

		val, err = cacheDriver.GetBlob(tableName, keyDigest)
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		exists = cacheDriver.HasBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeTrue)

		err = cacheDriver.DeleteBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(err, ShouldBeNil)

		exists = cacheDriver.HasBlob(tableName, keyDigest, path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.PutBlob(tableName, keyDigest, path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		err = cacheDriver.PutBlob(tableName, keyDigest, path.Join(dir, "value2"))
		So(err, ShouldBeNil)

		err = cacheDriver.DeleteBlob(tableName, keyDigest, path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		exists = cacheDriver.HasBlob(tableName, keyDigest, path.Join(dir, "value2"))
		So(exists, ShouldBeTrue)

		exists = cacheDriver.HasBlob(tableName, keyDigest, path.Join(dir, "value1"))
		So(exists, ShouldBeFalse)

		err = cacheDriver.DeleteBlob(tableName, keyDigest, path.Join(dir, "value2"))
		So(err, ShouldBeNil)

		_, err = cacheDriver.GetBlob("", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		ok := cacheDriver.HasBlob("", "key", "path")
		So(ok, ShouldBeFalse)

		err = cacheDriver.DeleteBlob("", "", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		err = cacheDriver.PutBlob("", "", "key")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		err = cacheDriver.Close()
		So(err, ShouldBeNil)
	})
}
