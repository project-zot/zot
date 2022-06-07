package dynamodatabase_test

import (
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/database"
	"zotregistry.io/zot/pkg/storage/dynamodatabase"
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

		cache, err := database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
			Endpoint: "http://brokenlink",
		}, log)
		So(cache, ShouldNotBeNil)
		So(err, ShouldBeNil)

		val, err := cache.GetBlob("key")
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cache.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldNotBeNil)

		exists := cache.HasBlob("key", path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cache.DeleteBlob("key", path.Join(dir, "value"))
		So(err, ShouldNotBeNil)

		cache, err = database.Create("dynamodb", dynamodatabase.DynamoDBDriverParameters{
			Endpoint: os.Getenv("DYNAMODBMOCK_ENDPOINT"),
		}, log)
		So(cache, ShouldNotBeNil)
		So(err, ShouldBeNil)

		returnedName := cache.Name()
		So(returnedName, ShouldEqual, "dynamodb")

		val, err = cache.GetBlob("key")
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = cache.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		err = cache.PutBlob("emptypath", "")
		So(err, ShouldNotBeNil)

		val, err = cache.GetBlob("key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		exists = cache.HasBlob("key", path.Join(dir, "value"))
		So(exists, ShouldBeTrue)

		err = cache.DeleteBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		exists = cache.HasBlob("key", path.Join(dir, "value"))
		So(exists, ShouldBeFalse)

		err = cache.PutBlob("key", path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		err = cache.PutBlob("key", path.Join(dir, "value2"))
		So(err, ShouldBeNil)

		err = cache.DeleteBlob("key", path.Join(dir, "value1"))
		So(err, ShouldBeNil)

		exists = cache.HasBlob("key", path.Join(dir, "value2"))
		So(exists, ShouldBeTrue)

		exists = cache.HasBlob("key", path.Join(dir, "value1"))
		So(exists, ShouldBeFalse)

		err = cache.DeleteBlob("key", path.Join(dir, "value2"))
		So(err, ShouldBeNil)
	})
}
