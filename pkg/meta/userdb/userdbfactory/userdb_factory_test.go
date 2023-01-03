package userdbfactory_test

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	bolt "zotregistry.io/zot/pkg/meta/userdb/boltdb-wrapper"
	dynamoParams "zotregistry.io/zot/pkg/meta/userdb/dynamodb-wrapper/params"
	"zotregistry.io/zot/pkg/meta/userdb/userdbfactory"
)

func TestCreateDynamo(t *testing.T) {
	skipDynamo(t)

	Convey("Create", t, func() {
		dynamoDBDriverParams := dynamoParams.DBDriverParameters{
			Endpoint:             os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			APIKeyTablename:      "ApiKeyTable",
			UserProfileTablename: "UserProfileTable",
			VersionTablename:     "Version",
			Region:               "us-east-2",
		}

		userdb, err := userdbfactory.Create("dynamodb", dynamoDBDriverParams)
		So(userdb, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("Fails", t, func() {
		So(func() { _, _ = userdbfactory.Create("dynamodb", bolt.DBParameters{RootDir: "root"}) }, ShouldPanic)

		userdb, err := userdbfactory.Create("random", bolt.DBParameters{RootDir: "root"})
		So(userdb, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})
}

func TestCreateBoltDB(t *testing.T) {
	Convey("Create", t, func() {
		rootDir := t.TempDir()

		userdb, err := userdbfactory.Create("boltdb", bolt.DBParameters{
			RootDir: rootDir,
		})
		So(userdb, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("fails", t, func() {
		So(func() { _, _ = userdbfactory.Create("boltdb", dynamoParams.DBDriverParameters{}) }, ShouldPanic)
	})
}

func skipDynamo(t *testing.T) {
	t.Helper()

	if os.Getenv("DYNAMODBMOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS DynamoDB mock server")
	}
}
