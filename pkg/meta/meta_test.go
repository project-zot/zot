package meta_test

import (
	"os"
	"path"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/dynamo"
)

func TestCreateDynamo(t *testing.T) {
	skipDynamo(t)

	Convey("Create", t, func() {
		dynamoDBDriverParams := dynamo.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestDataTablename: "ManifestDataTable",
			IndexDataTablename:    "IndexDataTable",
			UserDataTablename:     "UserDataTable",
			VersionTablename:      "Version",
			Region:                "us-east-2",
		}

		client, err := dynamo.GetDynamoClient(dynamoDBDriverParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		repoDB, err := meta.Create("dynamodb", client, dynamoDBDriverParams, log)
		So(repoDB, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("Fails", t, func() {
		log := log.NewLogger("debug", "")

		So(func() { _, _ = meta.Create("dynamodb", nil, bolt.DBParameters{RootDir: "root"}, log) }, ShouldPanic)

		So(func() { _, _ = meta.Create("dynamodb", &dynamodb.Client{}, "bad", log) }, ShouldPanic)

		repoDB, err := meta.Create("random", nil, bolt.DBParameters{RootDir: "root"}, log)
		So(repoDB, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})
}

func TestCreateBoltDB(t *testing.T) {
	Convey("Create", t, func() {
		rootDir := t.TempDir()
		params := bolt.DBParameters{
			RootDir: rootDir,
		}
		boltDriver, err := bolt.GetBoltDriver(params)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		repoDB, err := meta.Create("boltdb", boltDriver, params, log)
		So(repoDB, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("fails", t, func() {
		log := log.NewLogger("debug", "")

		So(func() { _, _ = meta.Create("boltdb", nil, dynamo.DBDriverParameters{}, log) }, ShouldPanic)
	})
}

func TestNew(t *testing.T) {
	Convey("InitCosignAndNotationDirs fails", t, func() {
		rootDir := t.TempDir()

		var storageConfig config.StorageConfig

		storageConfig.RootDirectory = rootDir
		storageConfig.RemoteCache = false
		log := log.NewLogger("debug", "")

		_, err := os.Create(path.Join(rootDir, "repo.db"))
		So(err, ShouldBeNil)

		err = os.Chmod(rootDir, 0o555)
		So(err, ShouldBeNil)

		newRepodb, err := meta.New(storageConfig, log)
		So(newRepodb, ShouldBeNil)
		So(err, ShouldNotBeNil)

		err = os.Chmod(rootDir, 0o777)
		So(err, ShouldBeNil)
	})
}

func skipDynamo(t *testing.T) {
	t.Helper()

	if os.Getenv("DYNAMODBMOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS DynamoDB mock server")
	}
}
