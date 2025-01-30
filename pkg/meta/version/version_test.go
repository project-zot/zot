package version_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	guuid "github.com/gofrs/uuid"
	goredis "github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mdynamodb "zotregistry.dev/zot/pkg/meta/dynamodb"
	"zotregistry.dev/zot/pkg/meta/redis"
	"zotregistry.dev/zot/pkg/meta/version"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

var ErrTestError = errors.New("test error")

func TestVersioningBoltDB(t *testing.T) {
	Convey("Tests", t, func() {
		tmpDir := t.TempDir()
		boltDBParams := boltdb.DBParameters{RootDir: tmpDir}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb.New(boltDriver, log)

		defer os.Remove(path.Join(boltDBParams.RootDir, "meta.db"))
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		boltdbWrapper.Patches = []func(DB *bbolt.DB) error{
			func(DB *bbolt.DB) error {
				return nil
			},
		}

		Convey("success", func() {
			boltdbWrapper.Patches = []func(DB *bbolt.DB) error{
				func(DB *bbolt.DB) error { // V1 to V2
					return nil
				},
			}

			err := setBoltDBVersion(boltdbWrapper.DB, version.Version1)
			So(err, ShouldBeNil)

			err = boltdbWrapper.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("DBVersion is empty", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				versionBuck := tx.Bucket([]byte(boltdb.VersionBucket))

				return versionBuck.Put([]byte(version.DBVersionKey), []byte(""))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("iterate patches with skip", func() {
			boltdbWrapper.Patches = []func(DB *bbolt.DB) error{
				func(DB *bbolt.DB) error { // V1 to V2
					return nil
				},
				func(DB *bbolt.DB) error { // V2 to V3
					return nil
				},
				func(DB *bbolt.DB) error { // V3 to V4
					return nil
				},
			}

			err := setBoltDBVersion(boltdbWrapper.DB, version.Version1)
			So(err, ShouldBeNil)
			// we should skip the first patch

			err = boltdbWrapper.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("patch has error", func() {
			boltdbWrapper.Patches = []func(DB *bbolt.DB) error{
				func(DB *bbolt.DB) error { // V1 to V2
					return ErrTestError
				},
			}

			err = boltdbWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})
	})
}

func setBoltDBVersion(db *bbolt.DB, vers string) error {
	err := db.Update(func(tx *bbolt.Tx) error {
		versionBuck := tx.Bucket([]byte(boltdb.VersionBucket))

		return versionBuck.Put([]byte(version.DBVersionKey), []byte(vers))
	})

	return err
}

func TestVersioningDynamoDB(t *testing.T) {
	tskip.SkipDynamo(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	Convey("Tests", t, func() {
		params := mdynamodb.DBDriverParameters{
			Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                 "us-east-2",
			RepoMetaTablename:      "RepoMetadataTable" + uuid.String(),
			RepoBlobsInfoTablename: "RepoBlobsInfoTablename" + uuid.String(),
			ImageMetaTablename:     "ImageMetaTablename" + uuid.String(),
			UserDataTablename:      "UserDataTable" + uuid.String(),
			APIKeyTablename:        "ApiKeyTable" + uuid.String(),
			VersionTablename:       "Version" + uuid.String(),
		}

		dynamoClient, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		dynamoWrapper, err := mdynamodb.New(dynamoClient, params, log)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename), ShouldBeNil)

		Convey("dbVersion is empty", func() {
			err := setDynamoDBVersion(dynamoWrapper.Client, params.VersionTablename, "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("iterate patches with skip", func() {
			dynamoWrapper.Patches = []func(client *dynamodb.Client, tableNames map[string]string) error{
				func(client *dynamodb.Client, tableNames map[string]string) error { // V1 to V2
					return nil
				},
				func(client *dynamodb.Client, tableNames map[string]string) error { // V2 to V3
					return nil
				},
				func(client *dynamodb.Client, tableNames map[string]string) error { // V3 to V4
					return nil
				},
			}

			err := setDynamoDBVersion(dynamoWrapper.Client, params.VersionTablename, version.Version1)
			So(err, ShouldBeNil)
			// we should skip the first patch

			err = dynamoWrapper.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("patch has error", func() {
			dynamoWrapper.Patches = []func(client *dynamodb.Client, tableNames map[string]string) error{
				func(client *dynamodb.Client, tableNames map[string]string) error { // V1 to V2
					return ErrTestError
				},
			}

			err = dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})
	})
}

func setDynamoDBVersion(client *dynamodb.Client, versTable, vers string) error {
	mdAttributeValue, err := attributevalue.Marshal(vers)
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#V": "Version",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":Version": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: version.DBVersionKey,
			},
		},
		TableName:        aws.String(versTable),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}

func TestVersioningRedisDB(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Tests", t, func() {
		opts, err := goredis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := goredis.NewClient(opts)
		defer dumpRedisKeys(t, client) // Troubleshoot test failures

		log := log.NewLogger("debug", "")

		params := redis.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redis.New(client, params, log)
		So(err, ShouldBeNil)

		So(metaDB.ResetDB(), ShouldBeNil)

		ctx := context.Background()

		Convey("empty initial version triggers setting the default", func() {
			// Check no value is initially set
			actualVersion, err := client.Get(ctx, metaDB.VersionKey).Result()
			So(err, ShouldEqual, goredis.Nil)
			So(actualVersion, ShouldEqual, "")

			err = metaDB.PatchDB()
			So(err, ShouldBeNil)

			// Check default version is added in the DB
			actualVersion, err = client.Get(ctx, metaDB.VersionKey).Result()
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})

		Convey("initial version with a bad value raises an error", func() {
			// Set invalid initial value
			err = client.Set(ctx, metaDB.VersionKey, "VInvalid", 0).Err()
			So(err, ShouldBeNil)

			// Check error when attempting to patch
			err = metaDB.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("skip iterating patches", func() {
			// Initialize DB version
			metaDB.Version = version.Version1

			// Patches have errors so we can check bad upgrade logic
			metaDB.Patches = []func(client goredis.UniversalClient) error{
				func(client goredis.UniversalClient) error { // V1 to V2
					return ErrTestError
				},
				func(client goredis.UniversalClient) error { // V2 to V3
					return ErrTestError
				},
			}

			// No patch should be applied for V1 so no error is expected
			err = metaDB.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("iterate over patches without any errors", func() {
			// Initialize DB version with a lower version
			metaDB.Version = version.Version1

			err = metaDB.PatchDB()
			So(err, ShouldBeNil)

			// Now change to a newer DB version and apply patches
			metaDB.Version = version.Version3

			metaDB.Patches = []func(goredis.UniversalClient) error{
				func(client goredis.UniversalClient) error { // V1 to V2
					return nil
				},
				func(client goredis.UniversalClient) error { // V2 to V3
					return nil
				},
			}

			err = metaDB.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("iterate over patches with errors", func() {
			// initialize DB version with a lower version
			metaDB.Version = version.Version1

			err = metaDB.PatchDB()
			So(err, ShouldBeNil)

			// now change to a newer DB version and apply patches
			metaDB.Version = version.Version3

			metaDB.Patches = []func(client goredis.UniversalClient) error{
				func(client goredis.UniversalClient) error { // V1 to V2
					return nil
				},
				func(client goredis.UniversalClient) error { // V2 to V3
					return ErrTestError
				},
			}

			err = metaDB.PatchDB()
			So(err, ShouldNotBeNil)
		})
	})
}

func dumpRedisKeys(t *testing.T, client goredis.UniversalClient) {
	t.Helper()

	// Retrieve all keys
	keys, err := client.Keys(context.Background(), "*").Result()
	if err != nil {
		t.Log("Error retrieving keys:", err)

		return
	}

	// Print the keys
	t.Log("Keys in Redis:")

	for _, key := range keys {
		keyType, err := client.Type(context.Background(), key).Result()
		if err != nil {
			t.Logf("Error retrieving type for key %s: %v\n", key, err)

			continue
		}

		var value string

		switch keyType {
		case "string":
			value, err = client.Get(context.Background(), key).Result()
		case "list":
			values, err := client.LRange(context.Background(), key, 0, -1).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "hash":
			values, err := client.HGetAll(context.Background(), key).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "set":
			values, err := client.SMembers(context.Background(), key).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "zset":
			values, err := client.ZRange(context.Background(), key, 0, -1).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		default:
			value = "Unsupported type"
		}

		if err != nil {
			t.Logf("Error retrieving value for key %s: %v\n", key, err)
		} else {
			t.Logf("Key: %s, Type: %s, Value: %s\n", key, keyType, value)
		}
	}
}
