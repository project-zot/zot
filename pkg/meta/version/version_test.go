package version_test

import (
	"context"
	"errors"
	"os"
	"path"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	guuid "github.com/gofrs/uuid"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mdynamodb "zotregistry.dev/zot/pkg/meta/dynamodb"
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
