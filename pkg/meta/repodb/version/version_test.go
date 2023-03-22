package version_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/dynamo"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamodb_wrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	"zotregistry.io/zot/pkg/meta/repodb/version"
)

var ErrTestError = errors.New("test error")

func TestVersioningBoltDB(t *testing.T) {
	Convey("Tests", t, func() {
		tmpDir := t.TempDir()
		boltDBParams := bolt.DBParameters{RootDir: tmpDir}
		boltDriver, err := bolt.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		boltdbWrapper, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver)
		defer os.Remove("repo.db")
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
				versionBuck := tx.Bucket([]byte(bolt.VersionBucket))

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
		versionBuck := tx.Bucket([]byte(bolt.VersionBucket))

		return versionBuck.Put([]byte(version.DBVersionKey), []byte(vers))
	})

	return err
}

func TestVersioningDynamoDB(t *testing.T) {
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	Convey("Tests", t, func() {
		params := dynamo.DBDriverParameters{
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestDataTablename: "ManifestDataTable",
			ArtifactDataTablename: "ArtifactDataTable",
			IndexDataTablename:    "IndexDataTable",
			VersionTablename:      "Version",
		}

		dynamoClient, err := dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamodb_wrapper.NewDynamoDBWrapper(dynamoClient, params)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetManifestDataTable(), ShouldBeNil)
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)

		Convey("DBVersion is empty", func() {
			err := setDynamoDBVersion(dynamoWrapper.Client, "")
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

			err := setDynamoDBVersion(dynamoWrapper.Client, version.Version1)
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

func setDynamoDBVersion(client *dynamodb.Client, vers string) error {
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
			"VersionKey": &types.AttributeValueMemberS{
				Value: version.DBVersionKey,
			},
		},
		TableName:        aws.String("Version"),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}
