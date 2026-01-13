package dynamodb

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	guuid "github.com/gofrs/uuid"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/version"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestWrapperErrors(t *testing.T) {
	tskip.SkipDynamo(t)

	const region = "us-east-2"

	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()

	versionTablename := "Version" + uuid.String()

	Convey("Create table errors", t, func() {
		badEndpoint := endpoint + "1"

		customResolver := aws.EndpointResolverWithOptionsFunc( //nolint: staticcheck
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{ //nolint: staticcheck
					PartitionID:   "aws",
					URL:           badEndpoint,
					SigningRegion: region,
				}, nil
			},
		)

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver)) //nolint: staticcheck
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client:            dynamodb.NewFromConfig(cfg),
			RepoMetaTablename: repoMetaTablename,
			VersionTablename:  versionTablename,
			UserDataTablename: userDataTablename,
			APIKeyTablename:   apiKeyTablename,
			Patches:           version.GetDynamoDBPatches(),
			Log:               log.NewTestLogger(),
		}

		// The table creation should fail as the endpoint is not configured correctly
		err = dynamoWrapper.createTable(dynamoWrapper.RepoMetaTablename)
		So(err, ShouldNotBeNil)

		err = dynamoWrapper.createVersionTable()
		So(err, ShouldNotBeNil)

		err = dynamoWrapper.createTable(dynamoWrapper.APIKeyTablename)
		So(err, ShouldNotBeNil)
	})

	Convey("Delete table errors", t, func() {
		customResolver := aws.EndpointResolverWithOptionsFunc( //nolint: staticcheck
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{ //nolint: staticcheck
					PartitionID:   "aws",
					URL:           endpoint,
					SigningRegion: region,
				}, nil
			},
		)

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver)) //nolint: staticcheck
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client:            dynamodb.NewFromConfig(cfg),
			RepoMetaTablename: repoMetaTablename,
			VersionTablename:  versionTablename,
			UserDataTablename: userDataTablename,
			Patches:           version.GetDynamoDBPatches(),
			Log:               log.NewTestLogger(),
		}

		// The tables were not created so delete calls fail, but dynamoWrapper should not error
		err = dynamoWrapper.deleteTable(dynamoWrapper.RepoMetaTablename)
		So(err, ShouldBeNil)
	})

	Convey("Create version table behavior", t, func() {
		customResolver := aws.EndpointResolverWithOptionsFunc( //nolint: staticcheck
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{ //nolint: staticcheck
					PartitionID:   "aws",
					URL:           endpoint,
					SigningRegion: region,
				}, nil
			},
		)

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver)) //nolint: staticcheck
		So(err, ShouldBeNil)

		Convey("createVersionTable sets version for new table", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client:           dynamodb.NewFromConfig(cfg),
				VersionTablename: versionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			// Create version table - should set version
			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)
			defer func() {
				_ = dynamoWrapper.deleteTable(versionTablename)
			}()

			// Verify version was set
			actualVersion, err := getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})

		Convey("createVersionTable sets version when table exists but version doesn't", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client:           dynamodb.NewFromConfig(cfg),
				VersionTablename: versionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			// Create table first without version
			err = dynamoWrapper.createTable(versionTablename)
			So(err, ShouldBeNil)
			defer func() {
				_ = dynamoWrapper.deleteTable(versionTablename)
			}()

			// Now create version table - should set version even though table exists
			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)

			// Verify version was set
			actualVersion, err := getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})

		Convey("createVersionTable does not overwrite existing version", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client:           dynamodb.NewFromConfig(cfg),
				VersionTablename: versionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			// Create version table first - sets version to CurrentVersion
			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)
			defer func() {
				_ = dynamoWrapper.deleteTable(versionTablename)
			}()

			// Manually set a different version
			err = setVersion(dynamoWrapper.Client, versionTablename, "V2")
			So(err, ShouldBeNil)

			// Verify version is V2
			actualVersion, err := getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, "V2")

			// Call createVersionTable again - should not overwrite existing version
			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)

			// Verify version is still V2, not overwritten
			actualVersion, err = getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, "V2")
		})

		Convey("createVersionTable is idempotent - can be called multiple times", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client:           dynamodb.NewFromConfig(cfg),
				VersionTablename: versionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			// Call createVersionTable multiple times
			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)
			defer func() {
				_ = dynamoWrapper.deleteTable(versionTablename)
			}()

			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)

			err = dynamoWrapper.createVersionTable()
			So(err, ShouldBeNil)

			// Verify version is set correctly
			actualVersion, err := getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})
	})
}

// Helper function to get version from DynamoDB
func getVersion(client *dynamodb.Client, versionTablename string) (string, error) {
	resp, err := client.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: aws.String(versionTablename),
		Key: map[string]types.AttributeValue{
			"TableKey": &types.AttributeValueMemberS{
				Value: version.DBVersionKey,
			},
		},
	})
	if err != nil {
		return "", err
	}

	if resp.Item == nil {
		return "", nil
	}

	var versionValue string
	err = attributevalue.Unmarshal(resp.Item["Version"], &versionValue)
	if err != nil {
		return "", err
	}

	return versionValue, nil
}

// Helper function to set version in DynamoDB
func setVersion(client *dynamodb.Client, versionTablename string, versionValue string) error {
	mdAttributeValue, err := attributevalue.Marshal(versionValue)
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
		TableName:        aws.String(versionTablename),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}
