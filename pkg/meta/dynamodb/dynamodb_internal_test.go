package dynamodb

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	guuid "github.com/gofrs/uuid"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log" //nolint:go-staticcheck
	"zotregistry.dev/zot/pkg/meta/version"
	tskip "zotregistry.dev/zot/pkg/test/skip"
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

		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           badEndpoint,
					SigningRegion: region,
				}, nil
			},
		)

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver))
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client:            dynamodb.NewFromConfig(cfg),
			RepoMetaTablename: repoMetaTablename,
			VersionTablename:  versionTablename,
			UserDataTablename: userDataTablename,
			APIKeyTablename:   apiKeyTablename,
			Patches:           version.GetDynamoDBPatches(),
			Log:               log.Logger{Logger: zerolog.New(os.Stdout)},
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
		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           endpoint,
					SigningRegion: region,
				}, nil
			},
		)

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region),
			config.WithEndpointResolverWithOptions(customResolver))
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client:            dynamodb.NewFromConfig(cfg),
			RepoMetaTablename: repoMetaTablename,
			VersionTablename:  versionTablename,
			UserDataTablename: userDataTablename,
			Patches:           version.GetDynamoDBPatches(),
			Log:               log.Logger{Logger: zerolog.New(os.Stdout)},
		}

		// The tables were not created so delete calls fail, but dynamoWrapper should not error
		err = dynamoWrapper.deleteTable(dynamoWrapper.RepoMetaTablename)
		So(err, ShouldBeNil)
	})
}
