package dynamodb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
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

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(badEndpoint)
			}),
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
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		So(err, ShouldBeNil)

		dynamoWrapper := DynamoDB{
			Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			}),
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
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		So(err, ShouldBeNil)

		Convey("createVersionTable sets version for new table", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
					o.BaseEndpoint = aws.String(endpoint)
				}),
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

		Convey("New sets version when version table already exists but version doesn't", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)

			client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			})

			params := DBDriverParameters{
				RepoMetaTablename:      "RepoMetadataTable" + uuid.String(),
				RepoBlobsInfoTablename: "RepoBlobsTable" + uuid.String(),
				ImageMetaTablename:     "ImageMetaTable" + uuid.String(),
				UserDataTablename:      "UserDataTable" + uuid.String(),
				APIKeyTablename:        "ApiKeyTable" + uuid.String(),
				VersionTablename:       "Version" + uuid.String(),
			}

			dynamoWrapper := DynamoDB{
				Client:           client,
				VersionTablename: params.VersionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			err = dynamoWrapper.createTable(params.VersionTablename)
			So(err, ShouldBeNil)

			defer func() {
				for _, tableName := range []string{
					params.RepoMetaTablename,
					params.RepoBlobsInfoTablename,
					params.ImageMetaTablename,
					params.UserDataTablename,
					params.APIKeyTablename,
					params.VersionTablename,
				} {
					_ = dynamoWrapper.deleteTable(tableName)
				}
			}()

			_, err = New(client, params, log.NewTestLogger())
			So(err, ShouldBeNil)

			actualVersion, err := getVersion(client, params.VersionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})

		Convey("createVersionTable sets version when table exists but version doesn't", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
					o.BaseEndpoint = aws.String(endpoint)
				}),
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
				Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
					o.BaseEndpoint = aws.String(endpoint)
				}),
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

		Convey("createVersionTable tolerates concurrent CreateTable", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
					o.BaseEndpoint = aws.String(endpoint)
				}),
				VersionTablename: versionTablename,
				Patches:          version.GetDynamoDBPatches(),
				Log:              log.NewTestLogger(),
			}

			var wg sync.WaitGroup

			errs := make(chan error, 2)

			for range 2 {
				wg.Go(func() {
					errs <- dynamoWrapper.createVersionTable()
				})
			}

			wg.Wait()
			close(errs)

			for err := range errs {
				So(err, ShouldBeNil)
			}

			defer func() {
				_ = dynamoWrapper.deleteTable(versionTablename)
			}()

			actualVersion, err := getVersion(dynamoWrapper.Client, versionTablename)
			So(err, ShouldBeNil)
			So(actualVersion, ShouldEqual, version.CurrentVersion)
		})

		Convey("createVersionTable is idempotent - can be called multiple times", func() {
			uuid, err := guuid.NewV4()
			So(err, ShouldBeNil)
			versionTablename := "Version" + uuid.String()

			dynamoWrapper := DynamoDB{
				Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
					o.BaseEndpoint = aws.String(endpoint)
				}),
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

	Convey("createTableIfNotExists", t, func() {
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
		So(err, ShouldBeNil)

		uuid, err := guuid.NewV4()
		So(err, ShouldBeNil)
		tableName := "RepoMetadataTable" + uuid.String()

		dynamoWrapper := DynamoDB{
			Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			}),
			Log: log.NewTestLogger(),
		}

		err = dynamoWrapper.createTable(tableName)
		So(err, ShouldBeNil)
		defer func() {
			_ = dynamoWrapper.deleteTable(tableName)
		}()

		err = dynamoWrapper.createTableIfNotExists(tableName)
		So(err, ShouldBeNil)
	})
}

func TestIgnoreResourceInUseError(t *testing.T) {
	Convey("ignoreResourceInUseError", t, func() {
		So(ignoreResourceInUseError(nil), ShouldBeNil)

		inUseErr := &types.ResourceInUseException{Message: aws.String("table exists")}
		So(ignoreResourceInUseError(inUseErr), ShouldBeNil)

		otherErr := errors.New("create table failed")
		So(ignoreResourceInUseError(otherErr), ShouldEqual, otherErr)
	})
}

func TestCreateVersionTableCreateErrors(t *testing.T) {
	const (
		region            = "us-east-2"
		versionTablename  = "VersionTest"
		describeTableOp   = "DynamoDB_20120810.DescribeTable"
		createTableOp     = "DynamoDB_20120810.CreateTable"
		updateItemOp      = "DynamoDB_20120810.UpdateItem"
		resourceNotFound  = `{"__type":"com.amazon.coral.service#ResourceNotFoundException","message":"not found"}`
		resourceInUse     = `{"__type":"com.amazon.coral.service#ResourceInUseException","message":"already exists"}`
		internalError     = `{"__type":"com.amazon.coral.service#InternalServerError","message":"boom"}`
		activeTable       = `{"Table":{"TableName":"VersionTest","TableStatus":"ACTIVE"}}`
	)

	newTestClient := func(handler func(target string) (int, string)) *dynamodb.Client {
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithCredentialsProvider(aws.AnonymousCredentials{}),
			config.WithHTTPClient(&http.Client{
				Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					target := req.Header.Get("X-Amz-Target")
					status, body := handler(target)

					return &http.Response{
						StatusCode: status,
						Body:       io.NopCloser(bytes.NewBufferString(body)),
						Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
						Request:    req,
					}, nil
				}),
			}),
		)
		So(err, ShouldBeNil)

		return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String("http://dynamodb.test")
		})
	}

	Convey("createVersionTable propagates non-ResourceInUse CreateTable errors", t, func() {
		client := newTestClient(func(target string) (int, string) {
			switch target {
			case describeTableOp:
				return http.StatusBadRequest, resourceNotFound
			case createTableOp:
				return http.StatusInternalServerError, internalError
			default:
				return http.StatusInternalServerError, internalError
			}
		})

		dynamoWrapper := DynamoDB{
			Client:           client,
			VersionTablename: versionTablename,
			Log:              log.NewTestLogger(),
		}

		err := dynamoWrapper.createVersionTable()
		So(err, ShouldNotBeNil)
	})

	Convey("createVersionTable tolerates ResourceInUseException from CreateTable", t, func() {
		describeCount := 0

		client := newTestClient(func(target string) (int, string) {
			switch target {
			case describeTableOp:
				describeCount++

				if describeCount == 1 {
					return http.StatusBadRequest, resourceNotFound
				}

				return http.StatusOK, activeTable
			case createTableOp:
				return http.StatusBadRequest, resourceInUse
			case updateItemOp:
				return http.StatusOK, `{}`
			default:
				return http.StatusInternalServerError, internalError
			}
		})

		dynamoWrapper := DynamoDB{
			Client:           client,
			VersionTablename: versionTablename,
			Log:              log.NewTestLogger(),
		}

		err := dynamoWrapper.createVersionTable()
		So(err, ShouldBeNil)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
