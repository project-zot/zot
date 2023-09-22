package dynamodb_test

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
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/imagetrust"
	"zotregistry.io/zot/pkg/log"
	mdynamodb "zotregistry.io/zot/pkg/meta/dynamodb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	reqCtx "zotregistry.io/zot/pkg/requestcontext"
	. "zotregistry.io/zot/pkg/test/image-utils"
	tskip "zotregistry.io/zot/pkg/test/skip"
)

const badTablename = "bad tablename"

func TestIterator(t *testing.T) {
	tskip.SkipDynamo(t)

	const region = "us-east-2"
	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()

	log := log.NewLogger("debug", "")

	Convey("TestIterator", t, func() {
		params := mdynamodb.DBDriverParameters{
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			APIKeyTablename:        apiKeyTablename,
			UserDataTablename:      userDataTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename), ShouldBeNil)
		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename), ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo1", "tag1", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo2", "tag2", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference(context.Background(), "repo3", "tag3", CreateRandomImage().AsImageMeta())
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := mdynamodb.NewBaseDynamoAttributesIterator(
			dynamoWrapper.Client,
			dynamoWrapper.RepoMetaTablename,
			"RepoMetadata",
			1,
			log,
		)

		attribute, err := repoMetaAttributeIterator.First(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = repoMetaAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldBeNil)
	})
}

func TestIteratorErrors(t *testing.T) {
	Convey("errors", t, func() {
		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           "endpoint",
					SigningRegion: region,
				}, nil
			})

		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("region"),
			config.WithEndpointResolverWithOptions(customResolver))
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := mdynamodb.NewBaseDynamoAttributesIterator(
			dynamodb.NewFromConfig(cfg),
			"RepoMetadataTable",
			"RepoMetadata",
			1,
			log.Logger{Logger: zerolog.New(os.Stdout)},
		)

		_, err = repoMetaAttributeIterator.First(context.Background())
		So(err, ShouldNotBeNil)
	})
}

func TestWrapperErrors(t *testing.T) {
	tskip.SkipDynamo(t)

	const region = "us-east-2"
	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	wrongTableName := "WRONG Tables"
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()

	log := log.NewLogger("debug", "")

	Convey("Errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params) //nolint:contextcheck
		So(err, ShouldBeNil)

		imgTrustStore, err := imagetrust.NewAWSImageTrustStore(params.Region, params.Endpoint)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log) //nolint:contextcheck
		So(err, ShouldBeNil)

		dynamoWrapper.SetImageTrustStore(imgTrustStore)

		So(dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename), ShouldBeNil)  //nolint:contextcheck
		So(dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename), ShouldBeNil) //nolint:contextcheck
		So(dynamoWrapper.ResetTable(dynamoWrapper.UserDataTablename), ShouldBeNil)  //nolint:contextcheck

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")
		ctx := userAc.DeriveContext(context.Background())

		Convey("SetUserData", func() {
			hashKey := "id"
			apiKeys := make(map[string]mTypes.APIKeyDetails)
			apiKeyDetails := mTypes.APIKeyDetails{
				Label:  "apiKey",
				Scopes: []string{"repo"},
				UUID:   hashKey,
			}

			apiKeys[hashKey] = apiKeyDetails

			userProfileSrc := mTypes.UserData{
				Groups:  []string{"group1", "group2"},
				APIKeys: apiKeys,
			}

			err := dynamoWrapper.SetUserData(ctx, userProfileSrc)
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = dynamoWrapper.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData", func() {
			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = dynamoWrapper.DeleteUserData(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo no access", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})
			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo GetUserMeta no user data", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)
			So(status, ShouldEqual, mTypes.Added)
		})

		Convey("ToggleBookmarkRepo GetUserMeta client error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})
			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
			So(status, ShouldEqual, mTypes.NotChanged)
		})

		Convey("GetBookmarkedRepos", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})
			ctx := userAc.DeriveContext(context.Background())

			repos, err := dynamoWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("ToggleStarRepo GetUserMeta bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta no access", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})
			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": false,
			})
			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetRepoMeta error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.RepoMetaTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			userData, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
			So(userData.BookmarkedRepos, ShouldBeEmpty)
			So(userData.StarredRepos, ShouldBeEmpty)
		})

		Convey("GetUserData client error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserMeta unmarshal error, bad user data", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			err := setBadUserData(dynamoWrapper.Client, userDataTablename, userAc.GetUsername())
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey returns nil", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx := userAc.DeriveContext(context.Background())

			apiKeyDetails := make(map[string]mTypes.APIKeyDetails)
			apiKeyDetails["id"] = mTypes.APIKeyDetails{
				UUID: "id",
			}
			err := dynamoWrapper.SetUserData(ctx, mTypes.UserData{
				APIKeys: apiKeyDetails,
			})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.DeleteUserAPIKey(ctx, "id")
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey", func() {
			Convey("no userid found", func() {
				userAc := reqCtx.NewUserAccessControl()
				ctx := userAc.DeriveContext(context.Background())

				err = dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
				So(err, ShouldNotBeNil)
			})

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx := userAc.DeriveContext(context.Background())

			err := dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.AddUserAPIKey(ctx, "key", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName
			_, err := dynamoWrapper.GetUserAPIKeyInfo("key")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData", func() {
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("email")
			ctx = userAc.DeriveContext(context.Background())

			dynamoWrapper.UserDataTablename = wrongTableName
			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("PatchDB dwr.getDBVersion errors", func() {
			dynamoWrapper.VersionTablename = badTablename

			err := dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("PatchDB patchIndex < version.GetVersionIndex", func() {
			err := setVersion(dynamoWrapper.Client, versionTablename, "V2")
			So(err, ShouldBeNil)

			dynamoWrapper.Patches = []func(client *dynamodb.Client, tableNames map[string]string) error{
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
				func(client *dynamodb.Client, tableNames map[string]string) error { return nil },
			}

			err = dynamoWrapper.PatchDB()
			So(err, ShouldBeNil)
		})

		Convey("ResetRepoMetaTable client errors", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			err := dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename)
			So(err, ShouldNotBeNil)
		})

		Convey("getDBVersion client errors", func() {
			dynamoWrapper.VersionTablename = badTablename

			err := dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})
	})

	Convey("NewDynamoDBWrapper errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      "",
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			VersionTablename:       "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			UserDataTablename:      "",
			APIKeyTablename:        apiKeyTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:               endpoint,
			Region:                 region,
			RepoMetaTablename:      repoMetaTablename,
			ImageMetaTablename:     imageMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			VersionTablename:       versionTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)
	})
}

func setBadUserData(client *dynamodb.Client, userDataTablename, userID string) error {
	userAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UM": "UserData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserData": userAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Key": &types.AttributeValueMemberS{
				Value: userID,
			},
		},
		TableName:        aws.String(userDataTablename),
		UpdateExpression: aws.String("SET #UM = :UserData"),
	})

	return err
}

func setVersion(client *dynamodb.Client, versionTablename string, version string) error {
	mdAttributeValue, err := attributevalue.Marshal(version)
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
			"Key": &types.AttributeValueMemberS{
				Value: "DBVersion",
			},
		},
		TableName:        aws.String(versionTablename),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}
