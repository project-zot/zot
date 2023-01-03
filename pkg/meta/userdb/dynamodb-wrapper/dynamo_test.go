package dynamo_test

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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/userdb"
	dynamo "zotregistry.io/zot/pkg/meta/userdb/dynamodb-wrapper"
	"zotregistry.io/zot/pkg/meta/userdb/dynamodb-wrapper/iterator"
	dynamoParams "zotregistry.io/zot/pkg/meta/userdb/dynamodb-wrapper/params"
)

const (
	wrongTableName = "WRONG table"
)

func TestIterator(t *testing.T) {
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	userProfileTablename := "UserProfileTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	versionTablename := "Version" + uuid.String()

	Convey("TestIterator", t, func() {
		dynamoWrapper, err := dynamo.NewDynamoDBWrapper(dynamoParams.DBDriverParameters{
			Endpoint:             endpoint,
			Region:               region,
			UserProfileTablename: userProfileTablename,
			APIKeyTablename:      apiKeyTablename,
			VersionTablename:     versionTablename,
		})
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetAPIKeyTable(), ShouldBeNil)
		So(dynamoWrapper.ResetUserProfileTable(), ShouldBeNil)
		err = dynamoWrapper.SetUserProfile("email1", userdb.UserProfile{})
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetUserProfile("email2", userdb.UserProfile{})
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetUserProfile("email3", userdb.UserProfile{})
		So(err, ShouldBeNil)

		err = dynamoWrapper.AddUserAPIKey("hk1", "email1", &userdb.APIKeyDetails{UUID: "1"})
		So(err, ShouldBeNil)

		err = dynamoWrapper.AddUserAPIKey("hk2", "email2", &userdb.APIKeyDetails{UUID: "2"})
		So(err, ShouldBeNil)

		err = dynamoWrapper.AddUserAPIKey("hk3", "email3", &userdb.APIKeyDetails{UUID: "3"})
		So(err, ShouldBeNil)

		err = dynamoWrapper.AddUserAPIKey("hk4", "email4", &userdb.APIKeyDetails{UUID: "4"})
		So(err, ShouldNotBeNil)

		apiKeyAttributeIterator := iterator.NewBaseDynamoAttributesIterator(
			dynamoWrapper.Client,
			apiKeyTablename,
			"HashedKey",
			1,
			log.Logger{Logger: zerolog.New(os.Stdout)},
		)

		attribute, err := apiKeyAttributeIterator.First(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = apiKeyAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = apiKeyAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)

		attribute, err = apiKeyAttributeIterator.Next(context.Background())
		So(err, ShouldBeNil)
		So(attribute, ShouldNotBeNil)
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

		apiKeyAttributeIterator := iterator.NewBaseDynamoAttributesIterator(
			dynamodb.NewFromConfig(cfg),
			"ApiKeyTable",
			"HashedKey",
			1,
			log.Logger{Logger: zerolog.New(os.Stdout)},
		)

		_, err = apiKeyAttributeIterator.First(context.Background())
		So(err, ShouldNotBeNil)
	})
}

func TestWrapperErrors(t *testing.T) {
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	userProfileTablename := "UserProfileTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	versionTablename := "Version" + uuid.String()

	// ctx := context.Background()

	Convey("Errors", t, func() {
		dynamoWrapper, err := dynamo.NewDynamoDBWrapper(dynamoParams.DBDriverParameters{ //nolint:contextcheck
			Endpoint:             endpoint,
			Region:               region,
			UserProfileTablename: userProfileTablename,
			APIKeyTablename:      apiKeyTablename,
			VersionTablename:     versionTablename,
		})
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetAPIKeyTable(), ShouldBeNil)      //nolint:contextcheck
		So(dynamoWrapper.ResetUserProfileTable(), ShouldBeNil) //nolint:contextcheck

		Convey("AddUserAPIKey wrong table", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName

			err := dynamoWrapper.AddUserAPIKey("hk", "test@email.com", &userdb.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey no user profile", func() {
			err := dynamoWrapper.AddUserAPIKey("hk", "test@email.com", &userdb.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo wrong table", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName

			_, err := dynamoWrapper.GetUserAPIKeyInfo("hk")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo unmarshal error", func() {
			err := setBadAPIKeyInfo(dynamoWrapper.Client, apiKeyTablename, "hk1")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetUserAPIKeyInfo("hk1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo not found error", func() {
			_, err = dynamoWrapper.GetUserAPIKeyInfo("hk1")
			So(err, ShouldEqual, zerr.ErrUserAPIKeyNotFound)
		})

		Convey("DeleteUserAPIKey no user profile", func() {
			err = dynamoWrapper.DeleteUserAPIKey("id1", "test@email.com")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey wrong table", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.SetUserProfile("test@email.com", userdb.UserProfile{
				APIKeys: map[string]userdb.APIKeyDetails{
					"test@email.com": {
						UUID: "id1",
					},
				},
			})
			So(err, ShouldBeNil)
			err = dynamoWrapper.DeleteUserAPIKey("id1", "test@email.com")
			So(err, ShouldNotBeNil)
		})
		Convey("DeleteUserAPIKey no api key", func() {
			err = dynamoWrapper.SetUserProfile("test@email.com", userdb.UserProfile{
				APIKeys: map[string]userdb.APIKeyDetails{
					"test@email.com": {},
				},
			})
			So(err, ShouldBeNil)
			err = dynamoWrapper.DeleteUserAPIKey("id1", "test@email.com")
			So(err, ShouldBeNil)
		})
		Convey("DeleteUserAPIKey", func() {
			err = dynamoWrapper.SetUserProfile("test@email.com", userdb.UserProfile{
				APIKeys: map[string]userdb.APIKeyDetails{
					"test@email.com": {
						UUID: "id1",
					},
				},
			})
			So(err, ShouldBeNil)
			err = dynamoWrapper.DeleteUserAPIKey("id1", "test@email.com")
			So(err, ShouldBeNil)
		})

		Convey("DeleteUserProfile", func() {
			err = dynamoWrapper.DeleteUserProfile("test@email.com")
			So(err, ShouldBeNil)
		})

		Convey("GetUserProfile invalid email", func() {
			_, err = dynamoWrapper.GetUserProfile("")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserProfile profile not found ", func() {
			_, err = dynamoWrapper.GetUserProfile("test@email.com")
			So(err, ShouldEqual, zerr.ErrUserProfileNotFound)
		})

		Convey("GetUserProfile unmarshal err ", func() {
			err = setBadUserProfile(dynamoWrapper.Client, userProfileTablename, "test@email.com")
			So(err, ShouldBeNil)
			_, err = dynamoWrapper.GetUserProfile("test@email.com")
			So(err, ShouldNotBeNil)
		})

		// Convey("SetManifestMeta GetRepoMeta error", func() {
		// 	err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo1")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.SetManifestMeta("repo1", "dig", userdb.ManifestMetadata{})
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("GetManifestMeta GetManifestData not found error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	_, err = dynamoWrapper.GetManifestMeta("repo", "dig")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("GetManifestMeta GetRepoMeta Not Found error", func() {
		// 	err := dynamoWrapper.SetManifestData("dig", userdb.ManifestData{})
		// 	So(err, ShouldBeNil)

		// 	_, err = dynamoWrapper.GetManifestMeta("repoNotFound", "dig")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("GetManifestMeta GetRepoMeta error", func() {
		// 	err := dynamoWrapper.SetManifestData("dig", userdb.ManifestData{})
		// 	So(err, ShouldBeNil)

		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
		// 	So(err, ShouldBeNil)

		// 	_, err = dynamoWrapper.GetManifestMeta("repo", "dig")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("IncrementRepoStars GetRepoMeta error", func() {
		// 	err = dynamoWrapper.IncrementRepoStars("repo")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("DecrementRepoStars GetRepoMeta error", func() {
		// 	err = dynamoWrapper.DecrementRepoStars("repo")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("DeleteRepoTag Client.GetItem error", func() {
		// 	strSlice := make([]string, 10000)
		// 	repoName := strings.Join(strSlice, ".")

		// 	err = dynamoWrapper.DeleteRepoTag(repoName, "tag")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("DeleteRepoTag unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.DeleteRepoTag("repo", "tag")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("GetRepoMeta Client.GetItem error", func() {
		// 	strSlice := make([]string, 10000)
		// 	repoName := strings.Join(strSlice, ".")

		// 	_, err = dynamoWrapper.GetRepoMeta(repoName)
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("GetRepoMeta unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
		// 	So(err, ShouldBeNil)

		// 	_, err = dynamoWrapper.GetRepoMeta("repo")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("IncrementImageDownloads GetRepoMeta error", func() {
		// 	err = dynamoWrapper.IncrementImageDownloads("repoNotFound", "")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("IncrementImageDownloads tag not found error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.IncrementImageDownloads("repo", "notFoundTag")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("IncrementImageDownloads GetManifestMeta error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.IncrementImageDownloads("repo", "tag")
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("AddManifestSignature GetRepoMeta error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.AddManifestSignature("repoNotFound", "tag", userdb.SignatureMetadata{})
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("AddManifestSignature ManifestSignatures signedManifestDigest not found error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", userdb.SignatureMetadata{})
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("AddManifestSignature SignatureType userdb.NotationType", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag", "dig", "")
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", userdb.SignatureMetadata{
		// 		SignatureType: "notation",
		// 	})
		// 	So(err, ShouldBeNil)
		// })

		// Convey("DeleteSignature GetRepoMeta error", func() {
		// 	err = dynamoWrapper.DeleteSignature("repoNotFound", "tagNotFound", userdb.SignatureMetadata{})
		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("DeleteSignature sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest true", func() {
		// 	err := setRepoMeta(dynamoWrapper.Client, repoMetaTablename, userdb.RepoMetadata{
		// 		Name: "repo",
		// 		Signatures: map[string]userdb.ManifestSignatures{
		// 			"tag1": {
		// 				"cosign": []userdb.SignatureInfo{
		// 					{SignatureManifestDigest: "dig1"},
		// 					{SignatureManifestDigest: "dig2"},
		// 				},
		// 			},
		// 		},
		// 	})
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.DeleteSignature("repo", "tag1", userdb.SignatureMetadata{
		// 		SignatureDigest: "dig2",
		// 		SignatureType:   "cosign",
		// 	})
		// 	So(err, ShouldBeNil)
		// })

		// Convey("GetMultipleRepoMeta unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, err = dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta userdb.RepoMetadata) bool { return true },
		// 		userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchRepos repoMeta unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchRepos(ctx, "", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchRepos GetManifestMeta error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "notFoundDigest", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchRepos(ctx, "", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchRepos config unmarshal error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "dig1", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.SetManifestData("dig1", userdb.ManifestData{ //nolint:contextcheck
		// 		ManifestBlob: []byte("{}"),
		// 		ConfigBlob:   []byte("bad json"),
		// 	})
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchRepos(ctx, "", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchTags repoMeta unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchTags GetManifestMeta error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "manifestNotFound", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("SearchTags config unmarshal error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "dig1", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.SetManifestData( //nolint:contextcheck
		// 		"dig1",
		// 		userdb.ManifestData{
		// 			ManifestBlob: []byte("{}"),
		// 			ConfigBlob:   []byte("bad json"),
		// 		},
		// 	)
		// 	So(err, ShouldBeNil)

		// 	_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", userdb.Filter{}, userdb.PageInput{})

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("FilterTags repoMeta unmarshal error", func() {
		// 	err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, err = dynamoWrapper.FilterTags(
		// 		ctx,
		// 		func(repoMeta userdb.RepoMetadata, manifestMeta userdb.ManifestMetadata) bool {
		// 			return true
		// 		},
		// 		userdb.PageInput{},
		// 	)

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("FilterTags manifestMeta not found", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "manifestNotFound", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, err = dynamoWrapper.FilterTags(
		// 		ctx,
		// 		func(repoMeta userdb.RepoMetadata, manifestMeta userdb.ManifestMetadata) bool {
		// 			return true
		// 		},
		// 		userdb.PageInput{},
		// 	)

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("FilterTags manifestMeta unmarshal error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "dig", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	err = setBadManifestData(dynamoWrapper.Client, manifestDataTablename, "dig") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	_, _, err = dynamoWrapper.FilterTags(
		// 		ctx,
		// 		func(repoMeta userdb.RepoMetadata, manifestMeta userdb.ManifestMetadata) bool {
		// 			return true
		// 		},
		// 		userdb.PageInput{},
		// 	)

		// 	So(err, ShouldNotBeNil)
		// })

		// Convey("FilterTags config unmarshal error", func() {
		// 	err := dynamoWrapper.SetRepoTag("repo", "tag1", "dig1", "") //nolint:contextcheck
		// 	So(err, ShouldBeNil)

		// 	err = dynamoWrapper.SetManifestData("dig1", userdb.ManifestData{ //nolint:contextcheck
		// 		ManifestBlob: []byte("{}"),
		// 		ConfigBlob:   []byte("bad json"),
		// 	})
		// 	So(err, ShouldBeNil)

		// 	_, _, err = dynamoWrapper.FilterTags(
		// 		ctx,
		// 		func(repoMeta userdb.RepoMetadata, manifestMeta userdb.ManifestMetadata) bool {
		// 			return true
		// 		},
		// 		userdb.PageInput{},
		// 	)

		// 	So(err, ShouldNotBeNil)
		// })
	})
}

func setBadAPIKeyInfo(client *dynamodb.Client, apiKeyTablename, hashedKey string) error {
	mdAttributeValue, err := attributevalue.Marshal(&struct {
		field1 int
		field2 int
	}{
		field1: 1,
		field2: 2,
	})
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#EM": "Email",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":Email": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"HashedKey": &types.AttributeValueMemberS{
				Value: hashedKey,
			},
		},
		TableName:        aws.String(apiKeyTablename),
		UpdateExpression: aws.String("SET #EM = :Email"),
	})

	return err
}

func setBadUserProfile(client *dynamodb.Client, userProfileTablename, email string) error {
	mdAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#UP": "UserProfile",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":UserProfile": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{
				Value: email,
			},
		},
		TableName:        aws.String(userProfileTablename),
		UpdateExpression: aws.String("SET #UP = :UserProfile"),
	})

	return err
}

// func setBadRepoMeta(client *dynamodb.Client, repoMetadataTableName, repoName string) error {
// 	repoAttributeValue, err := attributevalue.Marshal("string")
// 	if err != nil {
// 		return err
// 	}

// 	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
// 		ExpressionAttributeNames: map[string]string{
// 			"#RM": "RepoMetadata",
// 		},
// 		ExpressionAttributeValues: map[string]types.AttributeValue{
// 			":RepoMetadata": repoAttributeValue,
// 		},
// 		Key: map[string]types.AttributeValue{
// 			"RepoName": &types.AttributeValueMemberS{
// 				Value: repoName,
// 			},
// 		},
// 		TableName:        aws.String(repoMetadataTableName),
// 		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
// 	})

// 	return err
// }

// func setRepoMeta(client *dynamodb.Client, repoMetadataTableName string, repoMeta userdb.RepoMetadata) error {
// 	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
// 	if err != nil {
// 		return err
// 	}

// 	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
// 		ExpressionAttributeNames: map[string]string{
// 			"#RM": "RepoMetadata",
// 		},
// 		ExpressionAttributeValues: map[string]types.AttributeValue{
// 			":RepoMetadata": repoAttributeValue,
// 		},
// 		Key: map[string]types.AttributeValue{
// 			"RepoName": &types.AttributeValueMemberS{
// 				Value: repoMeta.Name,
// 			},
// 		},
// 		TableName:        aws.String(repoMetadataTableName),
// 		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
// 	})

// 	return err
// }
