package dynamo_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	guuid "github.com/gofrs/uuid"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/dynamo"
	"zotregistry.io/zot/pkg/meta/repodb"
	dynamoWrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test"
)

const badTablename = "bad tablename"

func TestIterator(t *testing.T) {
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	manifestDataTablename := "ManifestDataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	indexDataTablename := "IndexDataTable" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()

	log := log.NewLogger("debug", "")

	Convey("TestIterator", t, func() {
		params := dynamo.DBDriverParameters{
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			APIKeyTablename:       apiKeyTablename,
			UserDataTablename:     userDataTablename,
		}
		client, err := dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetManifestDataTable(), ShouldBeNil)
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo1", "tag1", "manifestType", "manifestDigest1")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo2", "tag2", "manifestType", "manifestDigest2")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo3", "tag3", "manifestType", "manifestDigest3")
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := dynamo.NewBaseDynamoAttributesIterator(
			dynamoWrapper.Client,
			repoMetaTablename,
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

		repoMetaAttributeIterator := dynamo.NewBaseDynamoAttributesIterator(
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
	const (
		endpoint = "http://localhost:4566"
		region   = "us-east-2"
	)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	manifestDataTablename := "ManifestDataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	indexDataTablename := "IndexDataTable" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	wrongTableName := "WRONG Tables"

	log := log.NewLogger("debug", "")

	Convey("Errors", t, func() {
		params := dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err := dynamo.GetDynamoClient(params) //nolint:contextcheck
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamoWrapper.NewDynamoDBWrapper(client, params, log) //nolint:contextcheck
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetManifestDataTable(), ShouldBeNil) //nolint:contextcheck
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)     //nolint:contextcheck

		authzCtxKey := localCtx.GetContextKey()

		acCtx := localCtx.AccessControlContext{
			Username: "test",
		}

		ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

		Convey("SetUserData", func() {
			hashKey := "id"
			apiKeys := make(map[string]repodb.APIKeyDetails)
			apiKeyDetails := repodb.APIKeyDetails{
				Label:  "apiKey",
				Scopes: []string{"repo"},
				UUID:   hashKey,
			}

			apiKeys[hashKey] = apiKeyDetails

			userProfileSrc := repodb.UserData{
				Groups:  []string{"group1", "group2"},
				APIKeys: apiKeys,
			}

			err := dynamoWrapper.SetUserData(ctx, userProfileSrc)
			So(err, ShouldBeNil)

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = dynamoWrapper.SetUserData(ctx, repodb.UserData{}) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData", func() {
			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = dynamoWrapper.DeleteUserData(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo no access", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": false,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo GetUserMeta no user data", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)
			So(status, ShouldEqual, repodb.NotChanged)
		})

		Convey("ToggleBookmarkRepo GetUserMeta client error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			dynamoWrapper.UserDataTablename = badTablename

			status, err := dynamoWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
			So(status, ShouldEqual, repodb.NotChanged)
		})

		Convey("GetBookmarkedRepos", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			repos, err := dynamoWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("ToggleStarRepo GetUserMeta bad context", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "some bad context")

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta no access", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": false,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "unaccesible")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetUserMeta error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": false,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo GetRepoMeta error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			dynamoWrapper.RepoMetaTablename = badTablename

			_, err := dynamoWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			userData, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
			So(userData.BookmarkedRepos, ShouldBeEmpty)
			So(userData.StarredRepos, ShouldBeEmpty)
		})

		Convey("GetUserData client error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			dynamoWrapper.UserDataTablename = badTablename

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserMeta unmarshal error, bad user data", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := setBadUserData(dynamoWrapper.Client, userDataTablename, acCtx.Username)
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, repodb.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.SetUserData(ctx, repodb.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.AddUserAPIKey(ctx, "", &repodb.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			err := dynamoWrapper.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey returns nil", func() {
			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "email",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			apiKeyDetails := make(map[string]repodb.APIKeyDetails)
			apiKeyDetails["id"] = repodb.APIKeyDetails{
				UUID: "id",
			}
			err := dynamoWrapper.SetUserData(ctx, repodb.UserData{
				APIKeys: apiKeyDetails,
			})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.DeleteUserAPIKey(ctx, "id")
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey", func() {
			Convey("no userid found", func() {
				authzCtxKey := localCtx.GetContextKey()

				acCtx := localCtx.AccessControlContext{
					Username: "",
				}

				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				err = dynamoWrapper.AddUserAPIKey(ctx, "key", &repodb.APIKeyDetails{})
				So(err, ShouldNotBeNil)
			})
			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "email",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := dynamoWrapper.AddUserAPIKey(ctx, "key", &repodb.APIKeyDetails{})
			So(err, ShouldBeNil)

			dynamoWrapper.APIKeyTablename = wrongTableName
			err = dynamoWrapper.AddUserAPIKey(ctx, "key", &repodb.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			dynamoWrapper.APIKeyTablename = wrongTableName
			_, err := dynamoWrapper.GetUserAPIKeyInfo("key")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData", func() {
			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)
			_, err := dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			acCtx = localCtx.AccessControlContext{
				Username: "email",
			}

			ctx = context.WithValue(context.Background(), authzCtxKey, acCtx)

			dynamoWrapper.UserDataTablename = wrongTableName
			_, err = dynamoWrapper.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetManifestData", func() {
			dynamoWrapper.ManifestDataTablename = wrongTableName

			err := dynamoWrapper.SetManifestData("dig", repodb.ManifestData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestData", func() {
			dynamoWrapper.ManifestDataTablename = wrongTableName

			_, err := dynamoWrapper.GetManifestData("dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestData unmarshal error", func() {
			err := setBadManifestData(dynamoWrapper.Client, manifestDataTablename, "dig")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestData("dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetIndexData", func() {
			dynamoWrapper.IndexDataTablename = wrongTableName

			_, err := dynamoWrapper.GetIndexData("dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetIndexData unmarshal error", func() {
			err := setBadIndexData(dynamoWrapper.Client, indexDataTablename, "dig")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestData("dig")
			So(err, ShouldNotBeNil)
		})

		Convey("SetManifestMeta GetRepoMeta error", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo1")
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestMeta("repo1", "dig", repodb.ManifestMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetManifestData not found error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestMeta("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetRepoMeta Not Found error", func() {
			err := dynamoWrapper.SetManifestData("dig", repodb.ManifestData{})
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestMeta("repoNotFound", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetRepoMeta error", func() {
			err := dynamoWrapper.SetManifestData("dig", repodb.ManifestData{})
			So(err, ShouldBeNil)

			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestMeta("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("SetRepoReference client error", func() {
			dynamoWrapper.RepoMetaTablename = badTablename
			digest := digest.FromString("str")
			err := dynamoWrapper.SetRepoReference("repo", digest.String(), digest, ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer client error", func() {
			dynamoWrapper.RepoMetaTablename = badTablename
			err := dynamoWrapper.SetReferrer("repo", "", repodb.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer bad repoMeta", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "", repodb.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers client error", func() {
			dynamoWrapper.RepoMetaTablename = badTablename
			_, err := dynamoWrapper.GetReferrers("repo", "")
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrers bad repoMeta", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetReferrers("repo", "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteReferrer client error", func() {
			dynamoWrapper.RepoMetaTablename = badTablename
			err := dynamoWrapper.DeleteReferrer("repo", "", "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteReferrer bad repoMeta", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.DeleteReferrer("repo", "", "")
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrersInfo GetReferrers errors", func() {
			dynamoWrapper.RepoMetaTablename = badTablename
			_, err := dynamoWrapper.GetReferrersInfo("repo", "", nil)
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrersInfo getData fails", func() {
			dynamoWrapper.ManifestDataTablename = badTablename
			err = dynamoWrapper.SetReferrer("repo", "rf", repodb.ReferrerInfo{
				Digest:    "dig1",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", repodb.ReferrerInfo{
				Digest:    "dig2",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			_, err := dynamoWrapper.GetReferrersInfo("repo", "rf", nil)
			So(err, ShouldBeNil)
		})

		Convey("GetReferrersInfo bad descriptor blob", func() {
			err = dynamoWrapper.SetManifestData("dig3", repodb.ManifestData{
				ManifestBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", repodb.ReferrerInfo{
				Digest:    "dig2",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", repodb.ReferrerInfo{
				Digest:    "dig3",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			_, err := dynamoWrapper.GetReferrersInfo("repo", "rf", nil)
			So(err, ShouldBeNil)
		})

		Convey("IncrementRepoStars GetRepoMeta error", func() {
			err = dynamoWrapper.IncrementRepoStars("repo")
			So(err, ShouldNotBeNil)
		})

		Convey("DecrementRepoStars GetRepoMeta error", func() {
			err = dynamoWrapper.DecrementRepoStars("repo")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag Client.GetItem error", func() {
			strSlice := make([]string, 10000)
			repoName := strings.Join(strSlice, ".")

			err = dynamoWrapper.DeleteRepoTag(repoName, "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.DeleteRepoTag("repo", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoMeta Client.GetItem error", func() {
			strSlice := make([]string, 10000)
			repoName := strings.Join(strSlice, ".")

			_, err = dynamoWrapper.GetRepoMeta(repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetRepoMeta("repo")
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementImageDownloads GetRepoMeta error", func() {
			err = dynamoWrapper.IncrementImageDownloads("repoNotFound", "")
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementImageDownloads tag not found error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.IncrementImageDownloads("repo", "notFoundTag")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateSignaturesValidity GetManifestData error", func() {
			err := setBadManifestData(dynamoWrapper.Client, manifestDataTablename, "dig")
			So(err, ShouldBeNil)

			err = dynamoWrapper.UpdateSignaturesValidity("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateSignaturesValidity GetRepoMeta error", func() {
			err := dynamoWrapper.SetManifestData("dig", repodb.ManifestData{})
			So(err, ShouldBeNil)

			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.UpdateSignaturesValidity("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature GetRepoMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repoNotFound", "tag", repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature ManifestSignatures signedManifestDigest not found error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature SignatureType repodb.NotationType", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", repodb.SignatureMetadata{
				SignatureType: "notation",
			})
			So(err, ShouldBeNil)
		})

		Convey("DeleteSignature GetRepoMeta error", func() {
			err = dynamoWrapper.DeleteSignature("repoNotFound", "tagNotFound", repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteSignature sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest true", func() {
			err := setRepoMeta(dynamoWrapper.Client, repoMetaTablename, repodb.RepoMetadata{
				Name: "repo",
				Signatures: map[string]repodb.ManifestSignatures{
					"tag1": {
						"cosign": []repodb.SignatureInfo{
							{SignatureManifestDigest: "dig1"},
							{SignatureManifestDigest: "dig2"},
						},
					},
				},
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.DeleteSignature("repo", "tag1", repodb.SignatureMetadata{
				SignatureDigest: "dig2",
				SignatureType:   "cosign",
			})
			So(err, ShouldBeNil)
		})

		Convey("GetMultipleRepoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta repodb.RepoMetadata) bool { return true },
				repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos GetManifestMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "notFoundDigest", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos config unmarshal error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "dig1", ispec.MediaTypeImageManifest) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData("dig1", repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("Unsuported type", func() {
			digest := digest.FromString("digest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", digest, "invalid type") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(
				ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldBeNil)
		})

		Convey("SearchRepos bad index data", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos good index data, bad manifest inside index", func() {
			var (
				indexDigest              = digest.FromString("indexDigest")
				manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
				manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
			)

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
				manifestDigestFromIndex1, manifestDigestFromIndex2,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex1, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("Bad Manifest"),
				ConfigBlob:   []byte("Bad Manifest"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex2, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("Bad Manifest"),
				ConfigBlob:   []byte("Bad Manifest"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags GetManifestMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "manifestNotFound", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags config unmarshal error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "dig1", ispec.MediaTypeImageManifest) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData( //nolint:contextcheck
				"dig1",
				repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("bad json"),
				},
			)
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags bad index data", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags good index data, bad manifest inside index", func() {
			var (
				indexDigest              = digest.FromString("indexDigest")
				manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
				manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
			)

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
				manifestDigestFromIndex1, manifestDigestFromIndex2,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex1, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("Bad Manifest"),
				ConfigBlob:   []byte("Bad Manifest"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex2, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("Bad Manifest"),
				ConfigBlob:   []byte("Bad Manifest"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos NewBaseRepoPageFinder errors", func() {
			_, _, _, _, err := dynamoWrapper.SearchRepos(ctx, "text", repodb.Filter{}, repodb.PageInput{Offset: -2, Limit: -2})
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos attributevalue.Unmarshal(repoMetaAttribute) errors", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err := dynamoWrapper.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(
				ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
					return true
				},
				repodb.PageInput{},
			)

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags manifestMeta not found", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "manifestNotFound", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(
				ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
					return true
				},
				repodb.PageInput{},
			)

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags manifestMeta unmarshal error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "dig", ispec.MediaTypeImageManifest) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadManifestData(dynamoWrapper.Client, manifestDataTablename, "dig") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(
				ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
					return true
				},
				repodb.PageInput{},
			)

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags didn't match any index manifest", func() {
			var (
				indexDigest              = digest.FromString("indexDigest")
				manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
				manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
			)

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
				manifestDigestFromIndex1, manifestDigestFromIndex2,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, repodb.IndexData{ //nolint:contextcheck
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex1, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex2, repodb.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return false },
				repodb.PageInput{},
			)
			So(err, ShouldBeNil)
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

			err := dynamoWrapper.ResetRepoMetaTable()
			So(err, ShouldNotBeNil)
		})

		Convey("getDBVersion client errors", func() {
			dynamoWrapper.VersionTablename = badTablename

			err := dynamoWrapper.PatchDB()
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta client.GetItem error", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta repoMeta not found", func() {
			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "unknown-repo-meta")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta userMeta not found", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", digest.FromString("1"), ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			dynamoWrapper.UserDataTablename = badTablename

			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}

			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})
	})

	Convey("NewDynamoDBWrapper errors", t, func() {
		params := dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     "",
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err := dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: "",
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    "",
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      "",
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     "",
			APIKeyTablename:       apiKeyTablename,
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)

		params = dynamo.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       "",
		}
		client, err = dynamo.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = dynamoWrapper.NewDynamoDBWrapper(client, params, log)
		So(err, ShouldNotBeNil)
	})
}

func setBadManifestData(client *dynamodb.Client, manifestDataTableName, digest string) error {
	mdAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#MD": "ManifestData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":ManifestData": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"Digest": &types.AttributeValueMemberS{
				Value: digest,
			},
		},
		TableName:        aws.String(manifestDataTableName),
		UpdateExpression: aws.String("SET #MD = :ManifestData"),
	})

	return err
}

func setBadRepoMeta(client *dynamodb.Client, repoMetadataTableName, repoName string) error {
	repoAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repoName,
			},
		},
		TableName:        aws.String(repoMetadataTableName),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}

func setBadIndexData(client *dynamodb.Client, indexDataTableName, digest string) error {
	mdAttributeValue, err := attributevalue.Marshal("string")
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#ID": "IndexData",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":IndexData": mdAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"IndexDigest": &types.AttributeValueMemberS{
				Value: digest,
			},
		},
		TableName:        aws.String(indexDataTableName),
		UpdateExpression: aws.String("SET #ID = :IndexData"),
	})

	return err
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
			"Identity": &types.AttributeValueMemberS{
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
			"VersionKey": &types.AttributeValueMemberS{
				Value: "DBVersion",
			},
		},
		TableName:        aws.String(versionTablename),
		UpdateExpression: aws.String("SET #V = :Version"),
	})

	return err
}

func setRepoMeta(client *dynamodb.Client, repoMetadataTableName string, repoMeta repodb.RepoMetadata) error {
	repoAttributeValue, err := attributevalue.Marshal(repoMeta)
	if err != nil {
		return err
	}

	_, err = client.UpdateItem(context.TODO(), &dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]string{
			"#RM": "RepoMetadata",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":RepoMetadata": repoAttributeValue,
		},
		Key: map[string]types.AttributeValue{
			"RepoName": &types.AttributeValueMemberS{
				Value: repoMeta.Name,
			},
		},
		TableName:        aws.String(repoMetadataTableName),
		UpdateExpression: aws.String("SET #RM = :RepoMetadata"),
	})

	return err
}
