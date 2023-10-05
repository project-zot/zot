package dynamodb_test

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
	manifestDataTablename := "ManifestDataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	indexDataTablename := "IndexDataTable" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()

	log := log.NewLogger("debug", "")

	Convey("TestIterator", t, func() {
		params := mdynamodb.DBDriverParameters{
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			APIKeyTablename:       apiKeyTablename,
			UserDataTablename:     userDataTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log)
		So(err, ShouldBeNil)

		So(dynamoWrapper.ResetManifestDataTable(), ShouldBeNil)
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo1", "tag1", "manifestType", "manifestDigest1")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo2", "tag2", "manifestType", "manifestDigest2")
		So(err, ShouldBeNil)

		err = dynamoWrapper.SetRepoReference("repo3", "tag3", "manifestType", "manifestDigest3")
		So(err, ShouldBeNil)

		repoMetaAttributeIterator := mdynamodb.NewBaseDynamoAttributesIterator(
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
	manifestDataTablename := "ManifestDataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	indexDataTablename := "IndexDataTable" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	wrongTableName := "WRONG Tables"

	log := log.NewLogger("debug", "")

	Convey("Errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params) //nolint:contextcheck
		So(err, ShouldBeNil)

		imgTrustStore, err := imagetrust.NewAWSImageTrustStore(params.Region, params.Endpoint)
		So(err, ShouldBeNil)

		dynamoWrapper, err := mdynamodb.New(client, params, log) //nolint:contextcheck
		So(err, ShouldBeNil)

		dynamoWrapper.SetImageTrustStore(imgTrustStore)

		So(dynamoWrapper.ResetManifestDataTable(), ShouldBeNil) //nolint:contextcheck
		So(dynamoWrapper.ResetRepoMetaTable(), ShouldBeNil)     //nolint:contextcheck

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
			So(status, ShouldEqual, mTypes.NotChanged)
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

		Convey("SetManifestData", func() {
			dynamoWrapper.ManifestDataTablename = wrongTableName

			err := dynamoWrapper.SetManifestData("dig", mTypes.ManifestData{})
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

			err = dynamoWrapper.SetManifestMeta("repo1", "dig", mTypes.ManifestMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetManifestData not found error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestMeta("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetRepoMeta Not Found error", func() {
			err := dynamoWrapper.SetManifestData("dig", mTypes.ManifestData{})
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetManifestMeta("repoNotFound", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("GetManifestMeta GetRepoMeta error", func() {
			err := dynamoWrapper.SetManifestData("dig", mTypes.ManifestData{})
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
			err := dynamoWrapper.SetReferrer("repo", "", mTypes.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer bad repoMeta", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "", mTypes.ReferrerInfo{})
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
			err = dynamoWrapper.SetReferrer("repo", "rf", mTypes.ReferrerInfo{
				Digest:    "dig1",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", mTypes.ReferrerInfo{
				Digest:    "dig2",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			_, err := dynamoWrapper.GetReferrersInfo("repo", "rf", nil)
			So(err, ShouldBeNil)
		})

		Convey("GetReferrersInfo bad descriptor blob", func() {
			err = dynamoWrapper.SetManifestData("dig3", mTypes.ManifestData{
				ManifestBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", mTypes.ReferrerInfo{
				Digest:    "dig2",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetReferrer("repo", "rf", mTypes.ReferrerInfo{
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

			err = dynamoWrapper.UpdateSignaturesValidity("repo", digest.FromString("dig"))
			So(err, ShouldBeNil)
		})

		Convey("UpdateSignaturesValidity GetRepoMeta error", func() {
			err := dynamoWrapper.SetManifestData("dig", mTypes.ManifestData{})
			So(err, ShouldBeNil)

			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			err = dynamoWrapper.UpdateSignaturesValidity("repo", "dig")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature GetRepoMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repoNotFound", "tag", mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature ManifestSignatures signedManifestDigest not found error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature SignatureType metadb.NotationType", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag", "dig", "")
			So(err, ShouldBeNil)

			err = dynamoWrapper.AddManifestSignature("repo", "tagNotFound", mTypes.SignatureMetadata{
				SignatureType: "notation",
			})
			So(err, ShouldBeNil)
		})

		Convey("DeleteSignature GetRepoMeta error", func() {
			err = dynamoWrapper.DeleteSignature("repoNotFound", "tagNotFound", mTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteSignature sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest true", func() {
			err := setRepoMeta(dynamoWrapper.Client, repoMetaTablename, mTypes.RepoMetadata{
				Name: "repo",
				Signatures: map[string]mTypes.ManifestSignatures{
					"tag1": {
						"cosign": []mTypes.SignatureInfo{
							{SignatureManifestDigest: "dig1"},
							{SignatureManifestDigest: "dig2"},
						},
					},
				},
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.DeleteSignature("repo", "tag1", mTypes.SignatureMetadata{
				SignatureDigest: "dig2",
				SignatureType:   "cosign",
			})
			So(err, ShouldBeNil)
		})

		Convey("GetMultipleRepoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, err = dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool { return true })

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos bad tablename", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")

			So(err, ShouldNotBeNil)
		})

		Convey("GetMultipleRepoMeta bad tablename", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, err = dynamoWrapper.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMetadata) bool { return true })

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad tablename", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
					return true
				})

			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos bad tablename", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, _, _, err = dynamoWrapper.FilterRepos(ctx, func(repoMeta mTypes.RepoMetadata) bool { return true })

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags bad tablename", func() {
			dynamoWrapper.RepoMetaTablename = badTablename

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:tag")

			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos GetManifestMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "notFoundDigest", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")

			So(err, ShouldNotBeNil)
		})

		Convey("Unsuported type", func() {
			digest := digest.FromString("digest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", digest, "invalid type") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:")
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true })
			So(err, ShouldBeNil)
		})

		Convey("SearchRepos bad index data", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, mTypes.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchRepos(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:")

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags GetManifestMeta error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "manifestNotFound", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:")

			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags bad index data", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:")
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, mTypes.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.SearchTags(ctx, "repo:")
			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos attr", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err := dynamoWrapper.SearchRepos(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos attributevalue.Unmarshal(repoMetaAttribute) errors", func() {
			dynamoWrapper.RepoMetaTablename = "bad-table-FilterRepos"

			_, _, _, err := dynamoWrapper.FilterRepos(ctx, func(repoMeta mTypes.RepoMetadata) bool {
				return true
			})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchRepos bad RepoMeta table name", func() {
			dynamoWrapper.RepoMetaTablename = "SearchRepos-bad-table"

			_, _, _, err := dynamoWrapper.SearchRepos(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags repoMeta unmarshal error", func() {
			err = setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
					return true
				})

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad RepoMeta table name", func() {
			dynamoWrapper.RepoMetaTablename = "bad-table"

			_, _, _, err := dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
					return true
				})

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags manifestMeta not found", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "manifestNotFound", //nolint:contextcheck
				ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
					return true
				})

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags manifestMeta unmarshal error", func() {
			err := dynamoWrapper.SetRepoReference("repo", "tag1", "dig", ispec.MediaTypeImageManifest) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadManifestData(dynamoWrapper.Client, manifestDataTablename, "dig") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(
				ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
					return true
				})

			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = setBadIndexData(dynamoWrapper.Client, indexDataTablename, indexDigest.String()) //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true })
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags bad indexBlob in IndexData", func() {
			indexDigest := digest.FromString("indexDigest")

			err := dynamoWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, mTypes.IndexData{ //nolint:contextcheck
				IndexBlob: []byte("bad json"),
			})
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return true })
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

			indexBlob, err := GetIndexBlobWithManifests([]digest.Digest{
				manifestDigestFromIndex1, manifestDigestFromIndex2,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetIndexData(indexDigest, mTypes.IndexData{ //nolint:contextcheck
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex1, mTypes.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = dynamoWrapper.SetManifestData(manifestDigestFromIndex2, mTypes.ManifestData{ //nolint:contextcheck
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			_, _, _, err = dynamoWrapper.FilterTags(ctx,
				func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool { return false })
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

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			err := setBadRepoMeta(dynamoWrapper.Client, repoMetaTablename, "repo")
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})
			ctx := userAc.DeriveContext(context.Background())

			_, err = dynamoWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})
	})

	Convey("NewDynamoDBWrapper errors", t, func() {
		params := mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     "",
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err := mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: "",
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    "",
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      versionTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			VersionTablename:      "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     "",
			APIKeyTablename:       apiKeyTablename,
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
		So(err, ShouldNotBeNil)

		params = mdynamodb.DBDriverParameters{ //nolint:contextcheck
			Endpoint:              endpoint,
			Region:                region,
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       "",
		}
		client, err = mdynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		_, err = mdynamodb.New(client, params, log)
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

func setRepoMeta(client *dynamodb.Client, repoMetadataTableName string, repoMeta mTypes.RepoMetadata) error {
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
