package repodb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	guuid "github.com/gofrs/uuid"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/dynamo"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamodb_wrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	"zotregistry.io/zot/pkg/meta/signatures"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test"
)

const (
	LINUX   = "linux"
	WINDOWS = "windows"
	AMD     = "amd"
)

func TestBoltDBWrapper(t *testing.T) {
	Convey("BoltDB Wrapper creation", t, func() {
		boltDBParams := bolt.DBParameters{}
		boltDriver, err := bolt.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
		So(repoDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod("repo.db", 0o200)
		So(err, ShouldBeNil)

		_, err = bolt.GetBoltDriver(boltDBParams)
		So(err, ShouldNotBeNil)

		err = os.Chmod("repo.db", 0o600)
		So(err, ShouldBeNil)

		defer os.Remove("repo.db")
	})

	Convey("BoltDB Wrapper", t, func() {
		boltDBParams := bolt.DBParameters{}
		boltDriver, err := bolt.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
		defer os.Remove("repo.db")
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		RunRepoDBTests(t, boltdbWrapper)
	})
}

func TestDynamoDBWrapper(t *testing.T) {
	skipIt(t)

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

	Convey("DynamoDB Wrapper", t, func() {
		dynamoDBDriverParams := dynamo.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			APIKeyTablename:       apiKeyTablename,
			Region:                "us-east-2",
		}

		dynamoClient, err := dynamo.GetDynamoClient(dynamoDBDriverParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		dynamoDriver, err := dynamodb_wrapper.NewDynamoDBWrapper(dynamoClient, dynamoDBDriverParams, log)
		So(dynamoDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		resetDynamoDBTables := func() error {
			err := dynamoDriver.ResetRepoMetaTable()
			if err != nil {
				return err
			}

			// Note: Tests are very slow if we reset the UserData table every new convey. We'll reset it as needed

			err = dynamoDriver.ResetManifestDataTable()

			return err
		}

		RunRepoDBTests(t, dynamoDriver, resetDynamoDBTables)
	})
}

func RunRepoDBTests(t *testing.T, repoDB repodb.RepoDB, preparationFuncs ...func() error) { //nolint: thelper
	Convey("Test RepoDB Interface implementation", func() {
		for _, prepFunc := range preparationFuncs {
			err := prepFunc()
			So(err, ShouldBeNil)
		}

		Convey("Test CRUD operations on UserData and API keys", func() {
			hashKey1 := "id"
			hashKey2 := "key"
			apiKeys := make(map[string]repodb.APIKeyDetails)
			apiKeyDetails := repodb.APIKeyDetails{
				Label:  "apiKey",
				Scopes: []string{"repo"},
				UUID:   hashKey1,
			}

			apiKeys[hashKey1] = apiKeyDetails

			userProfileSrc := repodb.UserData{
				Groups:  []string{"group1", "group2"},
				APIKeys: apiKeys,
			}

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: "test",
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := repoDB.AddUserAPIKey(ctx, hashKey1, &apiKeyDetails)
			So(err, ShouldBeNil)

			err = repoDB.SetUserData(ctx, userProfileSrc)
			So(err, ShouldBeNil)

			userProfile, err := repoDB.GetUserData(ctx)
			So(err, ShouldBeNil)
			So(userProfile.Groups, ShouldResemble, userProfileSrc.Groups)
			So(userProfile.APIKeys, ShouldContainKey, hashKey1)
			So(userProfile.APIKeys[hashKey1].Label, ShouldEqual, apiKeyDetails.Label)
			So(userProfile.APIKeys[hashKey1].Scopes, ShouldResemble, apiKeyDetails.Scopes)

			lastUsed := userProfile.APIKeys[hashKey1].LastUsed

			err = repoDB.UpdateUserAPIKeyLastUsed(ctx, hashKey1)
			So(err, ShouldBeNil)

			userProfile, err = repoDB.GetUserData(ctx)
			So(err, ShouldBeNil)
			So(userProfile.APIKeys[hashKey1].LastUsed, ShouldHappenAfter, lastUsed)

			userGroups, err := repoDB.GetUserGroups(ctx)
			So(err, ShouldBeNil)
			So(userGroups, ShouldResemble, userProfileSrc.Groups)

			apiKeyDetails.UUID = hashKey2
			err = repoDB.AddUserAPIKey(ctx, hashKey2, &apiKeyDetails)
			So(err, ShouldBeNil)

			userProfile, err = repoDB.GetUserData(ctx)
			So(err, ShouldBeNil)
			So(userProfile.Groups, ShouldResemble, userProfileSrc.Groups)
			So(userProfile.APIKeys, ShouldContainKey, hashKey2)
			So(userProfile.APIKeys[hashKey2].Label, ShouldEqual, apiKeyDetails.Label)
			So(userProfile.APIKeys[hashKey2].Scopes, ShouldResemble, apiKeyDetails.Scopes)

			email, err := repoDB.GetUserAPIKeyInfo(hashKey2)
			So(err, ShouldBeNil)
			So(email, ShouldEqual, "test")

			err = repoDB.DeleteUserAPIKey(ctx, hashKey1)
			So(err, ShouldBeNil)

			userProfile, err = repoDB.GetUserData(ctx)
			So(err, ShouldBeNil)
			So(len(userProfile.APIKeys), ShouldEqual, 1)
			So(userProfile.APIKeys, ShouldNotContainKey, hashKey1)

			err = repoDB.DeleteUserAPIKey(ctx, hashKey2)
			So(err, ShouldBeNil)

			userProfile, err = repoDB.GetUserData(ctx)
			So(err, ShouldBeNil)
			So(len(userProfile.APIKeys), ShouldEqual, 0)
			So(userProfile.APIKeys, ShouldNotContainKey, hashKey2)

			// delete non existent api key
			err = repoDB.DeleteUserAPIKey(ctx, hashKey2)
			So(err, ShouldBeNil)

			err = repoDB.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			email, err = repoDB.GetUserAPIKeyInfo(hashKey2)
			So(err, ShouldNotBeNil)
			So(email, ShouldBeEmpty)

			email, err = repoDB.GetUserAPIKeyInfo(hashKey1)
			So(err, ShouldNotBeNil)
			So(email, ShouldBeEmpty)

			_, err = repoDB.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			userGroups, err = repoDB.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)
			So(userGroups, ShouldBeEmpty)

			err = repoDB.SetUserGroups(ctx, userProfileSrc.Groups)
			So(err, ShouldBeNil)

			userGroups, err = repoDB.GetUserGroups(ctx)
			So(err, ShouldBeNil)
			So(userGroups, ShouldResemble, userProfileSrc.Groups)
		})

		Convey("Test SetManifestData and GetManifestData", func() {
			configBlob, manifestBlob, err := generateTestImage()
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob)

			err = repoDB.SetManifestData(manifestDigest, repodb.ManifestData{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			mm, err := repoDB.GetManifestData(manifestDigest)
			So(err, ShouldBeNil)
			So(mm.ManifestBlob, ShouldResemble, manifestBlob)
			So(mm.ConfigBlob, ShouldResemble, configBlob)
		})

		Convey("Test GetManifestMeta fails", func() {
			_, err := repoDB.GetManifestMeta("repo", "bad digest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test SetManifestMeta", func() {
			Convey("RepoMeta not found", func() {
				var (
					manifestDigest = godigest.FromString("dig")
					manifestBlob   = []byte("manifestBlob")
					configBlob     = []byte("configBlob")

					signatures = repodb.ManifestSignatures{
						"digest1": []repodb.SignatureInfo{
							{
								SignatureManifestDigest: "signatureDigest",
								LayersInfo: []repodb.LayerInfo{
									{
										LayerDigest:  "layerDigest",
										LayerContent: []byte("layerContent"),
									},
								},
							},
						},
					}
				)

				err := repoDB.SetManifestMeta("repo", manifestDigest, repodb.ManifestMetadata{
					ManifestBlob:  manifestBlob,
					ConfigBlob:    configBlob,
					DownloadCount: 10,
					Signatures:    signatures,
				})
				So(err, ShouldBeNil)

				manifestMeta, err := repoDB.GetManifestMeta("repo", manifestDigest)
				So(err, ShouldBeNil)

				So(manifestMeta.ManifestBlob, ShouldResemble, manifestBlob)
				So(manifestMeta.ConfigBlob, ShouldResemble, configBlob)
				So(manifestMeta.DownloadCount, ShouldEqual, 10)
				So(manifestMeta.Signatures, ShouldResemble, signatures)
			})
		})

		Convey("Test SetRepoReference", func() {
			// test behaviours
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")

				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifes2")
			)

			Convey("Setting a good repo", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)

				err = repoDB.SetRepoMeta(repo2, repodb.RepoMetadata{Tags: map[string]repodb.Descriptor{
					tag2: {
						Digest: manifestDigest2.String(),
					},
				}})
				So(err, ShouldBeNil)

				repoMeta, err = repoDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo2)
				So(repoMeta.Tags[tag2].Digest, ShouldEqual, manifestDigest2)
			})

			Convey("Setting a good repo using a digest", func() {
				_, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldNotBeNil)

				digest := godigest.FromString("digest")
				err = repoDB.SetRepoReference(repo1, digest.String(), digest,
					ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
			})

			Convey("Set multiple tags for repo", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)
				So(repoMeta.Tags[tag2].Digest, ShouldEqual, manifestDigest2)
			})

			Convey("Set multiple repos", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta1, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				repoMeta2, err := repoDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)

				So(repoMeta1.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())
				So(repoMeta2.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Setting a repo with invalid fields", func() {
				Convey("Repo name is not valid", func() {
					err := repoDB.SetRepoReference("", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Tag is not valid", func() {
					err := repoDB.SetRepoReference(repo1, "", manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Manifest Digest is not valid", func() {
					err := repoDB.SetRepoReference(repo1, tag1, "", ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("Test GetRepoMeta", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")

				repo2           = "repo2"
				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifest2")

				InexistentRepo = "InexistentRepo"
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Get a existent repo", func() {
				repoMeta1, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta1.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())

				repoMeta2, err := repoDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)
				So(repoMeta2.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Get a repo that doesn't exist", func() {
				repoMeta, err := repoDB.GetRepoMeta(InexistentRepo)
				So(err, ShouldNotBeNil)
				So(repoMeta, ShouldBeZeroValue)
			})
		})

		Convey("Test DeleteRepoTag", func() {
			var (
				repo            = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifest2")
			)

			err := repoDB.SetRepoReference(repo, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Delete from repo a tag", func() {
				_, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				err = repoDB.DeleteRepoTag(repo, tag1)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				_, ok := repoMeta.Tags[tag1]
				So(ok, ShouldBeFalse)
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Delete inexistent tag from repo", func() {
				err := repoDB.DeleteRepoTag(repo, "InexistentTag")
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Delete from inexistent repo", func() {
				err := repoDB.DeleteRepoTag("InexistentRepo", "InexistentTag")
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})
		})

		Convey("Test GetMultipleRepoMeta", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifest2")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Get all Repometa", func() {
				repoMetaSlice, err := repoDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta repodb.RepoMetadata) bool {
					return true
				}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 2)
			})

			Convey("Get repo with a tag", func() {
				repoMetaSlice, err := repoDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta repodb.RepoMetadata) bool {
					for tag := range repoMeta.Tags {
						if tag == tag1 {
							return true
						}
					}

					return false
				}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 1)
				So(repoMetaSlice[0].Tags[tag1].Digest == manifestDigest1.String(), ShouldBeTrue)
			})

			Convey("Wrong page input", func() {
				repoMetaSlice, err := repoDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta repodb.RepoMetadata) bool {
					for tag := range repoMeta.Tags {
						if tag == tag1 {
							return true
						}
					}

					return false
				}, repodb.PageInput{Limit: -1, Offset: -1})

				So(err, ShouldNotBeNil)
				So(len(repoMetaSlice), ShouldEqual, 0)
			})
		})

		Convey("Test IncrementRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 2)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 3)
		})

		Convey("Test DecrementRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			err = repoDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 0)

			err = repoDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 0)

			_, err = repoDB.GetRepoMeta("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			stars, err := repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(stars, ShouldEqual, 1)

			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)
			err = repoDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			stars, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(stars, ShouldEqual, 3)

			_, err = repoDB.GetRepoStars("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test repo stars for user", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				repo2           = "repo2"
			)

			authzCtxKey := localCtx.GetContextKey()

			acCtx1 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "user1",
			}

			// "user1"
			ctx1 := context.WithValue(context.Background(), authzCtxKey, acCtx1)

			acCtx2 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "user2",
			}

			// "user2"
			ctx2 := context.WithValue(context.Background(), authzCtxKey, acCtx2)

			acCtx3 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "",
			}

			// anonymous
			ctx3 := context.WithValue(context.Background(), authzCtxKey, acCtx3)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			starCount, err := repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

			starCount, err = repoDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

			repos, err := repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 bookmarks repo 1, User 2 has no stars
			toggleState, err := repoDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 and User 2 star only repo 1
			toggleState, err = repoDB.ToggleStarRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 2)

			starCount, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 2)

			repos, err = repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars repos 1 and 2, and User 2 stars only repo 1
			toggleState, err = repoDB.ToggleStarRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repoMeta, err = repoDB.GetRepoMeta(repo2)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = repoDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars only repo 2, and User 2 stars only repo 1
			toggleState, err = repoDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Removed)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars both repos 1 and 2, and User 2 removes all stars
			toggleState, err = repoDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			toggleState, err = repoDB.ToggleStarRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Removed)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			repoMeta, err = repoDB.GetRepoMeta(repo2)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			starCount, err = repoDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = repoDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// Anonyous user attempts to toggle a star
			toggleState, err = repoDB.ToggleStarRepo(ctx3, repo1)
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, repodb.NotChanged)

			starCount, err = repoDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars just repo 1
			toggleState, err = repoDB.ToggleStarRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Removed)

			starCount, err = repoDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

			repos, err = repoDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("Test repo bookmarks for user", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				repo2           = "repo2"
			)

			authzCtxKey := localCtx.GetContextKey()

			acCtx1 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "user1",
			}

			// "user1"
			ctx1 := context.WithValue(context.Background(), authzCtxKey, acCtx1)

			acCtx2 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "user2",
			}

			// "user2"
			ctx2 := context.WithValue(context.Background(), authzCtxKey, acCtx2)

			acCtx3 := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo1: true,
					repo2: true,
				},
				Username: "",
			}

			// anonymous
			ctx3 := context.WithValue(context.Background(), authzCtxKey, acCtx3)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			repos, err := repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// anonymous cannot use bookmarks
			repos, err = repoDB.GetBookmarkedRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			toggleState, err := repoDB.ToggleBookmarkRepo(ctx3, repo1)
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, repodb.NotChanged)

			repos, err = repoDB.GetBookmarkedRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 bookmarks repo 1, User 2 has no bookmarks
			toggleState, err = repoDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repos, err = repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 and User 2 bookmark only repo 1
			toggleState, err = repoDB.ToggleBookmarkRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repos, err = repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks repos 1 and 2, and User 2 bookmarks only repo 1
			toggleState, err = repoDB.ToggleBookmarkRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			repos, err = repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks only repo 2, and User 2 bookmarks only repo 1
			toggleState, err = repoDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Removed)

			repos, err = repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks both repos 1 and 2, and User 2 removes all bookmarks
			toggleState, err = repoDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Added)

			toggleState, err = repoDB.ToggleBookmarkRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, repodb.Removed)

			repos, err = repoDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = repoDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("Test IncrementImageDownloads", func() {
			var (
				repo1 = "repo1"
				tag1  = "0.0.1"
			)

			configBlob, manifestBlob, err := generateTestImage()
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob)

			err = repoDB.SetRepoReference(repo1, tag1, manifestDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest, repodb.ManifestMetadata{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			err = repoDB.IncrementImageDownloads(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 1)

			err = repoDB.IncrementImageDownloads(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 2)

			_, err = repoDB.GetManifestMeta(repo1, "badManiestDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test AddImageSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{})
			So(err, ShouldBeNil)

			err = repoDB.AddManifestSignature(repo1, manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			_, err = repoDB.GetManifestMeta(repo1, "badDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test UpdateSignaturesValidity", func() {
			Convey("untrusted signature", func() {
				var (
					repo1           = "repo1"
					tag1            = "0.0.1"
					manifestDigest1 = godigest.FromString("dig")
				)

				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				layerInfo := repodb.LayerInfo{LayerDigest: "", LayerContent: []byte{}, SignatureKey: ""}

				err = repoDB.AddManifestSignature(repo1, manifestDigest1, repodb.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: string(manifestDigest1),
					LayersInfo:      []repodb.LayerInfo{layerInfo},
				})
				So(err, ShouldBeNil)

				err = repoDB.UpdateSignaturesValidity(repo1, manifestDigest1)
				So(err, ShouldBeNil)

				repoData, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoData.Signatures[string(manifestDigest1)]["cosign"][0].LayersInfo[0].Signer,
					ShouldBeEmpty)
				So(repoData.Signatures[string(manifestDigest1)]["cosign"][0].LayersInfo[0].Date,
					ShouldBeZeroValue)
			})

			Convey("trusted signature", func() {
				_, _, manifest, _ := test.GetRandomImageComponents(10)
				manifestContent, _ := json.Marshal(manifest)
				manifestDigest := godigest.FromBytes(manifestContent)
				repo := "repo"
				tag := "0.0.1"

				err := repoDB.SetRepoReference(repo, tag, manifestDigest, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo, manifestDigest, repodb.ManifestMetadata{
					ManifestBlob: manifestContent,
					ConfigBlob:   []byte("configContent"),
				})
				So(err, ShouldBeNil)

				mediaType := jws.MediaTypeEnvelope

				signOpts := notation.SignerSignOptions{
					SignatureMediaType: mediaType,
					PluginConfig:       map[string]string{},
					ExpiryDuration:     24 * time.Hour,
				}

				tdir := t.TempDir()
				keyName := "notation-sign-test"

				test.NotationPathLock.Lock()
				defer test.NotationPathLock.Unlock()

				test.LoadNotationPath(tdir)

				err = test.GenerateNotationCerts(tdir, keyName)
				So(err, ShouldBeNil)

				// getSigner
				var newSigner notation.Signer

				// ResolveKey
				signingKeys, err := test.LoadNotationSigningkeys(tdir)
				So(err, ShouldBeNil)

				idx := test.Index(signingKeys.Keys, keyName)
				So(idx, ShouldBeGreaterThanOrEqualTo, 0)

				key := signingKeys.Keys[idx]

				if key.X509KeyPair != nil {
					newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
					So(err, ShouldBeNil)
				}

				descToSign := ispec.Descriptor{
					MediaType: manifest.MediaType,
					Digest:    manifestDigest,
					Size:      int64(len(manifestContent)),
				}

				ctx := context.Background()

				sig, _, err := newSigner.Sign(ctx, descToSign, signOpts)
				So(err, ShouldBeNil)

				layerInfo := repodb.LayerInfo{
					LayerDigest:  string(godigest.FromBytes(sig)),
					LayerContent: sig, SignatureKey: mediaType,
				}

				err = repoDB.AddManifestSignature(repo, manifestDigest, repodb.SignatureMetadata{
					SignatureType:   "notation",
					SignatureDigest: string(godigest.FromString("signature digest")),
					LayersInfo:      []repodb.LayerInfo{layerInfo},
				})
				So(err, ShouldBeNil)

				err = signatures.InitNotationDir(tdir)
				So(err, ShouldBeNil)

				trustpolicyPath := path.Join(tdir, "_notation/trustpolicy.json")

				trustPolicy := `
					{
						"version": "1.0",
						"trustPolicies": [
							{
								"name": "notation-sign-test",
								"registryScopes": [ "*" ],
								"signatureVerification": {
									"level" : "strict" 
								},
								"trustStores": ["ca:notation-sign-test"],
								"trustedIdentities": [
									"*"
								]
							}
						]
					}`

				file, err := os.Create(trustpolicyPath)
				So(err, ShouldBeNil)

				defer file.Close()

				_, err = file.WriteString(trustPolicy)
				So(err, ShouldBeNil)

				truststore := "_notation/truststore/x509/ca/notation-sign-test"
				truststoreSrc := "notation/truststore/x509/ca/notation-sign-test"
				err = os.MkdirAll(path.Join(tdir, truststore), 0o755)
				So(err, ShouldBeNil)

				err = test.CopyFile(path.Join(tdir, truststoreSrc, "notation-sign-test.crt"),
					path.Join(tdir, truststore, "notation-sign-test.crt"))
				So(err, ShouldBeNil)

				err = repoDB.UpdateSignaturesValidity(repo, manifestDigest) //nolint:contextcheck
				So(err, ShouldBeNil)

				repoData, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)
				So(repoData.Signatures[string(manifestDigest)]["notation"][0].LayersInfo[0].Signer,
					ShouldNotBeEmpty)
				So(repoData.Signatures[string(manifestDigest)]["notation"][0].LayersInfo[0].Date,
					ShouldNotBeZeroValue)
			})
		})

		Convey("Test AddImageSignature with inverted order", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.AddManifestSignature(repo1, manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestData(manifestDigest1, repodb.ManifestData{})
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			_, err = repoDB.GetManifestMeta(repo1, "badDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test DeleteSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestData(manifestDigest1, repodb.ManifestData{})
			So(err, ShouldBeNil)

			err = repoDB.AddManifestSignature(repo1, manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			err = repoDB.DeleteSignature(repo1, manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"], ShouldBeEmpty)

			err = repoDB.DeleteSignature(repo1, "badDigest", repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Test SearchRepos", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				repo3           = "repo3"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifest2")
				tag3            = "0.0.3"
				manifestDigest3 = godigest.FromString("fake-manifest3")
				ctx             = context.Background()
				emptyManifest   ispec.Manifest
				emptyConfig     ispec.Manifest
			)
			emptyManifestBlob, err := json.Marshal(emptyManifest)
			So(err, ShouldBeNil)

			emptyConfigBlob, err := json.Marshal(emptyConfig)
			So(err, ShouldBeNil)

			emptyRepoMeta := repodb.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			Convey("Search all repos", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(len(manifestMetaMap), ShouldEqual, 3)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
			})

			Convey("Search a repo by name", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := repoDB.SearchRepos(ctx, repo1, repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(manifestMetaMap), ShouldEqual, 1)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("Search non-existing repo by name", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := repoDB.SearchRepos(ctx, "RepoThatDoesntExist", repodb.Filter{},
					repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
			})

			Convey("Search with partial match", func() {
				err := repoDB.SetRepoReference("alpine", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference("pine", tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference("golang", tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta("alpine", manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta("pine", manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta("golang", manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := repoDB.SearchRepos(ctx, "pine", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldNotContainKey, manifestDigest3.String())
			})

			Convey("Search multiple repos that share manifests", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo3, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 3)
				So(len(manifestMetaMap), ShouldEqual, 1)
			})

			Convey("Search repos with access control", func() {
				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo3, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				acCtx := localCtx.AccessControlContext{
					ReadGlobPatterns: map[string]bool{
						repo1: true,
						repo2: true,
					},
					Username: "username",
				}
				authzCtxKey := localCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				repos, _, _, _, err := repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				for _, k := range repos {
					So(k.Name, ShouldBeIn, []string{repo1, repo2})
				}
			})

			Convey("Search paginated repos", func() {
				reposCount := 50
				repoNameBuilder := strings.Builder{}

				for _, i := range rand.Perm(reposCount) {
					manifestDigest := godigest.FromString("fakeManifest" + strconv.Itoa(i))
					timeString := fmt.Sprintf("1%02d0-01-01 04:35", i)
					createdTime, err := time.Parse("2006-01-02 15:04", timeString)
					So(err, ShouldBeNil)

					configContent := ispec.Image{
						History: []ispec.History{
							{
								Created: &createdTime,
							},
						},
					}

					configBlob, err := json.Marshal(configContent)
					So(err, ShouldBeNil)

					manifestMeta := repodb.ManifestMetadata{
						ManifestBlob:  emptyManifestBlob,
						ConfigBlob:    configBlob,
						DownloadCount: i,
					}
					repoName := "repo" + strconv.Itoa(i)

					err = repoDB.SetRepoReference(repoName, tag1, manifestDigest, ispec.MediaTypeImageManifest)
					So(err, ShouldBeNil)

					err = repoDB.SetManifestMeta(repoName, manifestDigest, manifestMeta)
					So(err, ShouldBeNil)

					repoNameBuilder.Reset()
				}

				repos, _, _, _, err := repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, reposCount)

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  20,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 20)

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo1")

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				// sort by downloads
				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.Downloads,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				// sort by last update
				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				repos, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(repos, ShouldBeEmpty)
			})

			Convey("Search with wrong pagination input", func() {
				_, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  -1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: -1,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: repodb.SortCriteria("InvalidSortingCriteria"),
				})
				So(err, ShouldNotBeNil)
			})

			Convey("Search Repos with Indexes", func() {
				var (
					tag4            = "0.0.4"
					indexDigest     = godigest.FromString("Multiarch")
					manifestDigest1 = godigest.FromString("manifestDigest1")
					manifestDigest2 = godigest.FromString("manifestDigest2")

					tag5            = "0.0.5"
					manifestDigest3 = godigest.FromString("manifestDigest3")
				)

				err := repoDB.SetManifestData(manifestDigest1, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				config := ispec.Image{
					Platform: ispec.Platform{
						Architecture: "arch",
						OS:           "os",
					},
				}

				confBlob, err := json.Marshal(config)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestData(manifestDigest2, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   confBlob,
				})
				So(err, ShouldBeNil)
				err = repoDB.SetManifestData(manifestDigest3, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				indexContent := ispec.Index{
					MediaType: ispec.MediaTypeImageIndex,
					Manifests: []ispec.Descriptor{
						{
							Digest: manifestDigest1,
						},
						{
							Digest: manifestDigest2,
						},
					},
				}

				indexBlob, err := json.Marshal(indexContent)
				So(err, ShouldBeNil)

				err = repoDB.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference("repo", tag4, indexDigest, ispec.MediaTypeImageIndex)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference("repo", tag5, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, indexDataMap, _, err := repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)

				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo")
				So(repos[0].Tags, ShouldContainKey, tag4)
				So(repos[0].Tags, ShouldContainKey, tag5)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
				So(indexDataMap, ShouldContainKey, indexDigest.String())
			})
		})

		Convey("Test SearchTags", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				manifestDigest2 = godigest.FromString("fake-manifest2")
				manifestDigest3 = godigest.FromString("fake-manifest3")
				ctx             = context.Background()
				emptyManifest   ispec.Manifest
				emptyConfig     ispec.Manifest
			)

			emptyManifestBlob, err := json.Marshal(emptyManifest)
			So(err, ShouldBeNil)

			emptyConfigBlob, err := json.Marshal(emptyConfig)
			So(err, ShouldBeNil)

			emptyRepoMeta := repodb.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = repoDB.SetRepoReference(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo2, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			Convey("With exact match", func() {
				repos, manifestMetaMap, _, _, err := repoDB.SearchTags(ctx, "repo1:0.0.1", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("With partial repo path", func() {
				repos, manifestMetaMap, _, _, err := repoDB.SearchTags(ctx, "repo:0.0.1", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
			})

			Convey("With partial tag", func() {
				repos, manifestMetaMap, _, _, err := repoDB.SearchTags(ctx, "repo1:0.0", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 2)
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())

				repos, manifestMetaMap, _, _, err = repoDB.SearchTags(ctx, "repo1:0.", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 3)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
			})

			Convey("With bad query", func() {
				repos, manifestMetaMap, _, _, err := repoDB.SearchTags(ctx, "repo:0.0.1:test", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
			})

			Convey("Search with access control", func() {
				var (
					repo1           = "repo1"
					repo2           = "repo2"
					repo3           = "repo3"
					tag1            = "0.0.1"
					manifestDigest1 = godigest.FromString("fake-manifest1")
					tag2            = "0.0.2"
					tag3            = "0.0.3"
				)

				err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				config := ispec.Image{}
				configBlob, err := json.Marshal(config)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob})
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo2, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob})
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo3, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob})
				So(err, ShouldBeNil)

				acCtx := localCtx.AccessControlContext{
					ReadGlobPatterns: map[string]bool{
						repo1: true,
						repo2: false,
					},
					Username: "username",
				}
				authzCtxKey := localCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				repos, _, _, _, err := repoDB.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, repo1)

				repos, _, _, _, err = repoDB.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(repos, ShouldBeEmpty)
			})

			Convey("With wrong pagination input", func() {
				repos, _, _, _, err := repoDB.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{
					Limit: -1,
				})
				So(err, ShouldNotBeNil)
				So(repos, ShouldBeEmpty)
			})

			Convey("Search Tags with Indexes", func() {
				var (
					tag4            = "0.0.4"
					indexDigest     = godigest.FromString("Multiarch")
					manifestDigest1 = godigest.FromString("manifestDigest1")
					manifestDigest2 = godigest.FromString("manifestDigest2")

					tag5            = "0.0.5"
					manifestDigest3 = godigest.FromString("manifestDigest3")

					tag6            = "6.0.0"
					manifestDigest4 = godigest.FromString("manifestDigest4")
				)

				err := repoDB.SetManifestData(manifestDigest1, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				config := ispec.Image{
					Platform: ispec.Platform{
						Architecture: "arch",
						OS:           "os",
					},
				}

				confBlob, err := json.Marshal(config)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestData(manifestDigest2, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   confBlob,
				})
				So(err, ShouldBeNil)
				err = repoDB.SetManifestData(manifestDigest3, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = repoDB.SetManifestData(manifestDigest4, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests(
					[]godigest.Digest{
						manifestDigest1,
						manifestDigest2,
					},
				)
				So(err, ShouldBeNil)

				err = repoDB.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference("repo", tag4, indexDigest, ispec.MediaTypeImageIndex)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference("repo", tag5, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoReference("repo", tag6, manifestDigest4, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, indexDataMap, _, err := repoDB.SearchTags(ctx, "repo:0.0", repodb.Filter{},
					repodb.PageInput{})
				So(err, ShouldBeNil)

				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo")
				So(repos[0].Tags, ShouldContainKey, tag4)
				So(repos[0].Tags, ShouldContainKey, tag5)
				So(repos[0].Tags, ShouldNotContainKey, tag6)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
				So(manifestMetaMap, ShouldNotContainKey, manifestDigest4.String())
				So(indexDataMap, ShouldContainKey, indexDigest.String())
			})
		})

		Convey("Paginated tag search", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				tag3            = "0.0.3"
				tag4            = "0.0.4"
				tag5            = "0.0.5"
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag4, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag5, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			config := ispec.Image{}
			configBlob, err := json.Marshal(config)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob})
			So(err, ShouldBeNil)

			repos, _, _, _, err := repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
				Limit:  1,
				Offset: 0,
				SortBy: repodb.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			keys := make([]string, 0, len(repos[0].Tags))
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
				Limit:  1,
				Offset: 1,
				SortBy: repodb.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
				Limit:  1,
				Offset: 2,
				SortBy: repodb.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			So(keys, ShouldContain, tag1)
			So(keys, ShouldContain, tag2)
			So(keys, ShouldContain, tag3)
		})

		Convey("Test repo search with filtering", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				repo3           = "repo3"
				repo4           = "repo4"
				tag1            = "0.0.1"
				tag2            = "0.0.2"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				manifestDigest2 = godigest.FromString("fake-manifest2")
				manifestDigest3 = godigest.FromString("fake-manifest3")
			)

			err := repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			config1 := ispec.Image{
				Platform: ispec.Platform{
					Architecture: AMD,
					OS:           LINUX,
				},
			}
			configBlob1, err := json.Marshal(config1)
			So(err, ShouldBeNil)

			config2 := ispec.Image{
				Platform: ispec.Platform{
					Architecture: "arch",
					OS:           WINDOWS,
				},
			}
			configBlob2, err := json.Marshal(config2)
			So(err, ShouldBeNil)

			config3 := ispec.Image{}
			configBlob3, err := json.Marshal(config3)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest2, repodb.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo2, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo3, manifestDigest2, repodb.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo4, manifestDigest3, repodb.ManifestMetadata{ConfigBlob: configBlob3})
			So(err, ShouldBeNil)

			opSys := LINUX
			arch := ""
			filter := repodb.Filter{
				Os: []*string{&opSys},
			}

			repos, _, _, _, err := repoDB.SearchRepos(context.TODO(), "", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo2")

			opSys = WINDOWS
			filter = repodb.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo3")

			opSys = "wrong"
			filter = repodb.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			opSys = LINUX
			arch = AMD
			filter = repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo2")

			opSys = WINDOWS
			arch = AMD
			filter = repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
		})

		Convey("Test tags search with filtering", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				repo3           = "repo3"
				repo4           = "repo4"
				tag1            = "0.0.1"
				tag2            = "0.0.2"
				tag3            = "0.0.3"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				manifestDigest2 = godigest.FromString("fake-manifest2")
				manifestDigest3 = godigest.FromString("fake-manifest3")

				indexDigest              = godigest.FromString("index-digest")
				manifestFromIndexDigest1 = godigest.FromString("fake-manifestFromIndexDigest1")
				manifestFromIndexDigest2 = godigest.FromString("fake-manifestFromIndexDigest2")
			)

			err := repoDB.SetRepoReference(repo1, tag3, indexDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests(
				[]godigest.Digest{
					manifestFromIndexDigest1,
					manifestFromIndexDigest2,
				},
			)
			So(err, ShouldBeNil)

			err = repoDB.SetIndexData(indexDigest, repodb.IndexData{
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			config1 := ispec.Image{
				Platform: ispec.Platform{
					Architecture: AMD,
					OS:           LINUX,
				},
			}
			configBlob1, err := json.Marshal(config1)
			So(err, ShouldBeNil)

			config2 := ispec.Image{
				Platform: ispec.Platform{
					Architecture: "arch",
					OS:           WINDOWS,
				},
			}
			configBlob2, err := json.Marshal(config2)
			So(err, ShouldBeNil)

			config3 := ispec.Image{}
			configBlob3, err := json.Marshal(config3)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest2, repodb.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo2, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo3, manifestDigest2, repodb.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo4, manifestDigest3, repodb.ManifestMetadata{ConfigBlob: configBlob3})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestFromIndexDigest1,
				repodb.ManifestMetadata{ConfigBlob: []byte("{}")})
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestFromIndexDigest2,
				repodb.ManifestMetadata{ConfigBlob: []byte("{}")})
			So(err, ShouldBeNil)

			opSys := LINUX
			arch := AMD
			filter := repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err := repoDB.SearchTags(context.TODO(), "repo1:", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos[0].Tags, ShouldContainKey, tag1)

			opSys = LINUX
			arch = "badArch"
			filter = repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("Test FilterTags", func() {
			var (
				repo1                    = "repo1"
				repo2                    = "repo2"
				manifestDigest1          = godigest.FromString("fake-manifest1")
				manifestDigest2          = godigest.FromString("fake-manifest2")
				manifestDigest3          = godigest.FromString("fake-manifest3")
				indexDigest              = godigest.FromString("index-digest")
				manifestFromIndexDigest1 = godigest.FromString("fake-manifestFromIndexDigest1")
				manifestFromIndexDigest2 = godigest.FromString("fake-manifestFromIndexDigest2")

				emptyManifest ispec.Manifest
				emptyConfig   ispec.Image
				ctx           = context.Background()
			)

			emptyManifestBlob, err := json.Marshal(emptyManifest)
			So(err, ShouldBeNil)

			emptyConfigBlob, err := json.Marshal(emptyConfig)
			So(err, ShouldBeNil)

			emptyManifestMeta := repodb.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			emptyManifestData := repodb.ManifestData{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = repoDB.SetRepoReference(repo1, "2.0.0", indexDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests([]godigest.Digest{
				manifestFromIndexDigest1,
				manifestFromIndexDigest2,
			})
			So(err, ShouldBeNil)

			err = repoDB.SetIndexData(indexDigest, repodb.IndexData{
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest3, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo2, manifestDigest3, emptyManifestMeta)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestData(manifestFromIndexDigest1, emptyManifestData)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestData(manifestFromIndexDigest2, emptyManifestData)
			So(err, ShouldBeNil)

			Convey("Return all tags", func() {
				repos, manifestMetaMap, indexDataMap, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return true
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(repos[0].Name, ShouldEqual, "repo1")
				So(repos[1].Name, ShouldEqual, "repo2")
				So(len(repos[0].Tags), ShouldEqual, 6)
				So(len(repos[1].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.1")
				So(repos[0].Tags, ShouldContainKey, "2.0.0")
				So(repos[1].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
				So(indexDataMap, ShouldContainKey, indexDigest.String())
				So(manifestMetaMap, ShouldContainKey, manifestFromIndexDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestFromIndexDigest2.String())
				So(pageInfo.ItemCount, ShouldEqual, 7)
				So(pageInfo.TotalCount, ShouldEqual, 7)
			})

			Convey("Return all tags in a specific repo", func() {
				repos, manifestMetaMap, indexDataMap, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return repoMeta.Name == repo1
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldEqual, repo1)
				So(len(repos[0].Tags), ShouldEqual, 6)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.1")
				So(repos[0].Tags, ShouldContainKey, "2.0.0")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
				So(indexDataMap, ShouldContainKey, indexDigest.String())
				So(manifestMetaMap, ShouldContainKey, manifestFromIndexDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestFromIndexDigest2.String())
				So(pageInfo.ItemCount, ShouldEqual, 6)
				So(pageInfo.TotalCount, ShouldEqual, 6)
			})

			Convey("Filter everything out", func() {
				repos, manifestMetaMap, _, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return false
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
				So(pageInfo.ItemCount, ShouldEqual, 0)
				So(pageInfo.TotalCount, ShouldEqual, 0)
			})

			Convey("Search with access control", func() {
				acCtx := localCtx.AccessControlContext{
					ReadGlobPatterns: map[string]bool{
						repo1: false,
						repo2: true,
					},
					Username: "username",
				}

				authzCtxKey := localCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				repos, manifestMetaMap, _, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return true
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, repo2)
				So(len(repos[0].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
				So(pageInfo.ItemCount, ShouldEqual, 1)
				So(pageInfo.TotalCount, ShouldEqual, 1)
			})

			Convey("With wrong pagination input", func() {
				repos, _, _, _, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return true
					},
					repodb.PageInput{Limit: -1},
				)
				So(err, ShouldNotBeNil)
				So(repos, ShouldBeEmpty)
			})
		})

		Convey("Test index logic", func() {
			multiArch, err := test.GetRandomMultiarchImage("tag1")
			So(err, ShouldBeNil)

			indexDigest, err := multiArch.Digest()
			So(err, ShouldBeNil)

			indexData, err := multiArch.IndexData()
			So(err, ShouldBeNil)

			err = repoDB.SetIndexData(indexDigest, indexData)
			So(err, ShouldBeNil)

			result, err := repoDB.GetIndexData(indexDigest)
			So(err, ShouldBeNil)
			So(result, ShouldResemble, indexData)

			_, err = repoDB.GetIndexData(godigest.FromString("inexistent"))
			So(err, ShouldNotBeNil)
		})

		Convey("Test Referrers", func() {
			image, err := test.GetRandomImage("tag")
			So(err, ShouldBeNil)

			referredDigest, err := image.Digest()
			So(err, ShouldBeNil)

			manifestBlob, err := json.Marshal(image.Manifest)
			So(err, ShouldBeNil)

			configBlob, err := json.Marshal(image.Config)
			So(err, ShouldBeNil)

			manifestData := repodb.ManifestData{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			}

			err = repoDB.SetManifestData(referredDigest, manifestData)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference("repo", "tag", referredDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			// ------- Add Artifact 1

			artifact1, err := test.GetImageWithSubject(
				referredDigest,
				ispec.MediaTypeImageManifest,
			)
			So(err, ShouldBeNil)

			artifactDigest1, err := artifact1.Digest()
			So(err, ShouldBeNil)

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    artifactDigest1.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------- Add Artifact 2

			artifact2, err := test.GetImageWithSubject(
				referredDigest,
				ispec.MediaTypeImageManifest,
			)
			So(err, ShouldBeNil)

			artifactDigest2, err := artifact2.Digest()
			So(err, ShouldBeNil)

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    artifactDigest2.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------ GetReferrers

			referrers, err := repoDB.GetReferrersInfo("repo", referredDigest, nil)
			So(len(referrers), ShouldEqual, 2)
			So(referrers, ShouldContain, repodb.ReferrerInfo{
				Digest:    artifactDigest1.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(referrers, ShouldContain, repodb.ReferrerInfo{
				Digest:    artifactDigest2.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------ DeleteReferrers

			err = repoDB.DeleteReferrer("repo", referredDigest, artifactDigest1)
			So(err, ShouldBeNil)

			err = repoDB.DeleteReferrer("repo", referredDigest, artifactDigest2)
			So(err, ShouldBeNil)

			referrers, err = repoDB.GetReferrersInfo("repo", referredDigest, nil)
			So(err, ShouldBeNil)
			So(len(referrers), ShouldEqual, 0)
		})

		Convey("Test Referrers on empty Repo", func() {
			repoMeta, err := repoDB.GetRepoMeta("repo")
			So(err, ShouldNotBeNil)
			So(repoMeta, ShouldResemble, repodb.RepoMetadata{})

			referredDigest := godigest.FromString("referredDigest")
			referrerDigest := godigest.FromString("referrerDigest")

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta("repo")
			So(err, ShouldBeNil)
			So(repoMeta.Referrers[referredDigest.String()][0].Digest, ShouldResemble, referrerDigest.String())
		})

		Convey("Test Referrers add same one twice", func() {
			repoMeta, err := repoDB.GetRepoMeta("repo")
			So(err, ShouldNotBeNil)
			So(repoMeta, ShouldResemble, repodb.RepoMetadata{})

			referredDigest := godigest.FromString("referredDigest")
			referrerDigest := godigest.FromString("referrerDigest")

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			repoMeta, err = repoDB.GetRepoMeta("repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[referredDigest.String()]), ShouldEqual, 1)
		})

		Convey("GetReferrersInfo", func() {
			referredDigest := godigest.FromString("referredDigest")

			err := repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:    "inexistendManifestDigest",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------- Set existent manifest and artifact manifest
			err = repoDB.SetManifestData("goodManifest", repodb.ManifestData{
				ManifestBlob: []byte(`{"artifactType": "unwantedType"}`),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:       "goodManifestUnwanted",
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "unwantedType",
			})
			So(err, ShouldBeNil)

			err = repoDB.SetReferrer("repo", referredDigest, repodb.ReferrerInfo{
				Digest:       "goodManifest",
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "wantedType",
			})
			So(err, ShouldBeNil)

			referrerInfo, err := repoDB.GetReferrersInfo("repo", referredDigest, []string{"wantedType"})
			So(err, ShouldBeNil)
			So(len(referrerInfo), ShouldEqual, 1)
			So(referrerInfo[0].ArtifactType, ShouldResemble, "wantedType")
			So(referrerInfo[0].Digest, ShouldResemble, "goodManifest")
		})

		Convey("FilterRepos", func() {
			img, err := test.GetRandomImage("img1")
			So(err, ShouldBeNil)
			imgDigest, err := img.Digest()
			So(err, ShouldBeNil)

			manifestData, err := NewManifestData(img.Manifest, img.Config)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestData(imgDigest, manifestData)
			So(err, ShouldBeNil)

			multiarch, err := test.GetRandomMultiarchImage("multi")
			So(err, ShouldBeNil)
			multiarchDigest, err := multiarch.Digest()
			So(err, ShouldBeNil)

			indexData, err := NewIndexData(multiarch.Index)
			So(err, ShouldBeNil)

			err = repoDB.SetIndexData(multiarchDigest, indexData)
			So(err, ShouldBeNil)

			for _, img := range multiarch.Images {
				digest, err := img.Digest()
				So(err, ShouldBeNil)

				indManData1, err := NewManifestData(multiarch.Images[0].Manifest, multiarch.Images[0].Config)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestData(digest, indManData1)
				So(err, ShouldBeNil)
			}

			err = repoDB.SetRepoReference("repo", img.Reference, imgDigest, img.Manifest.MediaType)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference("repo", multiarch.Reference, multiarchDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err := repoDB.FilterRepos(context.Background(),
				func(repoMeta repodb.RepoMetadata) bool { return true }, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)

			_, _, _, _, err = repoDB.FilterRepos(context.Background(),
				func(repoMeta repodb.RepoMetadata) bool { return true }, repodb.PageInput{
					Limit:  -1,
					Offset: -1,
				})
			So(err, ShouldNotBeNil)
		})

		Convey("Test bookmarked/starred field present in returned RepoMeta", func() {
			repo99 := "repo99"
			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					repo99: true,
				},
				Username: "user1",
			}
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			manifestDigest := godigest.FromString("dig")
			err := repoDB.SetManifestData(manifestDigest, repodb.ManifestData{
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = repoDB.SetRepoReference(repo99, "tag", manifestDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err := repoDB.SearchRepos(ctx, repo99, repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = repoDB.SearchTags(ctx, repo99+":", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = repoDB.FilterRepos(ctx, func(repoMeta repodb.RepoMetadata) bool {
				return true
			}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = repoDB.FilterTags(ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			_, err = repoDB.ToggleBookmarkRepo(ctx, repo99)
			So(err, ShouldBeNil)

			_, err = repoDB.ToggleStarRepo(ctx, repo99)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err = repoDB.SearchRepos(ctx, repo99, repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = repoDB.SearchTags(ctx, repo99+":", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = repoDB.FilterRepos(ctx, func(repoMeta repodb.RepoMetadata) bool {
				return true
			}, repodb.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = repoDB.FilterTags(ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)
		})

		Convey("Test GetUserRepoMeta", func() {
			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "user1",
			}
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			digest := godigest.FromString("1")

			err := repoDB.SetRepoReference("repo", "tag", digest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, err = repoDB.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)

			_, err = repoDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.IsBookmarked, ShouldBeTrue)
			So(repoMeta.IsStarred, ShouldBeTrue)
			So(repoMeta.Tags, ShouldContainKey, "tag")
		})
	})
}

func NewManifestData(manifest ispec.Manifest, config ispec.Image) (repodb.ManifestData, error) {
	configBlob, err := json.Marshal(config)
	if err != nil {
		return repodb.ManifestData{}, err
	}

	manifest.Config.Digest = godigest.FromBytes(configBlob)

	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return repodb.ManifestData{}, err
	}

	return repodb.ManifestData{ManifestBlob: manifestBlob, ConfigBlob: configBlob}, nil
}

func NewIndexData(index ispec.Index) (repodb.IndexData, error) {
	indexBlob, err := json.Marshal(index)

	return repodb.IndexData{IndexBlob: indexBlob}, err
}

func TestRelevanceSorting(t *testing.T) {
	Convey("Test Relevance Sorting", t, func() {
		So(common.RankRepoName("alpine", "alpine"), ShouldEqual, 0)
		So(common.RankRepoName("test/alpine", "test/alpine"), ShouldEqual, 0)
		So(common.RankRepoName("test/alpine", "alpine"), ShouldEqual, -1)
		So(common.RankRepoName("alpine", "test/alpine"), ShouldEqual, 1)
		So(common.RankRepoName("test", "test/alpine"), ShouldEqual, 10)
		So(common.RankRepoName("pine", "test/alpine"), ShouldEqual, 3)
		So(common.RankRepoName("pine", "alpine/alpine"), ShouldEqual, 3)
		So(common.RankRepoName("pine", "alpine/test"), ShouldEqual, 30)
		So(common.RankRepoName("test/pine", "alpine"), ShouldEqual, -1)
		So(common.RankRepoName("repo/test", "repo/test/alpine"), ShouldEqual, 10)
		So(common.RankRepoName("repo/test/golang", "repo/test2/alpine"), ShouldEqual, -1)
		So(common.RankRepoName("repo/test/pine", "repo/test/alpine"), ShouldEqual, 3)
		So(common.RankRepoName("debian", "c3/debian/base-amd64"), ShouldEqual, 400)
		So(common.RankRepoName("debian/base-amd64", "c3/debian/base-amd64"), ShouldEqual, 400)
		So(common.RankRepoName("debian/base-amd64", "c3/aux/debian/base-amd64"), ShouldEqual, 800)
		So(common.RankRepoName("aux/debian", "c3/aux/debian/base-amd64"), ShouldEqual, 400)

		Convey("Integration", func() {
			filePath := path.Join(t.TempDir(), "repo.db")
			boltDBParams := bolt.DBParameters{
				RootDir: t.TempDir(),
			}
			boltDriver, err := bolt.GetBoltDriver(boltDBParams)
			So(err, ShouldBeNil)

			log := log.NewLogger("debug", "")

			repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
			So(repoDB, ShouldNotBeNil)
			So(err, ShouldBeNil)

			defer os.Remove(filePath)

			var (
				repo1           = "alpine"
				repo2           = "alpine/test"
				repo3           = "notalpine"
				repo4           = "unmached/repo"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = godigest.FromString("fake-manifest2")
				tag3            = "0.0.3"
				manifestDigest3 = godigest.FromString("fake-manifest3")
				ctx             = context.Background()
				emptyManifest   ispec.Manifest
				emptyConfig     ispec.Manifest
			)
			emptyManifestBlob, err := json.Marshal(emptyManifest)
			So(err, ShouldBeNil)

			emptyConfigBlob, err := json.Marshal(emptyConfig)
			So(err, ShouldBeNil)

			emptyRepoMeta := repodb.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = repoDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo3, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo3, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo4, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			repos, _, _, _, err := repoDB.SearchRepos(ctx, "pine", repodb.Filter{},
				repodb.PageInput{SortBy: repodb.Relevance},
			)

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 3)
			So(repos[0].Name, ShouldEqual, repo1)
			So(repos[1].Name, ShouldEqual, repo3)
			So(repos[2].Name, ShouldEqual, repo2)
		})
	})
}

func generateTestImage() ([]byte, []byte, error) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           LINUX,
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, 100),
	}

	// init layers with random values
	for i := range layers {
		//nolint:gosec
		_, err := rand.Read(layers[i]) //nolint:staticcheck
		if err != nil {
			return []byte{}, []byte{}, err
		}
	}

	manifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return configBlob, manifestBlob, nil
}
