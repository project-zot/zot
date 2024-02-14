//go:build imagetrust
// +build imagetrust

package meta_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	guuid "github.com/gofrs/uuid"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/pkg/extensions/search/convert"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	"zotregistry.dev/zot/pkg/meta/common"
	mdynamodb "zotregistry.dev/zot/pkg/meta/dynamodb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	tCommon "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/signature"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

const (
	LINUX   = "linux"
	WINDOWS = "windows"
	AMD     = "amd"
	ARM     = "arm64"
)

func getManifestDigest(md mTypes.ManifestMeta) string { return md.Digest.String() }

func TestBoltDB(t *testing.T) {
	Convey("BoltDB creation", t, func() {
		boltDBParams := boltdb.DBParameters{RootDir: t.TempDir()}
		repoDBPath := path.Join(boltDBParams.RootDir, "meta.db")

		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)
		defer os.Remove(repoDBPath)

		log := log.NewLogger("debug", "")

		metaDB, err := boltdb.New(boltDriver, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod(repoDBPath, 0o200)
		So(err, ShouldBeNil)

		_, err = boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldNotBeNil)

		err = os.Chmod(repoDBPath, 0o600)
		So(err, ShouldBeNil)
	})

	Convey("BoltDB Wrapper", t, func() {
		boltDBParams := boltdb.DBParameters{RootDir: t.TempDir()}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		imgTrustStore, err := imagetrust.NewLocalImageTrustStore(boltDBParams.RootDir)
		So(err, ShouldBeNil)

		boltdbWrapper, err := boltdb.New(boltDriver, log)

		boltdbWrapper.SetImageTrustStore(imgTrustStore)

		defer func() {
			os.Remove(path.Join(boltDBParams.RootDir, "meta.db"))
			os.RemoveAll(path.Join(boltDBParams.RootDir, "_cosign"))
			os.RemoveAll(path.Join(boltDBParams.RootDir, "_notation"))
		}()

		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		RunMetaDBTests(t, boltdbWrapper)
	})
}

func TestDynamoDBWrapper(t *testing.T) {
	tskip.SkipDynamo(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	repoMetaTablename := "RepoMetadataTable" + uuid.String()
	versionTablename := "Version" + uuid.String()
	userDataTablename := "UserDataTable" + uuid.String()
	apiKeyTablename := "ApiKeyTable" + uuid.String()
	imageMetaTablename := "ImageMeta" + uuid.String()
	repoBlobsTablename := "RepoBlobs" + uuid.String()

	Convey("DynamoDB Wrapper", t, func() {
		dynamoDBDriverParams := mdynamodb.DBDriverParameters{
			Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:      repoMetaTablename,
			RepoBlobsInfoTablename: repoBlobsTablename,
			ImageMetaTablename:     imageMetaTablename,
			VersionTablename:       versionTablename,
			UserDataTablename:      userDataTablename,
			APIKeyTablename:        apiKeyTablename,
			Region:                 "us-east-2",
		}

		dynamoClient, err := mdynamodb.GetDynamoClient(dynamoDBDriverParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		dynamoDriver, err := mdynamodb.New(dynamoClient, dynamoDBDriverParams, log)
		So(dynamoDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		imgTrustStore, err := imagetrust.NewAWSImageTrustStore(dynamoDBDriverParams.Region, dynamoDBDriverParams.Endpoint)
		So(err, ShouldBeNil)

		dynamoDriver.SetImageTrustStore(imgTrustStore)

		resetDynamoDBTables := func() error {
			err := dynamoDriver.ResetTable(dynamoDriver.RepoMetaTablename)
			if err != nil {
				return err
			}

			err = dynamoDriver.ResetTable(dynamoDriver.ImageMetaTablename)
			if err != nil {
				return err
			}

			err = dynamoDriver.ResetTable(dynamoDriver.RepoBlobsTablename)
			if err != nil {
				return err
			}

			// Note: Tests are very slow if we reset the UserData table every new convey. We'll reset it as needed

			return err
		}

		RunMetaDBTests(t, dynamoDriver, resetDynamoDBTables)
	})
}

func RunMetaDBTests(t *testing.T, metaDB mTypes.MetaDB, preparationFuncs ...func() error) { //nolint: thelper
	ctx := context.Background()

	Convey("Test MetaDB Interface implementation", func() {
		for _, prepFunc := range preparationFuncs {
			err := prepFunc()
			So(err, ShouldBeNil)
		}

		Convey("Test CRUD operations on UserData and API keys", func() {
			hashKey1 := "id"
			label1 := "apiKey1"

			apiKeys := make(map[string]mTypes.APIKeyDetails)
			apiKeyDetails := mTypes.APIKeyDetails{
				Label:  label1,
				Scopes: []string{"repo"},
				UUID:   hashKey1,
			}

			apiKeys[hashKey1] = apiKeyDetails

			userProfileSrc := mTypes.UserData{
				Groups:  []string{"group1", "group2"},
				APIKeys: apiKeys,
			}

			Convey("Test basic operations on API keys", func() {
				hashKey2 := "key"
				label2 := "apiKey2"

				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")

				ctx := userAc.DeriveContext(context.Background())

				err := metaDB.AddUserAPIKey(ctx, hashKey1, &apiKeyDetails)
				So(err, ShouldBeNil)

				isExpired, err := metaDB.IsAPIKeyExpired(ctx, hashKey1)
				So(isExpired, ShouldBeFalse)
				So(err, ShouldBeNil)

				storedAPIKeys, err := metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 1)
				So(storedAPIKeys[0], ShouldResemble, apiKeyDetails)

				userProfile, err := metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(userProfile.APIKeys, ShouldContainKey, hashKey1)
				So(userProfile.APIKeys[hashKey1].Label, ShouldEqual, apiKeyDetails.Label)
				So(userProfile.APIKeys[hashKey1].Scopes, ShouldResemble, apiKeyDetails.Scopes)

				err = metaDB.SetUserData(ctx, userProfileSrc)
				So(err, ShouldBeNil)

				userProfile, err = metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(userProfile.Groups, ShouldResemble, userProfileSrc.Groups)
				So(userProfile.APIKeys, ShouldContainKey, hashKey1)
				So(userProfile.APIKeys[hashKey1].Label, ShouldEqual, apiKeyDetails.Label)
				So(userProfile.APIKeys[hashKey1].Scopes, ShouldResemble, apiKeyDetails.Scopes)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 1)
				So(storedAPIKeys[0], ShouldResemble, apiKeyDetails)

				lastUsed := userProfile.APIKeys[hashKey1].LastUsed

				err = metaDB.UpdateUserAPIKeyLastUsed(ctx, hashKey1)
				So(err, ShouldBeNil)

				userProfile, err = metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(userProfile.APIKeys[hashKey1].LastUsed, ShouldHappenAfter, lastUsed)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 1)
				So(storedAPIKeys[0].LastUsed, ShouldHappenAfter, lastUsed)

				userGroups, err := metaDB.GetUserGroups(ctx)
				So(err, ShouldBeNil)
				So(userGroups, ShouldResemble, userProfileSrc.Groups)

				apiKeyDetails.UUID = hashKey2
				apiKeyDetails.Label = label2
				err = metaDB.AddUserAPIKey(ctx, hashKey2, &apiKeyDetails)
				So(err, ShouldBeNil)

				userProfile, err = metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(userProfile.Groups, ShouldResemble, userProfileSrc.Groups)
				So(userProfile.APIKeys, ShouldContainKey, hashKey2)
				So(userProfile.APIKeys[hashKey2].Label, ShouldEqual, apiKeyDetails.Label)
				So(userProfile.APIKeys[hashKey2].Scopes, ShouldResemble, apiKeyDetails.Scopes)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 2)
				So(storedAPIKeys[0].Scopes, ShouldResemble, apiKeyDetails.Scopes)
				So(storedAPIKeys[1].Scopes, ShouldResemble, apiKeyDetails.Scopes)
				scopes := []string{storedAPIKeys[0].Label, storedAPIKeys[1].Label}
				// order is not preserved when getting api keys from db
				So(scopes, ShouldContain, label1)
				So(scopes, ShouldContain, label2)

				email, err := metaDB.GetUserAPIKeyInfo(hashKey2)
				So(err, ShouldBeNil)
				So(email, ShouldEqual, "test")

				email, err = metaDB.GetUserAPIKeyInfo(hashKey1)
				So(err, ShouldBeNil)
				So(email, ShouldEqual, "test")

				err = metaDB.DeleteUserAPIKey(ctx, hashKey1)
				So(err, ShouldBeNil)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 1)
				So(storedAPIKeys[0].Label, ShouldEqual, label2)

				userProfile, err = metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(len(userProfile.APIKeys), ShouldEqual, 1)

				err = metaDB.DeleteUserAPIKey(ctx, hashKey2)
				So(err, ShouldBeNil)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 0)

				userProfile, err = metaDB.GetUserData(ctx)
				So(err, ShouldBeNil)
				So(len(userProfile.APIKeys), ShouldEqual, 0)
				So(userProfile.APIKeys, ShouldNotContainKey, hashKey2)

				// delete non existent api key
				err = metaDB.DeleteUserAPIKey(ctx, hashKey2)
				So(err, ShouldBeNil)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 0)

				err = metaDB.DeleteUserData(ctx)
				So(err, ShouldBeNil)

				storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 0)

				email, err = metaDB.GetUserAPIKeyInfo(hashKey2)
				So(err, ShouldNotBeNil)
				So(email, ShouldBeEmpty)

				email, err = metaDB.GetUserAPIKeyInfo(hashKey1)
				So(err, ShouldNotBeNil)
				So(email, ShouldBeEmpty)

				_, err = metaDB.GetUserData(ctx)
				So(err, ShouldNotBeNil)

				userGroups, err = metaDB.GetUserGroups(ctx)
				So(err, ShouldNotBeNil)
				So(userGroups, ShouldBeEmpty)

				err = metaDB.SetUserGroups(ctx, userProfileSrc.Groups)
				So(err, ShouldBeNil)

				userGroups, err = metaDB.GetUserGroups(ctx)
				So(err, ShouldBeNil)
				So(userGroups, ShouldResemble, userProfileSrc.Groups)
			})

			Convey("Test API keys operations with invalid access control context", func() {
				var invalid struct{}

				key := reqCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), key, invalid)

				_, err := metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldNotBeNil)

				err = metaDB.AddUserAPIKey(ctx, hashKey1, &apiKeyDetails)
				So(err, ShouldNotBeNil)

				isExpired, err := metaDB.IsAPIKeyExpired(ctx, hashKey1)
				So(isExpired, ShouldBeFalse)
				So(err, ShouldNotBeNil)

				err = metaDB.DeleteUserAPIKey(ctx, hashKey1)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserData(ctx)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserGroups(ctx)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserAPIKeyInfo(hashKey1)
				So(err, ShouldNotBeNil)

				err = metaDB.UpdateUserAPIKeyLastUsed(ctx, hashKey1)
				So(err, ShouldNotBeNil)

				err = metaDB.SetUserData(ctx, userProfileSrc)
				So(err, ShouldNotBeNil)
			})

			Convey("Test API keys operations with empty userid", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("")

				ctx := userAc.DeriveContext(context.Background())

				_, err := metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldNotBeNil)

				isExpired, err := metaDB.IsAPIKeyExpired(ctx, hashKey1)
				So(isExpired, ShouldBeFalse)
				So(err, ShouldNotBeNil)

				err = metaDB.AddUserAPIKey(ctx, hashKey1, &apiKeyDetails)
				So(err, ShouldNotBeNil)

				err = metaDB.DeleteUserAPIKey(ctx, hashKey1)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserData(ctx)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserGroups(ctx)
				So(err, ShouldNotBeNil)

				_, err = metaDB.GetUserAPIKeyInfo(hashKey1)
				So(err, ShouldNotBeNil)

				err = metaDB.UpdateUserAPIKeyLastUsed(ctx, hashKey1)
				So(err, ShouldNotBeNil)

				err = metaDB.SetUserData(ctx, userProfileSrc)
				So(err, ShouldNotBeNil)
			})

			Convey("Test API keys with short expiration date", func() {
				expirationDate := time.Now().Add(1 * time.Second)
				apiKeyDetails.ExpirationDate = expirationDate

				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")

				ctx := userAc.DeriveContext(context.Background())

				err := metaDB.AddUserAPIKey(ctx, hashKey1, &apiKeyDetails)
				So(err, ShouldBeNil)

				storedAPIKeys, err := metaDB.GetUserAPIKeys(ctx)
				So(err, ShouldBeNil)
				So(len(storedAPIKeys), ShouldEqual, 1)
				So(storedAPIKeys[0].ExpirationDate, ShouldResemble, expirationDate)
				So(storedAPIKeys[0].Label, ShouldEqual, apiKeyDetails.Label)
				So(storedAPIKeys[0].Scopes, ShouldResemble, apiKeyDetails.Scopes)

				isExpired, err := metaDB.IsAPIKeyExpired(ctx, hashKey1)
				So(isExpired, ShouldBeFalse)
				So(err, ShouldBeNil)

				time.Sleep(1 * time.Second)

				Convey("GetUserAPIKeys detects api key expired", func() {
					storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
					So(err, ShouldBeNil)
					So(len(storedAPIKeys), ShouldEqual, 1)
					So(storedAPIKeys[0].IsExpired, ShouldBeTrue)

					isExpired, err = metaDB.IsAPIKeyExpired(ctx, hashKey1)
					So(isExpired, ShouldBeTrue)
					So(err, ShouldBeNil)
				})

				Convey("IsAPIKeyExpired detects api key expired", func() {
					isExpired, err = metaDB.IsAPIKeyExpired(ctx, hashKey1)
					So(isExpired, ShouldBeTrue)
					So(err, ShouldBeNil)

					storedAPIKeys, err = metaDB.GetUserAPIKeys(ctx)
					So(err, ShouldBeNil)
					So(len(storedAPIKeys), ShouldEqual, 1)
					So(storedAPIKeys[0].IsExpired, ShouldBeTrue)
				})
			})
		})

		Convey("Test Setting an image by tag and retrieving data", func() {
			imgData := CreateImageWith().
				DefaultLayers().
				ImageConfig(ispec.Image{
					Created: DateRef(2000, 10, 10, 10, 10, 10, 10, time.UTC),
					Author:  "author",
					Platform: ispec.Platform{
						Architecture: "arch",
						OS:           "os",
						OSVersion:    "os-vers",
						OSFeatures:   []string{"os-features"},
						Variant:      "variant",
					},
					Config: ispec.ImageConfig{
						Labels:       map[string]string{"test": "test"},
						Env:          []string{"test"},
						ExposedPorts: map[string]struct{}{"test": {}},
						Volumes:      map[string]struct{}{"test": {}},
					},
					RootFS: ispec.RootFS{
						DiffIDs: []godigest.Digest{godigest.FromString("test")},
					},
				}).Build().AsImageMeta()

			err := metaDB.SetImageMeta(imgData.Digest, imgData)
			So(err, ShouldBeNil)

			retrievedImgData, err := metaDB.GetImageMeta(imgData.Digest)
			So(err, ShouldBeNil)
			So(imgData, ShouldResemble, retrievedImgData)

			imgMulti := CreateRandomMultiarch()

			for i := range imgMulti.Images {
				err = metaDB.SetImageMeta(imgMulti.Images[i].Digest(), imgMulti.Images[i].AsImageMeta())
				So(err, ShouldBeNil)
			}

			err = metaDB.SetImageMeta(imgMulti.Digest(), imgMulti.AsImageMeta())
			So(err, ShouldBeNil)

			retrievedImgMultiData, err := metaDB.GetImageMeta(imgMulti.Digest())
			So(err, ShouldBeNil)
			So(imgMulti.AsImageMeta(), ShouldEqual, retrievedImgMultiData)

			// set subject on multiarch
		})

		Convey("GetFullImageMeta", func() {
			img1 := CreateRandomImage()
			multi := CreateMultiarchWith().Images([]Image{img1}).Build()

			err := metaDB.SetRepoReference(ctx, "repo", img1.Digest().String(), img1.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, "repo", "tag", multi.AsImageMeta())
			So(err, ShouldBeNil)

			fullImageMeta, err := metaDB.GetFullImageMeta(ctx, "repo", "tag")
			So(err, ShouldBeNil)
			So(fullImageMeta.Digest.String(), ShouldResemble, multi.DigestStr())
		})

		Convey("Set/Get RepoMeta", func() {
			err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
				Name: "repo",
				Tags: map[mTypes.Tag]mTypes.Descriptor{"tag": {Digest: "dig"}},

				Statistics: map[mTypes.ImageDigest]mTypes.DescriptorStatistics{},
				Signatures: map[mTypes.ImageDigest]mTypes.ManifestSignatures{},
				Referrers:  map[mTypes.ImageDigest][]mTypes.ReferrerInfo{"digest": {{Digest: "dig"}}},
			})
			So(err, ShouldBeNil)
			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.Name, ShouldResemble, "repo")
			So(repoMeta.Tags, ShouldContainKey, "tag")
		})

		Convey("Test SetRepoReference", func() {
			var (
				repo1 = "repo1"
				repo2 = "repo2"
				tag1  = "0.0.1"
				tag2  = "0.0.2"
			)

			img1 := CreateImageWith().RandomLayers(2, 10).RandomConfig().
				Annotations(map[string]string{"test": "annotation"}).Build()
			imgData1 := img1.AsImageMeta()
			img1Size := img1.ConfigDescriptor.Size + img1.ManifestDescriptor.Size + 2*10

			img2 := CreateImageWith().LayerBlobs(img1.Layers).RandomConfig().
				Annotations(map[string]string{"test": "annotation"}).Build()
			imgData2 := img2.AsImageMeta()
			img2Size := img2.ConfigDescriptor.Size + img2.ManifestDescriptor.Size + 2*10

			multiImages := []Image{
				CreateImageWith().RandomLayers(2, 10).
					ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "multi-os1", Architecture: "multi-arch1"}}).
					Annotations(map[string]string{ispec.AnnotationVendor: "vendor1"}).
					Build(),
				CreateImageWith().RandomLayers(2, 10).
					ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "multi-os2", Architecture: "multi-arch2"}}).
					Annotations(map[string]string{ispec.AnnotationVendor: "vendor2"}).
					Build(),
			}

			imgMulti := CreateMultiarchWith().
				Images(multiImages).
				Annotations(map[string]string{ispec.AnnotationVendor: "vendor1"}).Build()

			Convey("Setting a good repo", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, imgData1)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, img1.DigestStr())
			})

			Convey("Setting an index with it's manifests", func() {
				_, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldNotBeNil)

				for i := range imgMulti.Images {
					err := metaDB.SetRepoReference(ctx, repo1, imgMulti.Images[i].DigestStr(),
						imgMulti.Images[i].AsImageMeta())
					So(err, ShouldBeNil)
				}

				err = metaDB.SetRepoReference(ctx, repo1, tag1, imgMulti.AsImageMeta())
				So(err, ShouldBeNil)

				image1TotalSize := multiImages[0].ManifestDescriptor.Size + multiImages[0].ConfigDescriptor.Size + 2*10
				image2TotalSize := multiImages[1].ManifestDescriptor.Size + multiImages[1].ConfigDescriptor.Size + 2*10
				indexTotalSize := image1TotalSize + image2TotalSize + imgMulti.IndexDescriptor.Size

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
				So(repoMeta.Platforms, ShouldContain, ispec.Platform{OS: "multi-os1", Architecture: "multi-arch1"})
				So(repoMeta.Platforms, ShouldContain, ispec.Platform{OS: "multi-os2", Architecture: "multi-arch2"})
				So(repoMeta.Vendors, ShouldContain, "vendor1")
				So(repoMeta.Vendors, ShouldContain, "vendor2")
				So(repoMeta.Size, ShouldEqual, indexTotalSize)
			})

			Convey("Set multiple repos", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, imgData1)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, repo2, tag1, imgData2)
				So(err, ShouldBeNil)

				repoMeta1, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				repoMeta2, err := metaDB.GetRepoMeta(ctx, repo2)
				So(err, ShouldBeNil)

				So(repoMeta1.Tags[tag1].Digest, ShouldResemble, imgData1.Digest.String())
				So(repoMeta2.Tags[tag1].Digest, ShouldResemble, imgData2.Digest.String())
				So(repoMeta1.Size, ShouldEqual, img1Size)
				So(repoMeta2.Size, ShouldEqual, img2Size)
			})

			Convey("Set, delete and set again", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, imgData1)
				So(err, ShouldBeNil)

				err = metaDB.RemoveRepoReference(repo1, tag1, imgData1.Digest)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, repo1, tag1, imgData1)
				So(err, ShouldBeNil)
			})

			Convey("Check repo blobs info for manifest image", func() {
				image1 := CreateImageWith().RandomLayers(2, 10).
					ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os1", Architecture: "arch1"}}).
					Annotations(map[string]string{ispec.AnnotationVendor: "vendor1"}).
					Build()
				imageMeta1 := image1.AsImageMeta()

				layersSize := int64(2 * 10)
				image1Size := imageMeta1.Manifests[0].Size + imageMeta1.Manifests[0].Manifest.Config.Size + layersSize

				err := metaDB.SetRepoReference(ctx, repo1, tag1, imageMeta1)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Vendors, ShouldContain, "vendor1")
				So(repoMeta.Platforms, ShouldContain, ispec.Platform{OS: "os1", Architecture: "arch1"})
				So(repoMeta.Size, ShouldEqual, image1Size)

				image2 := CreateImageWith().
					LayerBlobs(image1.Layers).
					ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os2", Architecture: "arch2"}}).
					Annotations(map[string]string{ispec.AnnotationVendor: "vendor2"}).
					Build()
				imageMeta2 := image2.AsImageMeta()

				// the layers are the same so we add them once
				repoSize := image1Size + image2.ManifestDescriptor.Size + image2.ConfigDescriptor.Size

				err = metaDB.SetRepoReference(ctx, repo1, tag2, imageMeta2)
				So(err, ShouldBeNil)

				repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Vendors, ShouldContain, "vendor1")
				So(repoMeta.Vendors, ShouldContain, "vendor2")
				So(repoMeta.Platforms, ShouldContain, ispec.Platform{OS: "os1", Architecture: "arch1"})
				So(repoMeta.Platforms, ShouldContain, ispec.Platform{OS: "os2", Architecture: "arch2"})
				So(repoMeta.Size, ShouldEqual, repoSize)
			})

			Convey("Set with a bad reference", func() {
				err := metaDB.SetRepoReference(ctx, "repo", "", imgData1)
				So(err, ShouldNotBeNil)

				err = metaDB.SetRepoReference(ctx, "", "tag", imgData1)
				So(err, ShouldNotBeNil)
			})

			Convey("Check last updated for indexes", func() {
				config1 := GetDefaultConfig()
				config1.Created = DateRef(2009, 2, 1, 12, 0, 0, 0, time.UTC)

				config2 := GetDefaultConfig()
				config2.Created = DateRef(2011, 2, 1, 12, 0, 0, 0, time.UTC)

				config3 := GetDefaultConfig()
				config3.Created = DateRef(2011, 3, 1, 12, 0, 0, 0, time.UTC)

				image1 := CreateMultiarchWith().Images([]Image{
					CreateImageWith().RandomLayers(1, 10).ImageConfig(config1).Build(),
				}).Build()
				image2 := CreateMultiarchWith().Images([]Image{
					CreateImageWith().RandomLayers(1, 10).ImageConfig(config2).Build(),
					CreateImageWith().RandomLayers(1, 10).ImageConfig(config3).Build(),
				}).Build()

				_, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldNotBeNil)

				for i := range image1.Images {
					err := metaDB.SetRepoReference(ctx, repo1, image1.Images[i].DigestStr(),
						image1.Images[i].AsImageMeta())
					So(err, ShouldBeNil)
				}

				err = metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)

				for i := range image2.Images {
					err := metaDB.SetRepoReference(ctx, repo1, image2.Images[i].DigestStr(),
						image2.Images[i].AsImageMeta())
					So(err, ShouldBeNil)
				}

				err = metaDB.SetRepoReference(ctx, repo1, tag2, image2.AsImageMeta())
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(*repoMeta.LastUpdatedImage.LastUpdated, ShouldEqual, time.Date(2011, 3, 1, 12, 0, 0, 0, time.UTC))
			})
		})

		Convey("Test RemoveRepoReference", func() {
			var (
				repo = "repo1"
				tag1 = "0.0.1"
				tag2 = "0.0.2"
			)

			layersSize := int64(2 * 10)

			image1 := CreateImageWith().
				RandomLayers(2, 10).
				ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os1", Architecture: "arch1"}}).
				Annotations(map[string]string{ispec.AnnotationVendor: "vendor1"}).
				Build()
			imageMeta1 := image1.AsImageMeta()
			image1Size := imageMeta1.Manifests[0].Size + imageMeta1.Manifests[0].Manifest.Config.Size + layersSize

			image2 := CreateImageWith().
				LayerBlobs(image1.Layers).
				ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os2", Architecture: "arch2"}}).
				Annotations(map[string]string{ispec.AnnotationVendor: "vendor2", "annotation": "test"}).
				Build()
			imageMeta2 := image2.AsImageMeta()
			image2Size := imageMeta2.Manifests[0].Size + imageMeta2.Manifests[0].Manifest.Config.Size + layersSize

			totalRepoSize := image1Size + image2Size - layersSize

			err := metaDB.SetRepoReference(ctx, repo, tag1, imageMeta1)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo, tag2, imageMeta2)
			So(err, ShouldBeNil)

			Convey("Delete reference from repo", func() {
				err = metaDB.RemoveRepoReference(repo, tag1, imageMeta1.Digest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
				So(err, ShouldBeNil)

				_, ok := repoMeta.Tags[tag1]
				So(ok, ShouldBeFalse)
				So(repoMeta.Size, ShouldEqual, image2Size)
				So(repoMeta.Platforms, ShouldNotContain, ispec.Platform{OS: "os1", Architecture: "arch1"})
				So(repoMeta.Vendors, ShouldNotContain, "vendor1")
			})

			Convey("Delete a digest from repo", func() {
				err = metaDB.RemoveRepoReference(repo, tag2, imageMeta2.Digest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
				So(err, ShouldBeNil)

				_, ok := repoMeta.Tags[tag2]
				So(ok, ShouldBeFalse)
				So(repoMeta.Size, ShouldEqual, image1Size)
				So(repoMeta.Platforms, ShouldNotContain, ispec.Platform{OS: "os2", Architecture: "arch2"})
				So(repoMeta.Vendors, ShouldNotContain, "vendor2")
			})

			Convey("Delete inexistent reference from repo", func() {
				inexistentDigest := godigest.FromBytes([]byte("inexistent"))
				err := metaDB.RemoveRepoReference(repo, inexistentDigest.String(), inexistentDigest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1].Digest, ShouldResemble, imageMeta1.Digest.String())
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, imageMeta2.Digest.String())
				So(repoMeta.Size, ShouldEqual, totalRepoSize)
			})

			Convey("Delete reference from inexistent repo", func() {
				inexistentDigest := godigest.FromBytes([]byte("inexistent"))

				err := metaDB.RemoveRepoReference("InexistentRepo", inexistentDigest.String(), inexistentDigest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1].Digest, ShouldResemble, imageMeta1.Digest.String())
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, imageMeta2.Digest.String())
				So(repoMeta.Size, ShouldEqual, totalRepoSize)
			})
		})

		Convey("Test GetMultipleRepoMeta", func() {
			var (
				repo1 = "repo1"
				repo2 = "repo2"
				tag1  = "0.0.1"
				tag2  = "0.0.2"
			)

			image1 := CreateImageWith().
				RandomLayers(2, 10).
				ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os1", Architecture: "arch1"}}).
				Annotations(map[string]string{ispec.AnnotationVendor: "vendor1"}).
				Build()
			imageMeta1 := image1.AsImageMeta()

			image2 := CreateImageWith().
				LayerBlobs(image1.Layers).
				ImageConfig(ispec.Image{Platform: ispec.Platform{OS: "os2", Architecture: "arch2"}}).
				Annotations(map[string]string{ispec.AnnotationVendor: "vendor2"}).
				Build()
			imageMeta2 := image2.AsImageMeta()

			err := metaDB.SetRepoReference(ctx, repo1, tag1, imageMeta1)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo1, tag2, imageMeta2)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo2, tag2, imageMeta2)
			So(err, ShouldBeNil)

			Convey("Get all RepoMeta", func() {
				repoMetaSlice, err := metaDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta mTypes.RepoMeta) bool {
					return true
				})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 2)
			})

			Convey("Get repo with a tag", func() {
				repoMetaSlice, err := metaDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta mTypes.RepoMeta) bool {
					for tag := range repoMeta.Tags {
						if tag == tag1 {
							return true
						}
					}

					return false
				})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 1)
				So(repoMetaSlice[0].Tags[tag1].Digest == imageMeta1.Digest.String(), ShouldBeTrue)
			})
		})

		Convey("Test IncrementRepoStars", func() {
			var (
				repo1     = "repo1"
				tag1      = "0.0.1"
				imageMeta = CreateDefaultImage().AsImageMeta()
			)

			err := metaDB.IncrementRepoStars("missing-repo")
			So(err, ShouldNotBeNil)

			err = metaDB.SetRepoReference(ctx, repo1, tag1, imageMeta)
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 2)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 3)
		})

		Convey("Test DecrementRepoStars", func() {
			var (
				repo1     = "repo1"
				tag1      = "0.0.1"
				imageMeta = CreateDefaultImage().AsImageMeta()
			)

			err := metaDB.IncrementRepoStars("missing-repo")
			So(err, ShouldNotBeNil)

			err = metaDB.SetRepoReference(ctx, repo1, tag1, imageMeta)
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			err = metaDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 0)

			err = metaDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 0)

			_, err = metaDB.GetRepoMeta(ctx, "badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test Repo Stars", func() {
			var (
				repo1 = "repo1"
				tag1  = "0.0.1"
			)

			err := metaDB.SetRepoReference(ctx, repo1, tag1, CreateDefaultImage().AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)
			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)
			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 2)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)
			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 3)
		})

		Convey("Test repo stars for user", func() {
			var (
				repo1 = "repo1"
				tag1  = "0.0.1"
				repo2 = "repo2"
			)

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("user1")
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// "user1"
			ctx1 := userAc.DeriveContext(ctx)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("user2")
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// "user2"
			ctx2 := userAc.DeriveContext(ctx)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// anonymous user
			ctx3 := userAc.DeriveContext(ctx)

			err := metaDB.SetRepoReference(ctx, repo1, tag1, CreateDefaultImage().AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo2, tag1, CreateDefaultImage().AsImageMeta())
			So(err, ShouldBeNil)

			repos, err := metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 bookmarks repo 1, User 2 has no stars
			toggleState, err := metaDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			repos, err = metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 and User 2 star only repo 1
			toggleState, err = metaDB.ToggleStarRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 2)

			repos, err = metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars repos 1 and 2, and User 2 stars only repo 1
			toggleState, err = metaDB.ToggleStarRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo2)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			repos, err = metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars only repo 2, and User 2 stars only repo 1
			toggleState, err = metaDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Removed)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			repos, err = metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars both repos 1 and 2, and User 2 removes all stars
			toggleState, err = metaDB.ToggleStarRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			toggleState, err = metaDB.ToggleStarRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Removed)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo2)
			So(err, ShouldBeNil)
			So(repoMeta.StarCount, ShouldEqual, 1)

			repos, err = metaDB.GetStarredRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetStarredRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// Anonymous user attempts to toggle a star
			toggleState, err = metaDB.ToggleStarRepo(ctx3, repo1)
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, mTypes.NotChanged)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars just repo 1
			toggleState, err = metaDB.ToggleStarRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Removed)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		//nolint: contextcheck
		Convey("Test repo bookmarks for user", func() {
			var (
				repo1  = "repo1"
				tag1   = "0.0.1"
				repo2  = "repo2"
				image1 = CreateRandomImage().AsImageMeta()
			)

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("user1")
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// "user1"
			ctx1 := userAc.DeriveContext(context.Background())

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("user2")
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// "user2"
			ctx2 := userAc.DeriveContext(context.Background())

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetGlobPatterns("read", map[string]bool{
				repo1: true,
				repo2: true,
			})

			// anonymous user
			ctx3 := userAc.DeriveContext(context.Background())

			err := metaDB.SetRepoReference(ctx, repo1, tag1, image1)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo2, tag1, image1)
			So(err, ShouldBeNil)

			repos, err := metaDB.GetBookmarkedRepos(ctx1) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetBookmarkedRepos(ctx2) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// anonymous cannot use bookmarks
			repos, err = metaDB.GetBookmarkedRepos(ctx3) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			toggleState, err := metaDB.ToggleBookmarkRepo(ctx3, repo1) //nolint: contextcheck
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, mTypes.NotChanged)

			repos, err = metaDB.GetBookmarkedRepos(ctx3) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 bookmarks repo 1, User 2 has no bookmarks
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx1, repo1) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repos, err = metaDB.GetBookmarkedRepos(ctx1) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetBookmarkedRepos(ctx2) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 and User 2 bookmark only repo 1
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx2, repo1) //nolint: contextcheck
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks repos 1 and 2, and User 2 bookmarks only repo 1
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks only repo 2, and User 2 bookmarks only repo 1
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Removed)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			// User 1 bookmarks both repos 1 and 2, and User 2 removes all bookmarks
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Added)

			toggleState, err = metaDB.ToggleBookmarkRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, mTypes.Removed)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("Test UpdateStatsOnDownload", func() {
			var (
				repo1  = "repo1"
				tag1   = "0.0.1"
				image1 = CreateRandomImage().AsImageMeta()
			)

			err := metaDB.SetRepoReference(ctx, repo1, tag1, image1)
			So(err, ShouldBeNil)

			err = metaDB.UpdateStatsOnDownload(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[image1.Digest.String()].DownloadCount, ShouldEqual, 1)

			err = metaDB.UpdateStatsOnDownload(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[image1.Digest.String()].DownloadCount, ShouldEqual, 2)
			So(time.Now(), ShouldHappenAfter, repoMeta.Statistics[image1.Digest.String()].LastPullTimestamp)
		})

		Convey("Test AddImageSignature", func() {
			var (
				repo1  = "repo1"
				tag1   = "0.0.1"
				image1 = CreateRandomImage().AsImageMeta()
			)

			err := metaDB.SetRepoReference(ctx, repo1, tag1, image1)
			So(err, ShouldBeNil)

			err = metaDB.AddManifestSignature(repo1, image1.Digest, mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
				LayersInfo:      []mTypes.LayerInfo{{LayerDigest: "layer-digest", LayerContent: []byte{10}}},
			})
			So(err, ShouldBeNil)

			err = metaDB.AddManifestSignature(repo1, image1.Digest, mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureTag:    fmt.Sprintf("sha256-%s.sig", image1.Digest.Encoded()),
				SignatureDigest: "digesttag",
				LayersInfo:      []mTypes.LayerInfo{{LayerDigest: "layer-digest", LayerContent: []byte{10}}},
			})
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[image1.Digest.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digesttag")
			So(repoMeta.Signatures[image1.Digest.String()]["cosign"][1].SignatureManifestDigest,
				ShouldResemble, "digest")

			imageMeta, err := metaDB.GetImageMeta(image1.Digest)

			fullImageMeta := convert.GetFullImageMeta(tag1, repoMeta, imageMeta)
			So(err, ShouldBeNil)
			So(fullImageMeta.Signatures["cosign"][0].SignatureManifestDigest, ShouldResemble, "digesttag")
			So(fullImageMeta.Signatures["cosign"][0].LayersInfo[0].LayerDigest, ShouldResemble, "layer-digest")
			So(fullImageMeta.Signatures["cosign"][0].LayersInfo[0].LayerContent[0], ShouldEqual, 10)
			So(fullImageMeta.Signatures["cosign"][1].SignatureManifestDigest, ShouldResemble, "digest")
			So(fullImageMeta.Signatures["cosign"][1].LayersInfo[0].LayerDigest, ShouldResemble, "layer-digest")
			So(fullImageMeta.Signatures["cosign"][1].LayersInfo[0].LayerContent[0], ShouldEqual, 10)
		})

		Convey("Test UpdateSignaturesValidity", func() {
			Convey("untrusted signature", func() {
				var (
					repo1  = "repo1"
					tag1   = "0.0.1"
					image1 = CreateRandomImage()
				)

				err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)

				layerInfo := mTypes.LayerInfo{LayerDigest: "", LayerContent: []byte{}, SignatureKey: ""}

				err = metaDB.AddManifestSignature(repo1, image1.Digest(), mTypes.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: image1.DigestStr(),
					SignatureTag:    fmt.Sprintf("sha256-%s.sig", image1.Digest().Encoded()),
					LayersInfo:      []mTypes.LayerInfo{layerInfo},
				})
				So(err, ShouldBeNil)

				err = metaDB.UpdateSignaturesValidity(ctx, repo1, image1.Digest())
				So(err, ShouldBeNil)

				repoData, err := metaDB.GetRepoMeta(ctx, repo1)
				So(err, ShouldBeNil)
				So(repoData.Signatures[image1.DigestStr()]["cosign"][0].LayersInfo[0].Signer,
					ShouldBeEmpty)
				So(repoData.Signatures[image1.DigestStr()]["cosign"][0].LayersInfo[0].Date,
					ShouldBeZeroValue)

				Convey("with context done", func() {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					err = metaDB.UpdateSignaturesValidity(ctx, repo1, image1.Digest())
					So(err, ShouldNotBeNil)
				})
			})

			//nolint: contextcheck
			Convey("trusted signature", func() {
				image1 := CreateRandomImage()
				repo := "repo1"
				tag := "0.0.1"

				err := metaDB.SetRepoReference(ctx, repo, tag, image1.AsImageMeta())
				So(err, ShouldBeNil)

				mediaType := jws.MediaTypeEnvelope

				signOpts := notation.SignerSignOptions{
					SignatureMediaType: mediaType,
					PluginConfig:       map[string]string{},
					ExpiryDuration:     24 * time.Hour,
				}

				tdir := t.TempDir()
				uuid, err := guuid.NewV4()
				So(err, ShouldBeNil)

				keyName := fmt.Sprintf("notation-sign-test-%s", uuid)

				signature.NotationPathLock.Lock()
				defer signature.NotationPathLock.Unlock()

				signature.LoadNotationPath(tdir)

				err = signature.GenerateNotationCerts(tdir, keyName)
				So(err, ShouldBeNil)

				// getSigner
				var newSigner notation.Signer

				// ResolveKey
				signingKeys, err := signature.LoadNotationSigningkeys(tdir)
				So(err, ShouldBeNil)

				idx := tCommon.Index(signingKeys.Keys, keyName)
				So(idx, ShouldBeGreaterThanOrEqualTo, 0)

				key := signingKeys.Keys[idx]

				if key.X509KeyPair != nil {
					newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
					So(err, ShouldBeNil)
				}

				descToSign := ispec.Descriptor{
					MediaType: image1.Manifest.MediaType,
					Digest:    image1.Digest(),
					Size:      image1.ManifestDescriptor.Size,
				}

				ctx := context.Background()

				sig, _, err := newSigner.Sign(ctx, descToSign, signOpts)
				So(err, ShouldBeNil)

				layerInfo := mTypes.LayerInfo{
					LayerDigest:  string(godigest.FromBytes(sig)),
					LayerContent: sig, SignatureKey: mediaType,
				}

				err = metaDB.AddManifestSignature(repo, image1.Digest(), mTypes.SignatureMetadata{
					SignatureType:   "notation",
					SignatureDigest: string(godigest.FromString("signature digest")),
					LayersInfo:      []mTypes.LayerInfo{layerInfo},
				})
				So(err, ShouldBeNil)

				certificateContent, err := os.ReadFile(path.Join(
					tdir,
					"notation/localkeys",
					fmt.Sprintf("%s.crt", keyName),
				))
				So(err, ShouldBeNil)
				So(certificateContent, ShouldNotBeNil)

				imgTrustStore, ok := metaDB.ImageTrustStore().(*imagetrust.ImageTrustStore)
				So(ok, ShouldBeTrue)

				err = imagetrust.UploadCertificate(imgTrustStore.NotationStorage, certificateContent, "ca")
				So(err, ShouldBeNil)

				err = metaDB.UpdateSignaturesValidity(ctx, repo, image1.Digest()) //nolint:contextcheck
				So(err, ShouldBeNil)

				repoData, err := metaDB.GetRepoMeta(ctx, repo)
				So(err, ShouldBeNil)

				So(repoData.Signatures[image1.DigestStr()]["notation"][0].LayersInfo[0].Signer,
					ShouldNotBeEmpty)
				So(repoData.Signatures[image1.DigestStr()]["notation"][0].LayersInfo[0].Date,
					ShouldNotBeZeroValue)
			})
		})

		Convey("Test AddImageSignature with inverted order", func() {
			var (
				repo1  = "repo1"
				tag1   = "0.0.1"
				image1 = CreateRandomImage()
			)

			err := metaDB.AddManifestSignature(repo1, image1.Digest(), mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureTag:    fmt.Sprintf("sha256-%s.sig", image1.Digest().Encoded()),
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[image1.DigestStr()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")
		})

		Convey("Test DeleteSignature", func() {
			var (
				repo1  = "repo1"
				tag1   = "0.0.1"
				image1 = CreateRandomImage()
			)

			err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.AddManifestSignature(repo1, image1.Digest(), mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureTag:    fmt.Sprintf("sha256-%s.sig", image1.Digest().Encoded()),
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[image1.DigestStr()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			err = metaDB.DeleteSignature(repo1, image1.Digest(), mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[image1.DigestStr()]["cosign"], ShouldBeEmpty)

			err = metaDB.DeleteSignature(repo1, "badDigest", mTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Test SearchRepos", func() {
			var (
				repo1  = "repo1"
				repo2  = "repo2"
				repo3  = "repo3"
				tag1   = "0.0.1"
				tag2   = "0.0.2"
				tag3   = "0.0.3"
				image1 = CreateRandomImage()
				image2 = CreateRandomImage()
				image3 = CreateRandomImage()
				ctx    = context.Background()
			)
			_ = repo3
			Convey("Search all repos", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, repo1, tag2, image2.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, repo2, tag3, image3.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, "")
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 2)

				So(repoMetaList[0].Tags[tag1].Digest, ShouldResemble, image1.DigestStr())
				So(repoMetaList[0].Tags[tag2].Digest, ShouldResemble, image2.DigestStr())
				So(repoMetaList[1].Tags[tag3].Digest, ShouldResemble, image3.DigestStr())
			})

			Convey("Search a repo by name", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, repo1)
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 1)
				So(repoMetaList[0].Tags[tag1].Digest, ShouldResemble, image1.DigestStr())
			})

			Convey("Search non-existing repo by name", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, repo1, tag2, image2.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, "RepoThatDoesntExist")
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 0)
			})

			Convey("Search with partial match", func() {
				err := metaDB.SetRepoReference(ctx, "alpine", tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "pine", tag2, image2.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "golang", tag3, image3.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, "pine")
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 2)
			})

			Convey("Search multiple repos that share manifests", func() {
				err := metaDB.SetRepoReference(ctx, "alpine", tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "pine", tag2, image1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "golang", tag3, image1.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, "")
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 3)
			})

			Convey("Search repos with access control", func() {
				err := metaDB.SetRepoReference(ctx, repo1, tag1, image1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, repo2, tag2, image2.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, repo3, tag3, image3.AsImageMeta())
				So(err, ShouldBeNil)

				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("username")
				userAc.SetGlobPatterns("read", map[string]bool{
					repo1: true,
					repo2: true,
				})

				ctx := userAc.DeriveContext(context.Background()) //nolint: contextcheck

				repoMetaList, err := metaDB.SearchRepos(ctx, "repo") //nolint: contextcheck
				So(err, ShouldBeNil)
				So(len(repoMetaList), ShouldEqual, 2)
				for _, k := range repoMetaList {
					So(k.Name, ShouldBeIn, []string{repo1, repo2})
				}
			})

			Convey("Search Repos with Indexes", func() {
				var (
					tag4      = "0.0.4"
					subImage1 = CreateRandomImage()
					subImage2 = CreateRandomImage()
					multiarch = CreateMultiarchWith().Images([]Image{subImage1, subImage2}).Build()

					tag5   = "0.0.5"
					image1 = CreateRandomImage()
				)

				err := metaDB.SetRepoReference(ctx, "repo", subImage1.DigestStr(), subImage1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "repo", subImage2.DigestStr(), subImage2.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "repo", tag4, multiarch.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", tag5, image1.AsImageMeta())
				So(err, ShouldBeNil)

				repoMetaList, err := metaDB.SearchRepos(ctx, "repo")
				So(err, ShouldBeNil)

				So(len(repoMetaList), ShouldEqual, 1)
				So(repoMetaList[0].Name, ShouldResemble, "repo")
				So(repoMetaList[0].Tags, ShouldContainKey, tag4)
				So(repoMetaList[0].Tags[tag4].MediaType, ShouldResemble, ispec.MediaTypeImageIndex)
				So(repoMetaList[0].Tags, ShouldContainKey, tag5)
				So(repoMetaList[0].Tags[tag5].MediaType, ShouldResemble, ispec.MediaTypeImageManifest)
			})
		})

		Convey("Test SearchTags", func() {
			var (
				repo1  = "repo1"
				repo2  = "repo2"
				image1 = CreateRandomImage()
				image2 = CreateRandomImage()
				image3 = CreateRandomImage()
				ctx    = context.Background()
			)

			err := metaDB.SetRepoReference(ctx, repo1, "0.0.1", image1.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "0.0.2", image3.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "0.1.0", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "1.0.0", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "1.0.1", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo2, "0.0.1", image3.AsImageMeta())
			So(err, ShouldBeNil)

			Convey("With exact match", func() {
				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo1:0.0.1")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 1)
				So(fullImageMetaList[0].Digest.String(), ShouldResemble, image1.DigestStr())
			})

			Convey("With no match", func() {
				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo1:badtag")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 0)
			})

			Convey("With no permission", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("user1")
				userAc.SetGlobPatterns("read",
					map[string]bool{
						repo1: false,
						repo2: false,
					},
				)
				ctx1 := userAc.DeriveContext(context.Background())

				fullImageMetaList, err := metaDB.SearchTags(ctx1, "repo1:0.0.1")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 0)
			})

			Convey("With partial repo path", func() {
				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo:0.0.1")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 0)
			})

			Convey("With partial tag", func() {
				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo1:0.0")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 2)

				tags := map[string]struct{}{}
				for _, imageMeta := range fullImageMetaList {
					tags[imageMeta.Tag] = struct{}{}
				}

				So(tags, ShouldContainKey, "0.0.2")
				So(tags, ShouldContainKey, "0.0.1")

				fullImageMetaList, err = metaDB.SearchTags(ctx, "repo1:0.")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 3)

				tags = map[string]struct{}{}
				for _, imageMeta := range fullImageMetaList {
					tags[imageMeta.Tag] = struct{}{}
				}

				So(tags, ShouldContainKey, "0.0.1")
				So(tags, ShouldContainKey, "0.0.2")
				So(tags, ShouldContainKey, "0.1.0")
			})

			Convey("With bad query", func() {
				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo:0.0.1:test")
				So(err, ShouldNotBeNil)
				So(len(fullImageMetaList), ShouldEqual, 0)
			})

			Convey("Search with access control", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("username")
				userAc.SetGlobPatterns("read", map[string]bool{
					repo1: true,
					repo2: false,
				})

				ctx := userAc.DeriveContext(context.Background())

				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo1:")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 5)
				So(fullImageMetaList[0].Repo, ShouldResemble, repo1)

				fullImageMetaList, err = metaDB.SearchTags(ctx, "repo2:")
				So(err, ShouldBeNil)
				So(fullImageMetaList, ShouldBeEmpty)
			})

			Convey("Search Tags with Indexes", func() {
				var (
					tag4      = "0.0.4"
					subImage1 = CreateRandomImage()
					subImage2 = CreateRandomImage()
					multiarch = CreateMultiarchWith().Images([]Image{subImage1, subImage2}).Build()

					tag5   = "0.0.5"
					image5 = CreateRandomImage()

					tag6   = "6.0.0"
					image6 = CreateRandomImage()
				)

				err = metaDB.SetRepoReference(ctx, "repo", subImage1.DigestStr(), subImage1.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "repo", subImage2.DigestStr(), subImage2.AsImageMeta())
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(ctx, "repo", tag4, multiarch.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", tag5, image5.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", tag6, image6.AsImageMeta())
				So(err, ShouldBeNil)

				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo:0.0")
				So(err, ShouldBeNil)

				tags := map[string]struct{}{}
				for _, imageMeta := range fullImageMetaList {
					tags[imageMeta.Tag] = struct{}{}
				}

				So(len(fullImageMetaList), ShouldEqual, 2)
				So(tags, ShouldContainKey, tag4)
				So(tags, ShouldContainKey, tag5)
				So(tags, ShouldNotContainKey, tag6)

				multiarchImageMeta := mTypes.FullImageMeta{}
				found := false

				for _, imageMeta := range fullImageMetaList {
					if imageMeta.MediaType == ispec.MediaTypeImageIndex {
						multiarchImageMeta = imageMeta
						found = true
					}
				}

				So(found, ShouldBeTrue)
				So(len(multiarchImageMeta.Manifests), ShouldEqual, 2)

				digests := []string{}
				for _, manifest := range multiarchImageMeta.Manifests {
					digests = append(digests, manifest.Digest.String())
				}

				So(digests, ShouldContain, subImage1.DigestStr())
				So(digests, ShouldContain, subImage2.DigestStr())
			})

			Convey("With referrer", func() {
				refImage := CreateRandomImageWith().Subject(image1.DescriptorRef()).Build()
				err := metaDB.SetRepoReference(ctx, repo1, "ref-tag", refImage.AsImageMeta())
				So(err, ShouldBeNil)

				fullImageMetaList, err := metaDB.SearchTags(ctx, "repo1:0.0.1")
				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 1)
				So(len(fullImageMetaList[0].Referrers), ShouldEqual, 1)
				So(fullImageMetaList[0].Referrers[0].Digest, ShouldResemble, refImage.DigestStr())
			})
		})

		Convey("Test FilterTags", func() {
			var (
				repo1  = "repo1"
				repo2  = "repo2"
				image1 = CreateRandomImage()
				image2 = CreateRandomImage()
				image3 = CreateRandomImage()

				subImage1 = CreateRandomImage()
				subImage2 = CreateRandomImage()
				multiarch = CreateMultiarchWith().Images([]Image{subImage1, subImage2}).Build()
				ctx       = context.Background()
			)

			err := metaDB.SetRepoReference(ctx, repo1, subImage1.DigestStr(), subImage1.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, subImage2.DigestStr(), subImage2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "2.0.0", multiarch.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, repo1, "0.0.1", image1.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "0.0.2", image3.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "0.1.0", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "1.0.0", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo1, "1.0.1", image2.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo2, "0.0.1", image3.AsImageMeta())
			So(err, ShouldBeNil)

			Convey("Return all tags", func() {
				fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)

				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 7)

				tags := []string{}
				indexImage := mTypes.FullImageMeta{}

				for _, imageMeta := range fullImageMetaList {
					tags = append(tags, imageMeta.Tag)

					if imageMeta.MediaType == ispec.MediaTypeImageIndex {
						indexImage = imageMeta
					}
				}

				So(zcommon.Contains(tags, "0.0.1"), ShouldBeTrue)
				So(zcommon.Contains(tags, "0.0.2"), ShouldBeTrue)
				So(zcommon.Contains(tags, "0.1.0"), ShouldBeTrue)
				So(zcommon.Contains(tags, "1.0.0"), ShouldBeTrue)
				So(zcommon.Contains(tags, "1.0.1"), ShouldBeTrue)
				So(zcommon.Contains(tags, "2.0.0"), ShouldBeTrue)
				So(zcommon.Contains(tags, "0.0.1"), ShouldBeTrue)

				So(indexImage.Digest.String(), ShouldResemble, multiarch.DigestStr())

				digests := []string{}
				for _, manifest := range indexImage.Manifests {
					digests = append(digests, manifest.Digest.String())
				}

				So(digests, ShouldContain, subImage1.DigestStr())
				So(digests, ShouldContain, subImage2.DigestStr())
			})

			Convey("Return all tags in a specific repo", func() {
				fullImageMetaList, err := metaDB.FilterTags(ctx, func(repo, tag string) bool { return repo == repo1 },
					mTypes.AcceptAllImageMeta)

				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 6)

				tags := map[string]struct{}{}
				indexImage := mTypes.FullImageMeta{}

				for _, imageMeta := range fullImageMetaList {
					tags[imageMeta.Tag] = struct{}{}

					if imageMeta.MediaType == ispec.MediaTypeImageIndex {
						indexImage = imageMeta
					}
				}

				So(tags, ShouldContainKey, "0.0.1")
				So(tags, ShouldContainKey, "0.0.2")
				So(tags, ShouldContainKey, "0.1.0")
				So(tags, ShouldContainKey, "1.0.0")
				So(tags, ShouldContainKey, "1.0.1")
				So(tags, ShouldContainKey, "2.0.0")

				So(indexImage.Digest.String(), ShouldResemble, multiarch.DigestStr())

				digests := []string{}
				for _, manifest := range indexImage.Manifests {
					digests = append(digests, manifest.Digest.String())
				}

				So(digests, ShouldContain, subImage1.DigestStr())
				So(digests, ShouldContain, subImage2.DigestStr())
			})

			Convey("Filter everything out", func() {
				fullImageMetaList, err := metaDB.FilterTags(ctx,
					func(repo, tag string) bool { return false },
					func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool { return false },
				)

				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 0)
			})

			Convey("Search with access control", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("username")
				userAc.SetGlobPatterns("read", map[string]bool{
					repo1: false,
					repo2: true,
				})

				ctx := userAc.DeriveContext(context.Background())

				fullImageMetaList, err := metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)

				So(err, ShouldBeNil)
				So(len(fullImageMetaList), ShouldEqual, 1)
				So(fullImageMetaList[0].Repo, ShouldResemble, repo2)
				So(fullImageMetaList[0].Tag, ShouldResemble, "0.0.1")
			})
		})

		Convey("Test Referrers", func() {
			image1 := CreateRandomImage()

			err := metaDB.SetRepoReference(ctx, "repo", "tag", image1.AsImageMeta())
			So(err, ShouldBeNil)

			// Artifact 1 with artifact type in Manifest
			artifact1 := CreateImageWith().
				RandomLayers(10, 2).DefaultConfig().
				ArtifactType("art-type1").
				Subject(image1.DescriptorRef()).
				Build()

			err = metaDB.SetRepoReference(ctx, "repo", artifact1.DigestStr(), artifact1.AsImageMeta())
			So(err, ShouldBeNil)

			// Artifact 2 with artifact type in Config media type
			artifact2 := CreateImageWith().
				RandomLayers(10, 2).
				ArtifactConfig("art-type2").
				Subject(image1.DescriptorRef()).
				Build()

			err = metaDB.SetRepoReference(ctx, "repo", artifact2.DigestStr(), artifact2.AsImageMeta())
			So(err, ShouldBeNil)

			// GetReferrers
			referrers, err := metaDB.GetReferrersInfo("repo", image1.Digest(), nil)
			So(len(referrers), ShouldEqual, 2)
			So(referrers, ShouldContain, mTypes.ReferrerInfo{
				Digest:       artifact1.DigestStr(),
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "art-type1",
				Size:         int(artifact1.ManifestDescriptor.Size),
			})
			So(referrers, ShouldContain, mTypes.ReferrerInfo{
				Digest:       artifact2.DigestStr(),
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "art-type2",
				Size:         int(artifact2.ManifestDescriptor.Size),
			})
			So(err, ShouldBeNil)

			// Delete the Referrers
			err = metaDB.RemoveRepoReference("repo", artifact1.DigestStr(), artifact1.Digest())
			So(err, ShouldBeNil)

			referrers, err = metaDB.GetReferrersInfo("repo", image1.Digest(), nil)
			So(err, ShouldBeNil)
			So(len(referrers), ShouldEqual, 1)

			err = metaDB.RemoveRepoReference("repo", artifact2.DigestStr(), artifact2.Digest())
			So(err, ShouldBeNil)

			referrers, err = metaDB.GetReferrersInfo("repo", image1.Digest(), nil)
			So(err, ShouldBeNil)
			So(len(referrers), ShouldEqual, 0)
		})

		Convey("Test Referrers add same one twice but with different tags - delete by tag then digest", func() {
			_, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)

			tag := "tag1"
			refTag := "refTag"
			image := CreateRandomImage()
			referrer := CreateRandomImageWith().Subject(image.DescriptorRef()).Build()

			err = metaDB.SetRepoReference(ctx, "repo", tag, image.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", refTag, referrer.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", referrer.DigestStr(), referrer.AsImageMeta())
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 1)

			err = metaDB.RemoveRepoReference("repo", refTag, referrer.Digest())
			So(err, ShouldBeNil)

			// we still have the untagged manifest
			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 1)

			err = metaDB.RemoveRepoReference("repo", referrer.DigestStr(), referrer.Digest())
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 0)
		})

		Convey("Test Referrers add same one twice but with different tags - delete by digest", func() {
			_, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)

			tag := "tag-1"
			refTag := "refTag"
			image := CreateRandomImage()
			referrer := CreateRandomImageWith().Subject(image.DescriptorRef()).Build()

			err = metaDB.SetRepoReference(ctx, "repo", tag, image.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", refTag, referrer.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", referrer.DigestStr(), referrer.AsImageMeta())
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 1)

			// this should delete all references
			err = metaDB.RemoveRepoReference("repo", referrer.DigestStr(), referrer.Digest())
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 0)
		})

		Convey("Test Referrers add same one twice", func() {
			_, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)

			tag := "tag-ref"
			image := CreateRandomImage()
			referrer := CreateRandomImageWith().Subject(image.DescriptorRef()).Build()

			err = metaDB.SetRepoReference(ctx, "repo", tag, image.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", referrer.DigestStr(), referrer.AsImageMeta())
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(ctx, "repo", referrer.DigestStr(), referrer.AsImageMeta())
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[image.DigestStr()]), ShouldEqual, 1)
		})

		Convey("GetReferrersInfo", func() {
			repo := "repo"
			tag := "test-tag"

			image := CreateRandomImage()
			err := metaDB.SetRepoReference(ctx, repo, tag, image.AsImageMeta())
			So(err, ShouldBeNil)

			referrerWantedType := CreateRandomImageWith().
				ArtifactType("wanted-type").
				Subject(image.DescriptorRef()).Build()

			referrerNotWantedType := CreateRandomImageWith().
				ArtifactType("not-wanted-type").
				Subject(image.DescriptorRef()).Build()

			err = metaDB.SetRepoReference(ctx, repo, referrerWantedType.DigestStr(),
				referrerWantedType.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo, referrerNotWantedType.DigestStr(),
				referrerNotWantedType.AsImageMeta())
			So(err, ShouldBeNil)

			referrerInfo, err := metaDB.GetReferrersInfo("repo", image.Digest(), []string{"wanted-type"})
			So(err, ShouldBeNil)
			So(len(referrerInfo), ShouldEqual, 1)
			So(referrerInfo[0].ArtifactType, ShouldResemble, "wanted-type")
			So(referrerInfo[0].Digest, ShouldResemble, referrerWantedType.DigestStr())
		})

		Convey("FilterImageMeta", func() {
			repo := "repo"
			tag := "tag"

			Convey("Just manifests", func() {
				image := CreateRandomImage()
				err := metaDB.SetRepoReference(ctx, repo, tag, image.AsImageMeta())
				So(err, ShouldBeNil)

				imageMeta, err := metaDB.FilterImageMeta(ctx, []string{image.DigestStr()})
				So(err, ShouldBeNil)
				So(imageMeta, ShouldContainKey, image.DigestStr())

				_, err = metaDB.FilterImageMeta(ctx, []string{image.DigestStr(), "bad-digest"})
				So(err, ShouldNotBeNil)
			})

			Convey("Index", func() {
				multi := CreateRandomMultiarch()
				digests := []string{}

				for i := range multi.Images {
					err := metaDB.SetRepoReference(ctx, repo, multi.Images[i].DigestStr(),
						multi.Images[i].AsImageMeta())
					So(err, ShouldBeNil)

					digests = append(digests, multi.Images[i].DigestStr())
				}

				err := metaDB.SetRepoReference(ctx, repo, tag, multi.AsImageMeta())
				So(err, ShouldBeNil)

				imageMeta, err := metaDB.FilterImageMeta(ctx, []string{multi.DigestStr()})
				So(err, ShouldBeNil)
				So(imageMeta, ShouldContainKey, multi.DigestStr())

				actualDigests := tCommon.AccumulateField(imageMeta[multi.DigestStr()].Manifests, getManifestDigest)
				So(tCommon.ContainSameElements(actualDigests, digests), ShouldBeTrue)
			})
		})

		Convey("ResetDB", func() {
			repo := "repo-reset"
			tag := "tag-reset"

			image := CreateRandomImage()
			referrer := CreateRandomImageWith().Subject(image.DescriptorRef()).Build()
			err := metaDB.SetRepoReference(ctx, repo, tag, image.AsImageMeta())
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo, tag, referrer.AsImageMeta())
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
			So(err, ShouldBeNil)
			So(repoMeta.Tags, ShouldNotBeEmpty)
			So(repoMeta.Statistics, ShouldNotBeEmpty)
			So(repoMeta.Referrers, ShouldNotBeEmpty)

			err = metaDB.ResetDB()
			So(err, ShouldBeNil)

			_, err = metaDB.GetRepoMeta(ctx, repo)
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos", func() {
			repo := "repoFilter"
			tag1 := "tag1"
			tag2 := "tag22"

			image := CreateImageWith().DefaultLayers().PlatformConfig("image-platform", "image-os").Build()
			err := metaDB.SetRepoReference(ctx, repo, tag1, image.AsImageMeta())
			So(err, ShouldBeNil)

			multiarch := CreateMultiarchWith().
				Images([]Image{
					CreateImageWith().DefaultLayers().PlatformConfig("sub-platform1", "sub-os1").Build(),
					CreateImageWith().DefaultLayers().PlatformConfig("sub-platform2", "sub-os2").Build(),
				}).Build()

			for _, img := range multiarch.Images {
				err := metaDB.SetRepoReference(ctx, repo, img.DigestStr(), img.AsImageMeta())
				So(err, ShouldBeNil)
			}

			err = metaDB.SetRepoReference(ctx, repo, tag2, multiarch.AsImageMeta())
			So(err, ShouldBeNil)

			//nolint: contextcheck
			repoMetaList, err := metaDB.FilterRepos(context.Background(), mTypes.AcceptAllRepoNames,
				mTypes.AcceptAllRepoMeta)
			So(err, ShouldBeNil)
			So(len(repoMetaList), ShouldEqual, 1)
			repoMeta := repoMetaList[0]
			So(repoMeta.Platforms, ShouldContain, ispec.Platform{Architecture: "image-platform", OS: "image-os"})
			So(repoMeta.Platforms, ShouldContain, ispec.Platform{Architecture: "sub-platform1", OS: "sub-os1"})
			So(repoMeta.Platforms, ShouldContain, ispec.Platform{Architecture: "sub-platform2", OS: "sub-os2"})
		})

		Convey("Test bookmarked/starred field present in returned RepoMeta", func() {
			repo99 := "repo99"
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("user1")
			userAc.SetGlobPatterns("read", map[string]bool{
				repo99: true,
			})

			ctx := userAc.DeriveContext(context.Background())

			image := CreateRandomImage()

			err := metaDB.SetRepoReference(ctx, repo99, "tag", image.AsImageMeta())
			So(err, ShouldBeNil)

			repoMetaList, err := metaDB.SearchRepos(ctx, repo99)
			So(err, ShouldBeNil)
			So(len(repoMetaList), ShouldEqual, 1)
			So(repoMetaList[0].IsBookmarked, ShouldBeFalse)
			So(repoMetaList[0].IsStarred, ShouldBeFalse)

			fullImageMetaList, err := metaDB.SearchTags(ctx, repo99+":")
			So(err, ShouldBeNil)
			So(len(fullImageMetaList), ShouldEqual, 1)
			So(fullImageMetaList[0].IsBookmarked, ShouldBeFalse)
			So(fullImageMetaList[0].IsStarred, ShouldBeFalse)

			repoMetaList, err = metaDB.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
			So(err, ShouldBeNil)
			So(len(repoMetaList), ShouldEqual, 1)
			So(repoMetaList[0].IsBookmarked, ShouldBeFalse)
			So(repoMetaList[0].IsStarred, ShouldBeFalse)

			fullImageMetaList, err = metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
			So(err, ShouldBeNil)
			So(len(fullImageMetaList), ShouldEqual, 1)
			So(fullImageMetaList[0].IsBookmarked, ShouldBeFalse)
			So(fullImageMetaList[0].IsStarred, ShouldBeFalse)

			_, err = metaDB.ToggleBookmarkRepo(ctx, repo99)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, repo99)
			So(err, ShouldBeNil)

			repoMetaList, err = metaDB.SearchRepos(ctx, repo99)
			So(err, ShouldBeNil)
			So(len(repoMetaList), ShouldEqual, 1)
			So(repoMetaList[0].IsBookmarked, ShouldBeTrue)
			So(repoMetaList[0].IsStarred, ShouldBeTrue)

			fullImageMetaList, err = metaDB.SearchTags(ctx, repo99+":")
			So(err, ShouldBeNil)
			So(len(fullImageMetaList), ShouldEqual, 1)
			So(fullImageMetaList[0].IsBookmarked, ShouldBeTrue)
			So(fullImageMetaList[0].IsStarred, ShouldBeTrue)

			repoMetaList, err = metaDB.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
			So(err, ShouldBeNil)
			So(len(repoMetaList), ShouldEqual, 1)
			So(repoMetaList[0].IsBookmarked, ShouldBeTrue)
			So(repoMetaList[0].IsStarred, ShouldBeTrue)

			fullImageMetaList, err = metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
			So(err, ShouldBeNil)
			So(len(fullImageMetaList), ShouldEqual, 1)
			So(fullImageMetaList[0].IsBookmarked, ShouldBeTrue)
			So(fullImageMetaList[0].IsStarred, ShouldBeTrue)
		})

		Convey("Test GetUserRepoMeta", func() {
			err := metaDB.ResetDB()
			So(err, ShouldBeNil)

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("user1")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = metaDB.SetRepoReference(ctx, "repo", "tag", CreateDefaultImage().AsImageMeta())
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.IsBookmarked, ShouldBeTrue)
			So(repoMeta.IsStarred, ShouldBeTrue)
			So(repoMeta.Tags, ShouldContainKey, "tag")
		})

		Convey("GetAllRepoNames", func() {
			repo1 := "repo1"
			repo2 := "repo2"
			repo3 := "repo3"
			imageMeta := CreateRandomImage().AsImageMeta()

			err := metaDB.SetRepoReference(ctx, repo1, "tag", imageMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo2, "tag", imageMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(ctx, repo3, "tag", imageMeta)
			So(err, ShouldBeNil)

			repos, err := metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)
			So(repos, ShouldContain, repo3)

			err = metaDB.DeleteRepoMeta(repo1)
			So(err, ShouldBeNil)

			repos, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldNotContain, repo1)
			So(repos, ShouldContain, repo2)
			So(repos, ShouldContain, repo3)

			err = metaDB.DeleteRepoMeta(repo2)
			So(err, ShouldBeNil)

			repos, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldNotContain, repo1)
			So(repos, ShouldNotContain, repo2)
			So(repos, ShouldContain, repo3)

			err = metaDB.SetRepoReference(ctx, repo1, "tag", imageMeta)
			So(err, ShouldBeNil)

			repos, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldNotContain, repo2)
			So(repos, ShouldContain, repo3)

			err = metaDB.DeleteRepoMeta(repo1)
			So(err, ShouldBeNil)

			repos, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldNotContain, repo1)
			So(repos, ShouldNotContain, repo2)
			So(repos, ShouldContain, repo3)

			err = metaDB.DeleteRepoMeta(repo3)
			So(err, ShouldBeNil)

			repos, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(repos, ShouldNotContain, repo1)
			So(repos, ShouldNotContain, repo2)
			So(repos, ShouldNotContain, repo3)
		})
	})
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
	})
}

func TestCreateDynamo(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("Create", t, func() {
		dynamoDBDriverParams := mdynamodb.DBDriverParameters{
			Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:      "RepoMetadataTable",
			RepoBlobsInfoTablename: "RepoBlobs",
			ImageMetaTablename:     "ImageMeta",
			UserDataTablename:      "UserDataTable",
			APIKeyTablename:        "ApiKeyTable",
			VersionTablename:       "Version",
			Region:                 "us-east-2",
		}

		client, err := mdynamodb.GetDynamoClient(dynamoDBDriverParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		metaDB, err := meta.Create("dynamodb", client, dynamoDBDriverParams, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("Fails", t, func() {
		log := log.NewLogger("debug", "")

		_, err := meta.Create("dynamodb", nil, boltdb.DBParameters{RootDir: "root"}, log)
		So(err, ShouldNotBeNil)

		_, err = meta.Create("dynamodb", &dynamodb.Client{}, "bad", log)
		So(err, ShouldNotBeNil)

		metaDB, err := meta.Create("random", nil, boltdb.DBParameters{RootDir: "root"}, log)
		So(metaDB, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})
}

func TestCreateBoltDB(t *testing.T) {
	Convey("Create", t, func() {
		rootDir := t.TempDir()
		params := boltdb.DBParameters{
			RootDir: rootDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		metaDB, err := meta.Create("boltdb", boltDriver, params, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("fails", t, func() {
		log := log.NewLogger("debug", "")

		_, err := meta.Create("boltdb", nil, mdynamodb.DBDriverParameters{}, log)
		So(err, ShouldNotBeNil)
	})
}
