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
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/meta/repodb/common"
	dynamo "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	dynamoParams "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/params"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

const (
	LINUX   = "linux"
	WINDOWS = "windows"
	AMD     = "amd"
)

func TestBoltDBWrapper(t *testing.T) {
	Convey("BoltDB Wrapper creation", t, func() {
		boltDBParams := bolt.DBParameters{}
		searchDB, err := bolt.NewBoltDBWrapper(boltDBParams)
		So(searchDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod("repo.db", 0o200)
		So(err, ShouldBeNil)

		searchDB, err = bolt.NewBoltDBWrapper(boltDBParams)
		So(searchDB, ShouldBeNil)
		So(err, ShouldNotBeNil)

		err = os.Chmod("repo.db", 0o600)
		So(err, ShouldBeNil)

		defer os.Remove("repo.db")
	})

	Convey("BoltDB Wrapper", t, func() {
		boltDBParams := bolt.DBParameters{}
		boltdbWrapper, err := bolt.NewBoltDBWrapper(boltDBParams)
		defer os.Remove("repo.db")
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		RunRepoDBTests(boltdbWrapper)
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

	Convey("DynamoDB Wrapper", t, func() {
		dynamoDBDriverParams := dynamoParams.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			VersionTablename:      versionTablename,
			Region:                "us-east-2",
		}

		dynamoDriver, err := dynamo.NewDynamoDBWrapper(dynamoDBDriverParams)
		So(dynamoDriver, ShouldNotBeNil)
		So(err, ShouldBeNil)

		resetDynamoDBTables := func() error {
			err := dynamoDriver.ResetRepoMetaTable()
			if err != nil {
				return err
			}

			err = dynamoDriver.ResetManifestDataTable()

			return err
		}

		RunRepoDBTests(dynamoDriver, resetDynamoDBTables)
	})
}

func RunRepoDBTests(repoDB repodb.RepoDB, preparationFuncs ...func() error) {
	Convey("Test RepoDB Interface implementation", func() {
		for _, prepFunc := range preparationFuncs {
			err := prepFunc()
			So(err, ShouldBeNil)
		}

		Convey("Test SetManifestData and GetManifestData", func() {
			configBlob, manifestBlob, err := generateTestImage()
			So(err, ShouldBeNil)

			manifestDigest := digest.FromBytes(manifestBlob)

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

		Convey("Test SetRepoTag", func() {
			// test behaviours
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")

				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifes2")
			)

			Convey("Setting a good repo", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)
			})

			Convey("Set multiple tags for repo", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)
				So(repoMeta.Tags[tag2].Digest, ShouldEqual, manifestDigest2)
			})

			Convey("Set multiple repos", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
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
					err := repoDB.SetRepoTag("", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Tag is not valid", func() {
					err := repoDB.SetRepoTag(repo1, "", manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Manifest Digest is not valid", func() {
					err := repoDB.SetRepoTag(repo1, tag1, "", ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("Test GetRepoMeta", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")

				repo2           = "repo2"
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2")

				InexistentRepo = "InexistentRepo"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2")
			)

			err := repoDB.SetRepoTag(repo, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
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

			Convey("Delete all tags from repo", func() {
				err := repoDB.DeleteRepoTag(repo, tag1)
				So(err, ShouldBeNil)
				err = repoDB.DeleteRepoTag(repo, tag2)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldNotBeNil)
				So(repoMeta, ShouldBeZeroValue)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
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

			repoMeta, err = repoDB.GetRepoMeta("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
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

		Convey("Test IncrementImageDownloads", func() {
			var (
				repo1 = "repo1"
				tag1  = "0.0.1"
			)

			configBlob, manifestBlob, err := generateTestImage()
			So(err, ShouldBeNil)

			manifestDigest := digest.FromBytes(manifestBlob)

			err = repoDB.SetRepoTag(repo1, tag1, manifestDigest, ispec.MediaTypeImageManifest)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
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

		Convey("Test DeleteSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
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
				manifestDigest1 = digest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2")
				tag3            = "0.0.3"
				manifestDigest3 = digest.FromString("fake-manifest3")
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
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, _, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(len(manifesMetaMap), ShouldEqual, 3)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())
			})

			Convey("Search a repo by name", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, _, err := repoDB.SearchRepos(ctx, repo1, repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(manifesMetaMap), ShouldEqual, 1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("Search non-existing repo by name", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, _, err := repoDB.SearchRepos(ctx, "RepoThatDoesntExist", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
			})

			Convey("Search with partial match", func() {
				err := repoDB.SetRepoTag("alpine", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag("pine", tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag("golang", tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta("alpine", manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta("pine", manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta("golang", manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, _, err := repoDB.SearchRepos(ctx, "pine", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifesMetaMap, ShouldNotContainKey, manifestDigest3.String())
			})

			Convey("Search multiple repos that share manifests", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(repo3, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, _, err := repoDB.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 3)
				So(len(manifesMetaMap), ShouldEqual, 1)
			})

			Convey("Search repos with access control", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
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

				repos, _, _, err := repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
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
					manifestDigest := digest.FromString("fakeManifest" + strconv.Itoa(i))
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

					err = repoDB.SetRepoTag(repoName, tag1, manifestDigest, ispec.MediaTypeImageManifest)
					So(err, ShouldBeNil)

					err = repoDB.SetManifestMeta(repoName, manifestDigest, manifestMeta)
					So(err, ShouldBeNil)

					repoNameBuilder.Reset()
				}

				repos, _, _, err := repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, reposCount)

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  20,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 20)

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo1")

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				// sort by downloads
				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.Downloads,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				// sort by last update
				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				repos, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(repos, ShouldBeEmpty)
			})

			Convey("Search with wrong pagination input", func() {
				_, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)

				_, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  -1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: -1,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, err = repoDB.SearchRepos(ctx, "repo", repodb.Filter{}, repodb.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: repodb.SortCriteria("InvalidSortingCriteria"),
				})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Test SearchTags", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				manifestDigest1 = digest.FromString("fake-manifest1")
				manifestDigest2 = digest.FromString("fake-manifest2")
				manifestDigest3 = digest.FromString("fake-manifest3")
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

			err = repoDB.SetRepoTag(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
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
				repos, manifesMetaMap, _, err := repoDB.SearchTags(ctx, "repo1:0.0.1", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("With partial repo path", func() {
				repos, manifesMetaMap, _, err := repoDB.SearchTags(ctx, "repo:0.0.1", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
			})

			Convey("With partial tag", func() {
				repos, manifesMetaMap, _, err := repoDB.SearchTags(ctx, "repo1:0.0", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 2)
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())

				repos, manifesMetaMap, _, err = repoDB.SearchTags(ctx, "repo1:0.", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 3)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())
			})

			Convey("With bad query", func() {
				repos, manifesMetaMap, _, err := repoDB.SearchTags(ctx, "repo:0.0.1:test", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
			})

			Convey("Search with access control", func() {
				var (
					repo1           = "repo1"
					repo2           = "repo2"
					repo3           = "repo3"
					tag1            = "0.0.1"
					manifestDigest1 = digest.FromString("fake-manifest1")
					tag2            = "0.0.2"
					tag3            = "0.0.3"
				)

				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
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

				repos, _, _, err := repoDB.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, repo1)

				repos, _, _, err = repoDB.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(repos, ShouldBeEmpty)
			})

			Convey("With wrong pagination input", func() {
				repos, _, _, err := repoDB.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{
					Limit: -1,
				})
				So(err, ShouldNotBeNil)
				So(repos, ShouldBeEmpty)
			})
		})

		Convey("Paginated tag search", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				tag3            = "0.0.3"
				tag4            = "0.0.4"
				tag5            = "0.0.5"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag4, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag5, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			config := ispec.Image{}
			configBlob, err := json.Marshal(config)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, repodb.ManifestMetadata{ConfigBlob: configBlob})
			So(err, ShouldBeNil)

			repos, _, _, err := repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
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

			repos, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
				Limit:  1,
				Offset: 1,
				SortBy: repodb.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.Filter{}, repodb.PageInput{
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
				manifestDigest1 = digest.FromString("fake-manifest1")
				manifestDigest2 = digest.FromString("fake-manifest2")
				manifestDigest3 = digest.FromString("fake-manifest3")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
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

			repos, _, _, err := repoDB.SearchRepos(context.TODO(), "", filter, repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo2")

			opSys = WINDOWS
			filter = repodb.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter, repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo3")

			opSys = "wrong"
			filter = repodb.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter, repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			opSys = LINUX
			arch = AMD
			filter = repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter, repodb.PageInput{SortBy: repodb.AlphabeticAsc})
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
			repos, _, _, err = repoDB.SearchRepos(context.TODO(), "repo", filter, repodb.PageInput{SortBy: repodb.AlphabeticAsc})
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
				manifestDigest1 = digest.FromString("fake-manifest1")
				manifestDigest2 = digest.FromString("fake-manifest2")
				manifestDigest3 = digest.FromString("fake-manifest3")
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
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
			arch := AMD
			filter := repodb.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, err := repoDB.SearchTags(context.TODO(), "repo1:", filter,
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
			repos, _, _, err = repoDB.SearchTags(context.TODO(), "repo1:", filter,
				repodb.PageInput{SortBy: repodb.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)
		})

		Convey("Test FilterTags", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				manifestDigest1 = digest.FromString("fake-manifest1")
				manifestDigest2 = digest.FromString("fake-manifest2")
				manifestDigest3 = digest.FromString("fake-manifest3")
				ctx             = context.Background()
				emptyManifest   ispec.Manifest
				emptyConfig     ispec.Image
			)

			emptyManifestBlob, err := json.Marshal(emptyManifest)
			So(err, ShouldBeNil)

			emptyConfigBlob, err := json.Marshal(emptyConfig)
			So(err, ShouldBeNil)

			emptyRepoMeta := repodb.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = repoDB.SetRepoTag(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(repo2, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			Convey("Return all tags", func() {
				repos, manifesMetaMap, pageInfo, err := repoDB.FilterTags(
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
				So(len(repos[0].Tags), ShouldEqual, 5)
				So(len(repos[1].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.1")
				So(repos[1].Tags, ShouldContainKey, "0.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())
				So(pageInfo.ItemCount, ShouldEqual, 6)
				So(pageInfo.TotalCount, ShouldEqual, 6)
			})

			Convey("Return all tags in a specific repo", func() {
				repos, manifesMetaMap, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return repoMeta.Name == repo1
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldEqual, repo1)
				So(len(repos[0].Tags), ShouldEqual, 5)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.0")
				So(repos[0].Tags, ShouldContainKey, "1.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
			})

			Convey("Filter everything out", func() {
				repos, manifesMetaMap, pageInfo, err := repoDB.FilterTags(
					ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool {
						return false
					},
					repodb.PageInput{Limit: 10, Offset: 0, SortBy: repodb.AlphabeticAsc},
				)

				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
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

				repos, manifesMetaMap, pageInfo, err := repoDB.FilterTags(
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
				So(manifesMetaMap, ShouldContainKey, manifestDigest3.String())
				So(pageInfo.ItemCount, ShouldEqual, 1)
				So(pageInfo.TotalCount, ShouldEqual, 1)
			})

			Convey("With wrong pagination input", func() {
				repos, _, _, err := repoDB.FilterTags(
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
	})
}

func TestRelevanceSorting(t *testing.T) {
	Convey("Test Relevance Sorting", t, func() {
		So(common.ScoreRepoName("alpine", "alpine"), ShouldEqual, 1)
		So(common.ScoreRepoName("test/alpine", "alpine"), ShouldEqual, -1)
		So(common.ScoreRepoName("alpine", "test/alpine"), ShouldEqual, 1)
		So(common.ScoreRepoName("test", "test/alpine"), ShouldEqual, 10)
		So(common.ScoreRepoName("pine", "test/alpine"), ShouldEqual, 3)
		So(common.ScoreRepoName("pine", "alpine/alpine"), ShouldEqual, 3)
		So(common.ScoreRepoName("pine", "alpine/test"), ShouldEqual, 30)
		So(common.ScoreRepoName("test/pine", "alpine"), ShouldEqual, -1)
		So(common.ScoreRepoName("repo/test", "repo/test/alpine"), ShouldEqual, 1)
		So(common.ScoreRepoName("repo/test/golang", "repo/test2/alpine"), ShouldEqual, -1)
		So(common.ScoreRepoName("repo/test/pine", "repo/test/alpine"), ShouldEqual, 3)

		Convey("Integration", func() {
			filePath := path.Join(t.TempDir(), "repo.db")
			boltDBParams := bolt.DBParameters{
				RootDir: t.TempDir(),
			}

			repoDB, err := bolt.NewBoltDBWrapper(boltDBParams)
			So(repoDB, ShouldNotBeNil)
			So(err, ShouldBeNil)

			defer os.Remove(filePath)

			var (
				repo1           = "alpine"
				repo2           = "alpine/test"
				repo3           = "notalpine"
				repo4           = "unmached/repo"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1")
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2")
				tag3            = "0.0.3"
				manifestDigest3 = digest.FromString("fake-manifest3")
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

			err = repoDB.SetRepoTag(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo3, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
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

			repos, _, _, err := repoDB.SearchRepos(ctx, "pine", repodb.Filter{},
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
			DiffIDs: []digest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	configDigest := digest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, 100),
	}

	// init layers with random values
	for i := range layers {
		//nolint:gosec
		_, err := rand.Read(layers[i])
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
				Digest:    digest.FromBytes(layers[0]),
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
