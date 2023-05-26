package meta_test

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
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/dynamodb"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
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
		boltDBParams := boltdb.DBParameters{}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		metaDB, err := boltdb.New(boltDriver, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod("repo.db", 0o200)
		So(err, ShouldBeNil)

		_, err = boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldNotBeNil)

		err = os.Chmod("repo.db", 0o600)
		So(err, ShouldBeNil)

		defer os.Remove("repo.db")
	})

	Convey("BoltDB Wrapper", t, func() {
		boltDBParams := boltdb.DBParameters{}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb.New(boltDriver, log)
		defer os.Remove("repo.db")
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		RunMetaDBTests(boltdbWrapper)
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

	Convey("DynamoDB Wrapper", t, func() {
		dynamoDBDriverParams := dynamodb.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			RepoMetaTablename:     repoMetaTablename,
			ManifestDataTablename: manifestDataTablename,
			IndexDataTablename:    indexDataTablename,
			VersionTablename:      versionTablename,
			UserDataTablename:     userDataTablename,
			Region:                "us-east-2",
		}

		dynamoClient, err := dynamodb.GetDynamoClient(dynamoDBDriverParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		dynamoDriver, err := dynamodb.New(dynamoClient, dynamoDBDriverParams, log)
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

		RunMetaDBTests(dynamoDriver, resetDynamoDBTables)
	})
}

func RunMetaDBTests(metaDB metaTypes.MetaDB, preparationFuncs ...func() error) {
	Convey("Test MetaDB Interface implementation", func() {
		for _, prepFunc := range preparationFuncs {
			err := prepFunc()
			So(err, ShouldBeNil)
		}

		Convey("Test SetManifestData and GetManifestData", func() {
			configBlob, manifestBlob, err := generateTestImage()
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob)

			err = metaDB.SetManifestData(manifestDigest, metaTypes.ManifestData{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			mm, err := metaDB.GetManifestData(manifestDigest)
			So(err, ShouldBeNil)
			So(mm.ManifestBlob, ShouldResemble, manifestBlob)
			So(mm.ConfigBlob, ShouldResemble, configBlob)
		})

		Convey("Test GetManifestMeta fails", func() {
			_, err := metaDB.GetManifestMeta("repo", "bad digest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test SetManifestMeta", func() {
			Convey("RepoMeta not found", func() {
				var (
					manifestDigest = godigest.FromString("dig")
					manifestBlob   = []byte("manifestBlob")
					configBlob     = []byte("configBlob")

					signatures = metaTypes.ManifestSignatures{
						"digest1": []metaTypes.SignatureInfo{
							{
								SignatureManifestDigest: "signatureDigest",
								LayersInfo: []metaTypes.LayerInfo{
									{
										LayerDigest:  "layerDigest",
										LayerContent: []byte("layerContent"),
									},
								},
							},
						},
					}
				)

				err := metaDB.SetManifestMeta("repo", manifestDigest, metaTypes.ManifestMetadata{
					ManifestBlob:  manifestBlob,
					ConfigBlob:    configBlob,
					DownloadCount: 10,
					Signatures:    signatures,
				})
				So(err, ShouldBeNil)

				manifestMeta, err := metaDB.GetManifestMeta("repo", manifestDigest)
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
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)

				err = metaDB.SetRepoMeta(repo2, metaTypes.RepoMetadata{Tags: map[string]metaTypes.Descriptor{
					tag2: {
						Digest: manifestDigest2.String(),
					},
				}})
				So(err, ShouldBeNil)

				repoMeta, err = metaDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo2)
				So(repoMeta.Tags[tag2].Digest, ShouldEqual, manifestDigest2)
			})

			Convey("Setting a good repo using a digest", func() {
				_, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldNotBeNil)

				digest := godigest.FromString("digest")
				err = metaDB.SetRepoReference(repo1, digest.String(), digest,
					ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Name, ShouldResemble, repo1)
			})

			Convey("Set multiple tags for repo", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1].Digest, ShouldEqual, manifestDigest1)
				So(repoMeta.Tags[tag2].Digest, ShouldEqual, manifestDigest2)
			})

			Convey("Set multiple repos", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repoMeta1, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				repoMeta2, err := metaDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)

				So(repoMeta1.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())
				So(repoMeta2.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Setting a repo with invalid fields", func() {
				Convey("Repo name is not valid", func() {
					err := metaDB.SetRepoReference("", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Tag is not valid", func() {
					err := metaDB.SetRepoReference(repo1, "", manifestDigest1, ispec.MediaTypeImageManifest)
					So(err, ShouldNotBeNil)
				})

				Convey("Manifest Digest is not valid", func() {
					err := metaDB.SetRepoReference(repo1, tag1, "", ispec.MediaTypeImageManifest)
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Get a existent repo", func() {
				repoMeta1, err := metaDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta1.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())

				repoMeta2, err := metaDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)
				So(repoMeta2.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Get a repo that doesn't exist", func() {
				repoMeta, err := metaDB.GetRepoMeta(InexistentRepo)
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

			err := metaDB.SetRepoReference(repo, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Delete from repo a tag", func() {
				_, err := metaDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				err = metaDB.DeleteRepoTag(repo, tag1)
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				_, ok := repoMeta.Tags[tag1]
				So(ok, ShouldBeFalse)
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Delete inexistent tag from repo", func() {
				err := metaDB.DeleteRepoTag(repo, "InexistentTag")
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1].Digest, ShouldResemble, manifestDigest1.String())
				So(repoMeta.Tags[tag2].Digest, ShouldResemble, manifestDigest2.String())
			})

			Convey("Delete from inexistent repo", func() {
				err := metaDB.DeleteRepoTag("InexistentRepo", "InexistentTag")
				So(err, ShouldBeNil)

				repoMeta, err := metaDB.GetRepoMeta(repo)
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo2, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			Convey("Get all Repometa", func() {
				repoMetaSlice, err := metaDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta metaTypes.RepoMetadata) bool {
					return true
				}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 2)
			})

			Convey("Get repo with a tag", func() {
				repoMetaSlice, err := metaDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta metaTypes.RepoMetadata) bool {
					for tag := range repoMeta.Tags {
						if tag == tag1 {
							return true
						}
					}

					return false
				}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repoMetaSlice), ShouldEqual, 1)
				So(repoMetaSlice[0].Tags[tag1].Digest == manifestDigest1.String(), ShouldBeTrue)
			})

			Convey("Wrong page input", func() {
				repoMetaSlice, err := metaDB.GetMultipleRepoMeta(context.TODO(), func(repoMeta metaTypes.RepoMetadata) bool {
					for tag := range repoMeta.Tags {
						if tag == tag1 {
							return true
						}
					}

					return false
				}, metaTypes.PageInput{Limit: -1, Offset: -1})

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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 2)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 3)
		})

		Convey("Test DecrementRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			err = metaDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 0)

			err = metaDB.DecrementRepoStars(repo1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 0)

			_, err = metaDB.GetRepoMeta("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			stars, err := metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(stars, ShouldEqual, 1)

			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)
			err = metaDB.IncrementRepoStars(repo1)
			So(err, ShouldBeNil)

			stars, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(stars, ShouldEqual, 3)

			_, err = metaDB.GetRepoStars("badRepo")
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			starCount, err := metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

			starCount, err = metaDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 2)

			starCount, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 2)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

			repoMeta, err = metaDB.GetRepoMeta(repo2)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = metaDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

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
			So(toggleState, ShouldEqual, metaTypes.Removed)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

			toggleState, err = metaDB.ToggleStarRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, metaTypes.Removed)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			repoMeta, err = metaDB.GetRepoMeta(repo2)
			So(err, ShouldBeNil)
			So(repoMeta.Stars, ShouldEqual, 1)

			starCount, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			starCount, err = metaDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

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

			// Anonyous user attempts to toggle a star
			toggleState, err = metaDB.ToggleStarRepo(ctx3, repo1)
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, metaTypes.NotChanged)

			starCount, err = metaDB.GetRepoStars(repo1)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 1)

			repos, err = metaDB.GetStarredRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 stars just repo 1
			toggleState, err = metaDB.ToggleStarRepo(ctx1, repo2)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, metaTypes.Removed)

			starCount, err = metaDB.GetRepoStars(repo2)
			So(err, ShouldBeNil)
			So(starCount, ShouldEqual, 0)

			repos, err = metaDB.GetStarredRepos(ctx3)
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			repos, err := metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// anonymous cannot use bookmarks
			repos, err = metaDB.GetBookmarkedRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			toggleState, err := metaDB.ToggleBookmarkRepo(ctx3, repo1)
			So(err, ShouldNotBeNil)
			So(toggleState, ShouldEqual, metaTypes.NotChanged)

			repos, err = metaDB.GetBookmarkedRepos(ctx3)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 bookmarks repo 1, User 2 has no bookmarks
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx1, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, metaTypes.Added)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos, ShouldContain, repo1)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			// User 1 and User 2 bookmark only repo 1
			toggleState, err = metaDB.ToggleBookmarkRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, metaTypes.Added)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

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
			So(toggleState, ShouldEqual, metaTypes.Removed)

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
			So(toggleState, ShouldEqual, metaTypes.Added)

			toggleState, err = metaDB.ToggleBookmarkRepo(ctx2, repo1)
			So(err, ShouldBeNil)
			So(toggleState, ShouldEqual, metaTypes.Removed)

			repos, err = metaDB.GetBookmarkedRepos(ctx1)
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos, ShouldContain, repo1)
			So(repos, ShouldContain, repo2)

			repos, err = metaDB.GetBookmarkedRepos(ctx2)
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

			err = metaDB.SetRepoReference(repo1, tag1, manifestDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest, metaTypes.ManifestMetadata{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			err = metaDB.IncrementImageDownloads(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 1)

			err = metaDB.IncrementImageDownloads(repo1, tag1)
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)

			So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 2)

			_, err = metaDB.GetManifestMeta(repo1, "badManiestDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test AddImageSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, metaTypes.ManifestMetadata{})
			So(err, ShouldBeNil)

			err = metaDB.AddManifestSignature(repo1, manifestDigest1, metaTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			_, err = metaDB.GetManifestMeta(repo1, "badDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test AddImageSignature with inverted order", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := metaDB.AddManifestSignature(repo1, manifestDigest1, metaTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestData(manifestDigest1, metaTypes.ManifestData{})
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			_, err = metaDB.GetManifestMeta(repo1, "badDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test DeleteSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = godigest.FromString("fake-manifest1")
			)

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestData(manifestDigest1, metaTypes.ManifestData{})
			So(err, ShouldBeNil)

			err = metaDB.AddManifestSignature(repo1, manifestDigest1, metaTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"][0].SignatureManifestDigest,
				ShouldResemble, "digest")

			err = metaDB.DeleteSignature(repo1, manifestDigest1, metaTypes.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Signatures[manifestDigest1.String()]["cosign"], ShouldBeEmpty)

			err = metaDB.DeleteSignature(repo1, "badDigest", metaTypes.SignatureMetadata{
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

			emptyRepoMeta := metaTypes.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			Convey("Search all repos", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := metaDB.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(len(manifestMetaMap), ShouldEqual, 3)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())
			})

			Convey("Search a repo by name", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := metaDB.SearchRepos(ctx, repo1, metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(manifestMetaMap), ShouldEqual, 1)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("Search non-existing repo by name", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := metaDB.SearchRepos(ctx, "RepoThatDoesntExist", metaTypes.Filter{},
					metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
			})

			Convey("Search with partial match", func() {
				err := metaDB.SetRepoReference("alpine", tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference("pine", tag2, manifestDigest2, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference("golang", tag3, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta("alpine", manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta("pine", manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta("golang", manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := metaDB.SearchRepos(ctx, "pine", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest2.String())
				So(manifestMetaMap, ShouldNotContainKey, manifestDigest3.String())
			})

			Convey("Search multiple repos that share manifests", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo3, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, _, _, err := metaDB.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 3)
				So(len(manifestMetaMap), ShouldEqual, 1)
			})

			Convey("Search repos with access control", func() {
				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo3, manifestDigest1, emptyRepoMeta)
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

				repos, _, _, _, err := metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{})
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

					manifestMeta := metaTypes.ManifestMetadata{
						ManifestBlob:  emptyManifestBlob,
						ConfigBlob:    configBlob,
						DownloadCount: i,
					}
					repoName := "repo" + strconv.Itoa(i)

					err = metaDB.SetRepoReference(repoName, tag1, manifestDigest, ispec.MediaTypeImageManifest)
					So(err, ShouldBeNil)

					err = metaDB.SetManifestMeta(repoName, manifestDigest, manifestMeta)
					So(err, ShouldBeNil)

					repoNameBuilder.Reset()
				}

				repos, _, _, _, err := metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, reposCount)

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  20,
					SortBy: metaTypes.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 20)

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: metaTypes.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: metaTypes.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo1")

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: metaTypes.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: metaTypes.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: metaTypes.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				// sort by downloads
				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: metaTypes.Downloads,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				// sort by last update
				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: metaTypes.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				repos, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: metaTypes.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(repos, ShouldBeEmpty)
			})

			Convey("Search with wrong pagination input", func() {
				_, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: metaTypes.UpdateTime,
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  -1,
					Offset: 100,
					SortBy: metaTypes.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: -1,
					SortBy: metaTypes.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{}, metaTypes.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: metaTypes.SortCriteria("InvalidSortingCriteria"),
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

				err := metaDB.SetManifestData(manifestDigest1, metaTypes.ManifestData{
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

				err = metaDB.SetManifestData(manifestDigest2, metaTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   confBlob,
				})
				So(err, ShouldBeNil)
				err = metaDB.SetManifestData(manifestDigest3, metaTypes.ManifestData{
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

				err = metaDB.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference("repo", tag4, indexDigest, ispec.MediaTypeImageIndex)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference("repo", tag5, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, indexDataMap, _, err := metaDB.SearchRepos(ctx, "repo", metaTypes.Filter{},
					metaTypes.PageInput{})
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

			emptyRepoMeta := metaTypes.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = metaDB.SetRepoReference(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo1, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo2, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			Convey("With exact match", func() {
				repos, manifestMetaMap, _, _, err := metaDB.SearchTags(ctx, "repo1:0.0.1", metaTypes.Filter{},
					metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
			})

			Convey("With partial repo path", func() {
				repos, manifestMetaMap, _, _, err := metaDB.SearchTags(ctx, "repo:0.0.1", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifestMetaMap), ShouldEqual, 0)
			})

			Convey("With partial tag", func() {
				repos, manifestMetaMap, _, _, err := metaDB.SearchTags(ctx, "repo1:0.0", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 2)
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifestMetaMap, ShouldContainKey, manifestDigest1.String())
				So(manifestMetaMap, ShouldContainKey, manifestDigest3.String())

				repos, manifestMetaMap, _, _, err = metaDB.SearchTags(ctx, "repo1:0.", metaTypes.Filter{}, metaTypes.PageInput{})
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
				repos, manifestMetaMap, _, _, err := metaDB.SearchTags(ctx, "repo:0.0.1:test", metaTypes.Filter{},
					metaTypes.PageInput{})
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

				err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo2, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)
				err = metaDB.SetRepoReference(repo3, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				config := ispec.Image{}
				configBlob, err := json.Marshal(config)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestMeta(repo1, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob})
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo2, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob})
				So(err, ShouldBeNil)
				err = metaDB.SetManifestMeta(repo3, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob})
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

				repos, _, _, _, err := metaDB.SearchTags(ctx, "repo1:", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, repo1)

				repos, _, _, _, err = metaDB.SearchTags(ctx, "repo2:", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldBeNil)
				So(repos, ShouldBeEmpty)
			})

			Convey("With wrong pagination input", func() {
				repos, _, _, _, err := metaDB.SearchTags(ctx, "repo2:", metaTypes.Filter{}, metaTypes.PageInput{
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

				err := metaDB.SetManifestData(manifestDigest1, metaTypes.ManifestData{
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

				err = metaDB.SetManifestData(manifestDigest2, metaTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   confBlob,
				})
				So(err, ShouldBeNil)
				err = metaDB.SetManifestData(manifestDigest3, metaTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = metaDB.SetManifestData(manifestDigest4, metaTypes.ManifestData{
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

				err = metaDB.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference("repo", tag4, indexDigest, ispec.MediaTypeImageIndex)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference("repo", tag5, manifestDigest3, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference("repo", tag6, manifestDigest4, ispec.MediaTypeImageManifest)
				So(err, ShouldBeNil)

				repos, manifestMetaMap, indexDataMap, _, err := metaDB.SearchTags(ctx, "repo:0.0", metaTypes.Filter{},
					metaTypes.PageInput{})
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag2, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag3, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag4, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag5, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			config := ispec.Image{}
			configBlob, err := json.Marshal(config)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob})
			So(err, ShouldBeNil)

			repos, _, _, _, err := metaDB.SearchTags(context.TODO(), "repo1:", metaTypes.Filter{}, metaTypes.PageInput{
				Limit:  1,
				Offset: 0,
				SortBy: metaTypes.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			keys := make([]string, 0, len(repos[0].Tags))
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, _, _, err = metaDB.SearchTags(context.TODO(), "repo1:", metaTypes.Filter{}, metaTypes.PageInput{
				Limit:  1,
				Offset: 1,
				SortBy: metaTypes.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, _, _, err = metaDB.SearchTags(context.TODO(), "repo1:", metaTypes.Filter{}, metaTypes.PageInput{
				Limit:  1,
				Offset: 2,
				SortBy: metaTypes.AlphabeticAsc,
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

			err := metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
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

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest2, metaTypes.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo2, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo3, manifestDigest2, metaTypes.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo4, manifestDigest3, metaTypes.ManifestMetadata{ConfigBlob: configBlob3})
			So(err, ShouldBeNil)

			opSys := LINUX
			arch := ""
			filter := metaTypes.Filter{
				Os: []*string{&opSys},
			}

			repos, _, _, _, err := metaDB.SearchRepos(context.TODO(), "", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo2")

			opSys = WINDOWS
			filter = metaTypes.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, _, err = metaDB.SearchRepos(context.TODO(), "repo", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo3")

			opSys = "wrong"
			filter = metaTypes.Filter{
				Os: []*string{&opSys},
			}
			repos, _, _, _, err = metaDB.SearchRepos(context.TODO(), "repo", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 0)

			opSys = LINUX
			arch = AMD
			filter = metaTypes.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = metaDB.SearchRepos(context.TODO(), "repo", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 2)
			So(repos[0].Name, ShouldResemble, "repo1")
			So(repos[1].Name, ShouldResemble, "repo2")

			opSys = WINDOWS
			arch = AMD
			filter = metaTypes.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = metaDB.SearchRepos(context.TODO(), "repo", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
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

			err := metaDB.SetRepoReference(repo1, tag3, indexDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests(
				[]godigest.Digest{
					manifestFromIndexDigest1,
					manifestFromIndexDigest2,
				},
			)
			So(err, ShouldBeNil)

			err = metaDB.SetIndexData(indexDigest, metaTypes.IndexData{
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo2, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo3, tag1, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
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

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest2, metaTypes.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo2, manifestDigest1, metaTypes.ManifestMetadata{ConfigBlob: configBlob1})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo3, manifestDigest2, metaTypes.ManifestMetadata{ConfigBlob: configBlob2})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo4, manifestDigest3, metaTypes.ManifestMetadata{ConfigBlob: configBlob3})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestFromIndexDigest1,
				metaTypes.ManifestMetadata{ConfigBlob: []byte("{}")})
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestFromIndexDigest2,
				metaTypes.ManifestMetadata{ConfigBlob: []byte("{}")})
			So(err, ShouldBeNil)

			opSys := LINUX
			arch := AMD
			filter := metaTypes.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err := metaDB.SearchTags(context.TODO(), "repo1:", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			So(repos[0].Tags, ShouldContainKey, tag1)

			opSys = LINUX
			arch = "badArch"
			filter = metaTypes.Filter{
				Os:   []*string{&opSys},
				Arch: []*string{&arch},
			}
			repos, _, _, _, err = metaDB.SearchTags(context.TODO(), "repo1:", filter,
				metaTypes.PageInput{SortBy: metaTypes.AlphabeticAsc})
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

			emptyManifestMeta := metaTypes.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			emptyManifestData := metaTypes.ManifestData{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = metaDB.SetRepoReference(repo1, "2.0.0", indexDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			indexBlob, err := test.GetIndexBlobWithManifests([]godigest.Digest{
				manifestFromIndexDigest1,
				manifestFromIndexDigest2,
			})
			So(err, ShouldBeNil)

			err = metaDB.SetIndexData(indexDigest, metaTypes.IndexData{
				IndexBlob: indexBlob,
			})
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo1, "0.0.1", manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "0.0.2", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "0.1.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "1.0.0", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, "1.0.1", manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo2, "0.0.1", manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo1, manifestDigest2, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo1, manifestDigest3, emptyManifestMeta)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestMeta(repo2, manifestDigest3, emptyManifestMeta)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestData(manifestFromIndexDigest1, emptyManifestData)
			So(err, ShouldBeNil)
			err = metaDB.SetManifestData(manifestFromIndexDigest2, emptyManifestData)
			So(err, ShouldBeNil)

			Convey("Return all tags", func() {
				repos, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(
					ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
						return true
					},
					metaTypes.PageInput{Limit: 10, Offset: 0, SortBy: metaTypes.AlphabeticAsc},
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
				repos, manifestMetaMap, indexDataMap, pageInfo, err := metaDB.FilterTags(
					ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
						return repoMeta.Name == repo1
					},
					metaTypes.PageInput{Limit: 10, Offset: 0, SortBy: metaTypes.AlphabeticAsc},
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
				repos, manifestMetaMap, _, pageInfo, err := metaDB.FilterTags(
					ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
						return false
					},
					metaTypes.PageInput{Limit: 10, Offset: 0, SortBy: metaTypes.AlphabeticAsc},
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

				repos, manifestMetaMap, _, pageInfo, err := metaDB.FilterTags(
					ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
						return true
					},
					metaTypes.PageInput{Limit: 10, Offset: 0, SortBy: metaTypes.AlphabeticAsc},
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
				repos, _, _, _, err := metaDB.FilterTags(
					ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool {
						return true
					},
					metaTypes.PageInput{Limit: -1},
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

			err = metaDB.SetIndexData(indexDigest, indexData)
			So(err, ShouldBeNil)

			result, err := metaDB.GetIndexData(indexDigest)
			So(err, ShouldBeNil)
			So(result, ShouldResemble, indexData)

			_, err = metaDB.GetIndexData(godigest.FromString("inexistent"))
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

			manifestData := metaTypes.ManifestData{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			}

			err = metaDB.SetManifestData(referredDigest, manifestData)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference("repo", "tag", referredDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			// ------- Add Artifact 1

			artifact1, err := test.GetImageWithSubject(
				referredDigest,
				ispec.MediaTypeImageManifest,
			)
			So(err, ShouldBeNil)

			artifactDigest1, err := artifact1.Digest()
			So(err, ShouldBeNil)

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
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

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:    artifactDigest2.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------ GetReferrers

			referrers, err := metaDB.GetReferrersInfo("repo", referredDigest, nil)
			So(len(referrers), ShouldEqual, 2)
			So(referrers, ShouldContain, metaTypes.ReferrerInfo{
				Digest:    artifactDigest1.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(referrers, ShouldContain, metaTypes.ReferrerInfo{
				Digest:    artifactDigest2.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------ DeleteReferrers

			err = metaDB.DeleteReferrer("repo", referredDigest, artifactDigest1)
			So(err, ShouldBeNil)

			err = metaDB.DeleteReferrer("repo", referredDigest, artifactDigest2)
			So(err, ShouldBeNil)

			referrers, err = metaDB.GetReferrersInfo("repo", referredDigest, nil)
			So(err, ShouldBeNil)
			So(len(referrers), ShouldEqual, 0)
		})

		Convey("Test Referrers on empty Repo", func() {
			repoMeta, err := metaDB.GetRepoMeta("repo")
			So(err, ShouldNotBeNil)
			So(repoMeta, ShouldResemble, metaTypes.RepoMetadata{})

			referredDigest := godigest.FromString("referredDigest")
			referrerDigest := godigest.FromString("referrerDigest")

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta("repo")
			So(err, ShouldBeNil)
			So(repoMeta.Referrers[referredDigest.String()][0].Digest, ShouldResemble, referrerDigest.String())
		})

		Convey("Test Referrers add same one twice", func() {
			repoMeta, err := metaDB.GetRepoMeta("repo")
			So(err, ShouldNotBeNil)
			So(repoMeta, ShouldResemble, metaTypes.RepoMetadata{})

			referredDigest := godigest.FromString("referredDigest")
			referrerDigest := godigest.FromString("referrerDigest")

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:    referrerDigest.String(),
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta("repo")
			So(err, ShouldBeNil)
			So(len(repoMeta.Referrers[referredDigest.String()]), ShouldEqual, 1)
		})

		Convey("GetReferrersInfo", func() {
			referredDigest := godigest.FromString("referredDigest")

			err := metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:    "inexistendManifestDigest",
				MediaType: ispec.MediaTypeImageManifest,
			})
			So(err, ShouldBeNil)

			// ------- Set existent manifest and artifact manifest
			err = metaDB.SetManifestData("goodManifest", metaTypes.ManifestData{
				ManifestBlob: []byte(`{"artifactType": "unwantedType"}`),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:       "goodManifestUnwanted",
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "unwantedType",
			})
			So(err, ShouldBeNil)

			err = metaDB.SetReferrer("repo", referredDigest, metaTypes.ReferrerInfo{
				Digest:       "goodManifest",
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "wantedType",
			})
			So(err, ShouldBeNil)

			referrerInfo, err := metaDB.GetReferrersInfo("repo", referredDigest, []string{"wantedType"})
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

			err = metaDB.SetManifestData(imgDigest, manifestData)
			So(err, ShouldBeNil)

			multiarch, err := test.GetRandomMultiarchImage("multi")
			So(err, ShouldBeNil)
			multiarchDigest, err := multiarch.Digest()
			So(err, ShouldBeNil)

			indexData, err := NewIndexData(multiarch.Index)
			So(err, ShouldBeNil)

			err = metaDB.SetIndexData(multiarchDigest, indexData)
			So(err, ShouldBeNil)

			for _, img := range multiarch.Images {
				digest, err := img.Digest()
				So(err, ShouldBeNil)

				indManData1, err := NewManifestData(multiarch.Images[0].Manifest, multiarch.Images[0].Config)
				So(err, ShouldBeNil)

				err = metaDB.SetManifestData(digest, indManData1)
				So(err, ShouldBeNil)
			}

			err = metaDB.SetRepoReference("repo", img.Reference, imgDigest, img.Manifest.MediaType)
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference("repo", multiarch.Reference, multiarchDigest, ispec.MediaTypeImageIndex)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err := metaDB.FilterRepos(context.Background(),
				func(repoMeta metaTypes.RepoMetadata) bool { return true }, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)

			_, _, _, _, err = metaDB.FilterRepos(context.Background(),
				func(repoMeta metaTypes.RepoMetadata) bool { return true }, metaTypes.PageInput{
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
			err := metaDB.SetManifestData(manifestDigest, metaTypes.ManifestData{
				ManifestBlob: []byte("{}"),
				ConfigBlob:   []byte("{}"),
			})
			So(err, ShouldBeNil)

			err = metaDB.SetRepoReference(repo99, "tag", manifestDigest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err := metaDB.SearchRepos(ctx, repo99, metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = metaDB.SearchTags(ctx, repo99+":", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = metaDB.FilterRepos(ctx, func(repoMeta metaTypes.RepoMetadata) bool {
				return true
			}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			repoMetas, _, _, _, err = metaDB.FilterTags(ctx,
				func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return true },
				metaTypes.PageInput{},
			)
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeFalse)
			So(repoMetas[0].IsStarred, ShouldBeFalse)

			_, err = metaDB.ToggleBookmarkRepo(ctx, repo99)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, repo99)
			So(err, ShouldBeNil)

			repoMetas, _, _, _, err = metaDB.SearchRepos(ctx, repo99, metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = metaDB.SearchTags(ctx, repo99+":", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = metaDB.FilterRepos(ctx, func(repoMeta metaTypes.RepoMetadata) bool {
				return true
			}, metaTypes.PageInput{})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].IsBookmarked, ShouldBeTrue)
			So(repoMetas[0].IsStarred, ShouldBeTrue)

			repoMetas, _, _, _, err = metaDB.FilterTags(ctx,
				func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return true },
				metaTypes.PageInput{},
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

			err := metaDB.SetRepoReference("repo", "tag", digest, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldBeNil)
			So(repoMeta.IsBookmarked, ShouldBeTrue)
			So(repoMeta.IsStarred, ShouldBeTrue)
			So(repoMeta.Tags, ShouldContainKey, "tag")
		})
	})
}

func NewManifestData(manifest ispec.Manifest, config ispec.Image) (metaTypes.ManifestData, error) {
	configBlob, err := json.Marshal(config)
	if err != nil {
		return metaTypes.ManifestData{}, err
	}

	manifest.Config.Digest = godigest.FromBytes(configBlob)

	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return metaTypes.ManifestData{}, err
	}

	return metaTypes.ManifestData{ManifestBlob: manifestBlob, ConfigBlob: configBlob}, nil
}

func NewIndexData(index ispec.Index) (metaTypes.IndexData, error) {
	indexBlob, err := json.Marshal(index)

	return metaTypes.IndexData{IndexBlob: indexBlob}, err
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
			boltDBParams := boltdb.DBParameters{
				RootDir: t.TempDir(),
			}
			boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
			So(err, ShouldBeNil)

			log := log.NewLogger("debug", "")

			metaDB, err := boltdb.New(boltDriver, log)
			So(metaDB, ShouldNotBeNil)
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

			emptyRepoMeta := metaTypes.ManifestMetadata{
				ManifestBlob: emptyManifestBlob,
				ConfigBlob:   emptyConfigBlob,
			}

			err = metaDB.SetRepoReference(repo1, tag1, manifestDigest1, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo1, tag2, manifestDigest2, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo2, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo3, tag3, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)
			err = metaDB.SetRepoReference(repo4, tag1, manifestDigest3, ispec.MediaTypeImageManifest)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo1, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo2, manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo3, manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)

			err = metaDB.SetManifestMeta(repo4, manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			repos, _, _, _, err := metaDB.SearchRepos(ctx, "pine", metaTypes.Filter{},
				metaTypes.PageInput{SortBy: metaTypes.Relevance},
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
