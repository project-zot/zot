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

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/storage/repodb"
)

func TestBoltDBWrapper(t *testing.T) {
	Convey("BoltDB Wrapper creation", t, func() {
		boltDBParams := repodb.BoltDBParameters{}
		searchDB, err := repodb.NewBotDBWrapper(boltDBParams)
		So(searchDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		err = os.Chmod("repo.db", 0o200)
		So(err, ShouldBeNil)

		searchDB, err = repodb.NewBotDBWrapper(boltDBParams)
		So(searchDB, ShouldBeNil)
		So(err, ShouldNotBeNil)

		err = os.Chmod("repo.db", 0o600)
		So(err, ShouldBeNil)

		defer os.Remove("repo.db")
	})

	Convey("Test RepoDB Interface implementation", t, func() {
		filePath := path.Join(t.TempDir(), "repo.db")
		boltDBParams := repodb.BoltDBParameters{
			RootDir: t.TempDir(),
		}

		repoDB, err := repodb.NewBotDBWrapper(boltDBParams)
		So(repoDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		defer os.Remove(filePath)

		Convey("Test SetManifestMeta and GetManifestMeta", func() {
			configBlob, manifestBlob, err := generateTestImageManifest()
			So(err, ShouldBeNil)

			manifestDigest := digest.FromBytes(manifestBlob)

			err = repoDB.SetManifestMeta(manifestDigest.String(), repodb.ManifestMetadata{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			mm, err := repoDB.GetManifestMeta(manifestDigest.String())
			So(err, ShouldBeNil)
			So(mm.ManifestBlob, ShouldResemble, manifestBlob)
			So(mm.ConfigBlob, ShouldResemble, configBlob)
		})

		Convey("Test GetManifestMeta fails", func() {
			_, err := repoDB.GetManifestMeta("bad digest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test SetRepoTag", func() {
			// test behaviours
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()

				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifes2").String()
			)

			Convey("Setting a good repo", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1], ShouldEqual, manifestDigest1)
			})

			Convey("Set multiple tags for repo", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2)
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta.Tags[tag1], ShouldEqual, manifestDigest1)
				So(repoMeta.Tags[tag2], ShouldEqual, manifestDigest2)
			})

			Convey("Set multiple repos", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2)
				So(err, ShouldBeNil)

				repoMeta1, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				repoMeta2, err := repoDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)

				So(repoMeta1.Tags[tag1], ShouldResemble, manifestDigest1)
				So(repoMeta2.Tags[tag2], ShouldResemble, manifestDigest2)
			})

			Convey("Setting a repo with invalid fields", func() {
				Convey("Repo name is not valid", func() {
					err := repoDB.SetRepoTag("", tag1, manifestDigest1)
					So(err, ShouldNotBeNil)
				})

				Convey("Tag is not valid", func() {
					err = repoDB.SetRepoTag(repo1, "", manifestDigest1)
					So(err, ShouldNotBeNil)
				})

				Convey("Manifest Digest is not valid", func() {
					err = repoDB.SetRepoTag(repo1, tag1, "")
					So(err, ShouldNotBeNil)
				})
			})
		})

		Convey("Test GetRepoMeta", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()

				repo2           = "repo2"
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2").String()

				InexistentRepo = "InexistentRepo"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2)
			So(err, ShouldBeNil)

			Convey("Get a existent repo", func() {
				repoMeta1, err := repoDB.GetRepoMeta(repo1)
				So(err, ShouldBeNil)
				So(repoMeta1.Tags[tag1], ShouldResemble, manifestDigest1)

				repoMeta2, err := repoDB.GetRepoMeta(repo2)
				So(err, ShouldBeNil)
				So(repoMeta2.Tags[tag2], ShouldResemble, manifestDigest2)
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
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2").String()
			)

			err := repoDB.SetRepoTag(repo, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo, tag2, manifestDigest2)
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
				So(repoMeta.Tags[tag2], ShouldResemble, manifestDigest2)
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

				So(repoMeta.Tags[tag1], ShouldResemble, manifestDigest1)
				So(repoMeta.Tags[tag2], ShouldResemble, manifestDigest2)
			})

			Convey("Delete from inexistent repo", func() {
				err := repoDB.DeleteRepoTag("InexistentRepo", "InexistentTag")
				So(err, ShouldBeNil)

				repoMeta, err := repoDB.GetRepoMeta(repo)
				So(err, ShouldBeNil)

				So(repoMeta.Tags[tag1], ShouldResemble, manifestDigest1)
				So(repoMeta.Tags[tag2], ShouldResemble, manifestDigest2)
			})
		})

		Convey("Test GetMultipleRepoMeta", func() {
			var (
				repo1           = "repo1"
				repo2           = "repo2"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoTag(repo2, tag2, manifestDigest2)
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
				So(repoMetaSlice[0].Tags[tag1] == manifestDigest1, ShouldBeTrue)
			})
		})

		Convey("Test IncrementRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
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
				manifestDigest1 = digest.FromString("fake-manifest1").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
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

		Convey("Test SetRepoDescription", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				description     = "This is a test description"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoDescription(repo1, description)
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.Description, ShouldResemble, description)

			_, err = repoDB.GetRepoMeta("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test SetRepoLogo", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				logoPath        = "This is a fake logo path"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetRepoLogo(repo1, logoPath)
			So(err, ShouldBeNil)

			repoMeta, err := repoDB.GetRepoMeta(repo1)
			So(err, ShouldBeNil)
			So(repoMeta.LogoPath, ShouldResemble, logoPath)

			_, err = repoDB.GetRepoMeta("badRepo")
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetRepoStars", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
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

		Convey("Test IncrementManifestDownloads", func() {
			configBlob, manifestBlob, err := generateTestImageManifest()
			So(err, ShouldBeNil)

			manifestDigest := digest.FromBytes(manifestBlob)

			err = repoDB.SetManifestMeta(manifestDigest.String(), repodb.ManifestMetadata{
				ManifestBlob: manifestBlob,
				ConfigBlob:   configBlob,
			})
			So(err, ShouldBeNil)

			err = repoDB.IncrementManifestDownloads(manifestDigest.String())
			So(err, ShouldBeNil)

			manifestMeta, err := repoDB.GetManifestMeta(manifestDigest.String())
			So(err, ShouldBeNil)

			So(manifestMeta.DownloadCount, ShouldEqual, 1)

			err = repoDB.IncrementManifestDownloads(manifestDigest.String())
			So(err, ShouldBeNil)

			manifestMeta, err = repoDB.GetManifestMeta(manifestDigest.String())
			So(err, ShouldBeNil)

			So(manifestMeta.DownloadCount, ShouldEqual, 2)

			manifestMeta, err = repoDB.GetManifestMeta("badManiestDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test AddManifestSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(manifestDigest1, repodb.ManifestMetadata{})
			So(err, ShouldBeNil)

			err = repoDB.AddManifestSignature(manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			manifestMeta, err := repoDB.GetManifestMeta(manifestDigest1)
			So(err, ShouldBeNil)
			So(manifestMeta.Signatures["cosign"], ShouldContain, "digest")

			_, err = repoDB.GetManifestMeta("badDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("Test DeleteSignature", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(manifestDigest1, repodb.ManifestMetadata{})
			So(err, ShouldBeNil)

			err = repoDB.AddManifestSignature(manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			manifestMeta, err := repoDB.GetManifestMeta(manifestDigest1)
			So(err, ShouldBeNil)
			So(manifestMeta.Signatures["cosign"], ShouldContain, "digest")

			err = repoDB.DeleteSignature(manifestDigest1, repodb.SignatureMetadata{
				SignatureType:   "cosign",
				SignatureDigest: "digest",
			})
			So(err, ShouldBeNil)

			manifestMeta, err = repoDB.GetManifestMeta(manifestDigest1)
			So(err, ShouldBeNil)
			So(manifestMeta.Signatures["cosign"], ShouldBeEmpty)

			err = repoDB.DeleteSignature("badDigest", repodb.SignatureMetadata{
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
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2").String()
				tag3            = "0.0.3"
				manifestDigest3 = digest.FromString("fake-manifest3").String()
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
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag3, manifestDigest3)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, err := repoDB.SearchRepos(ctx, "", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(len(manifesMetaMap), ShouldEqual, 3)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest2)
				So(manifesMetaMap, ShouldContainKey, manifestDigest3)
			})

			Convey("Search a repo by name", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, err := repoDB.SearchRepos(ctx, repo1, repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(manifesMetaMap), ShouldEqual, 1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
			})

			Convey("Search non-existing repo by name", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)

				err = repoDB.SetRepoTag(repo1, tag2, manifestDigest2)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, err := repoDB.SearchRepos(ctx, "RepoThatDoesntExist", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
			})

			Convey("Search with partial match", func() {
				err := repoDB.SetRepoTag("alpine", tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag("pine", tag2, manifestDigest2)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag("golang", tag3, manifestDigest3)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest3, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, err := repoDB.SearchRepos(ctx, "pine", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 2)
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest2)
				So(manifesMetaMap, ShouldNotContainKey, manifestDigest3)
			})

			Convey("Search multiple repos that share manifests", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)

				repos, manifesMetaMap, err := repoDB.SearchRepos(ctx, "", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 3)
				So(len(manifesMetaMap), ShouldEqual, 1)
			})

			Convey("Search repos with access control", func() {
				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest2, emptyRepoMeta)
				So(err, ShouldBeNil)

				acCtx := localCtx.AccessControlContext{
					GlobPatterns: map[string]bool{
						repo1: true,
						repo2: true,
					},
					Username: "username",
				}
				authzCtxKey := localCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				repos, _, err := repoDB.SearchRepos(ctx, "repo", repodb.PageInput{})
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

					err = repoDB.SetManifestMeta(manifestDigest.String(), manifestMeta)
					So(err, ShouldBeNil)

					repoName := "repo" + strconv.Itoa(i)

					err = repoDB.SetRepoTag(repoName, tag1, manifestDigest.String())
					So(err, ShouldBeNil)

					repoNameBuilder.Reset()
				}

				repos, _, err := repoDB.SearchRepos(ctx, "repo", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, reposCount)

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  20,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 20)

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 1,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo1")

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticAsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 49,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.AlphabeticDsc,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo9")

				// sort by downloads
				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.Downloads,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				// sort by stars
				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.Stars,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo0")

				// sort by last update
				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 0,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, "repo49")

				repos, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(repos, ShouldBeEmpty)
			})

			Convey("Search with wrong pagination input", func() {
				_, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldBeNil)

				_, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  -1,
					Offset: 100,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
					Limit:  1,
					Offset: -1,
					SortBy: repodb.UpdateTime,
				})
				So(err, ShouldNotBeNil)

				_, _, err = repoDB.SearchRepos(ctx, "repo", repodb.PageInput{
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
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				manifestDigest2 = digest.FromString("fake-manifest2").String()
				manifestDigest3 = digest.FromString("fake-manifest3").String()
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

			err = repoDB.SetRepoTag(repo1, "0.0.1", manifestDigest1)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.0.2", manifestDigest3)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "0.1.0", manifestDigest2)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.0", manifestDigest2)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, "1.0.1", manifestDigest2)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo2, "0.0.1", manifestDigest3)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(manifestDigest1, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(manifestDigest2, emptyRepoMeta)
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(manifestDigest3, emptyRepoMeta)
			So(err, ShouldBeNil)

			Convey("With exact match", func() {
				repos, manifesMetaMap, err := repoDB.SearchTags(ctx, "repo1:0.0.1", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 1)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
			})

			Convey("With partial repo path", func() {
				repos, manifesMetaMap, err := repoDB.SearchTags(ctx, "repo:0.0.1", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 0)
				So(len(manifesMetaMap), ShouldEqual, 0)
			})

			Convey("With partial tag", func() {
				repos, manifesMetaMap, err := repoDB.SearchTags(ctx, "repo1:0.0", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 2)
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest3)

				repos, manifesMetaMap, err = repoDB.SearchTags(ctx, "repo1:0.", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(len(repos[0].Tags), ShouldEqual, 3)
				So(repos[0].Tags, ShouldContainKey, "0.0.1")
				So(repos[0].Tags, ShouldContainKey, "0.0.2")
				So(repos[0].Tags, ShouldContainKey, "0.1.0")
				So(manifesMetaMap, ShouldContainKey, manifestDigest1)
				So(manifesMetaMap, ShouldContainKey, manifestDigest2)
				So(manifesMetaMap, ShouldContainKey, manifestDigest3)
			})

			Convey("With bad query", func() {
				repos, manifesMetaMap, err := repoDB.SearchTags(ctx, "repo:0.0.1:test", repodb.PageInput{})
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
					manifestDigest1 = digest.FromString("fake-manifest1").String()
					tag2            = "0.0.2"
					manifestDigest2 = digest.FromString("fake-manifest2").String()
					tag3            = "0.0.3"
				)

				err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo2, tag2, manifestDigest1)
				So(err, ShouldBeNil)
				err = repoDB.SetRepoTag(repo3, tag3, manifestDigest1)
				So(err, ShouldBeNil)

				err = repoDB.SetManifestMeta(manifestDigest1, repodb.ManifestMetadata{})
				So(err, ShouldBeNil)
				err = repoDB.SetManifestMeta(manifestDigest2, repodb.ManifestMetadata{})
				So(err, ShouldBeNil)

				acCtx := localCtx.AccessControlContext{
					GlobPatterns: map[string]bool{
						repo1: true,
						repo2: false,
					},
					Username: "username",
				}
				authzCtxKey := localCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

				repos, _, err := repoDB.SearchTags(ctx, "repo1:", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(len(repos), ShouldEqual, 1)
				So(repos[0].Name, ShouldResemble, repo1)

				repos, _, err = repoDB.SearchTags(ctx, "repo2:", repodb.PageInput{})
				So(err, ShouldBeNil)
				So(repos, ShouldBeEmpty)
			})
		})

		Convey("Paginated tag search", func() {
			var (
				repo1           = "repo1"
				tag1            = "0.0.1"
				manifestDigest1 = digest.FromString("fake-manifest1").String()
				tag2            = "0.0.2"
				manifestDigest2 = digest.FromString("fake-manifest2").String()
				tag3            = "0.0.3"
				tag4            = "0.0.4"
				tag5            = "0.0.5"
			)

			err := repoDB.SetRepoTag(repo1, tag1, manifestDigest1)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag2, manifestDigest1)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag3, manifestDigest1)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag4, manifestDigest1)
			So(err, ShouldBeNil)
			err = repoDB.SetRepoTag(repo1, tag5, manifestDigest1)
			So(err, ShouldBeNil)

			err = repoDB.SetManifestMeta(manifestDigest1, repodb.ManifestMetadata{})
			So(err, ShouldBeNil)
			err = repoDB.SetManifestMeta(manifestDigest2, repodb.ManifestMetadata{})
			So(err, ShouldBeNil)

			repos, _, err := repoDB.SearchTags(context.TODO(), "repo1:", repodb.PageInput{
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

			repos, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.PageInput{
				Limit:  1,
				Offset: 1,
				SortBy: repodb.AlphabeticAsc,
			})

			So(err, ShouldBeNil)
			So(len(repos), ShouldEqual, 1)
			for k := range repos[0].Tags {
				keys = append(keys, k)
			}

			repos, _, err = repoDB.SearchTags(context.TODO(), "repo1:", repodb.PageInput{
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

		Convey("Test SearchDigests", func() {
		})

		Convey("Test SearchLayers", func() {
		})

		Convey("Test SearchForAscendantImages", func() {
		})

		Convey("Test SearchForDescendantImages", func() {
		})
	})
}

func generateTestImageManifest() ([]byte, []byte, error) {
	config := ispec.Image{
		Architecture: "amd64",
		OS:           "linux",
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
		// nolint:gosec
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
