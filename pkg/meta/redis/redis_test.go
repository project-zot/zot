package redis_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redismock/v9"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	goredis "github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

const keyPrefix = "zot"

var ErrTestError = errors.New("TestError")

type imgTrustStore struct{}

func (its imgTrustStore) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, imageMeta mTypes.ImageMeta,
	repo string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	return "", time.Time{}, false, nil
}

func TestRedisMocked(t *testing.T) {
	Convey("Test redis metadb implementation", t, func() {
		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		client, mock := redismock.NewClientMock()
		defer DumpKeys(t, client) // Troubleshoot test failures

		mock.ExpectPing().SetVal("PONG")

		params := redis.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redis.New(client, params, log)
		So(err, ShouldBeNil)

		Convey("GetAllRepoNames HGetAll error", func() {
			mock.ExpectHGetAll(metaDB.RepoMetaKey).
				SetErr(ErrTestError)

			repoNames, err := metaDB.GetAllRepoNames()
			So(errors.Is(err, ErrTestError), ShouldEqual, true)
			So(len(repoNames), ShouldEqual, 0)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("GetAllRepoNames HGetAll succeeds", func() {
			mock.ExpectHGetAll(metaDB.RepoMetaKey).SetVal(
				map[string]string{
					"repo1": "meta1",
					"repo2": "meta2",
					"repo3": "meta3",
				},
			)

			repoNames, err := metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(len(repoNames), ShouldEqual, 3)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del RepoMetaKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del ImageMetaKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del RepoBlobsKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoBlobsKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del RepoLastUpdatedKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoBlobsKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoLastUpdatedKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del UserDataKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoBlobsKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoLastUpdatedKey).SetVal(0)
			mock.ExpectDel(metaDB.UserDataKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del UserAPIKeysKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoBlobsKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoLastUpdatedKey).SetVal(0)
			mock.ExpectDel(metaDB.UserDataKey).SetVal(0)
			mock.ExpectDel(metaDB.UserAPIKeysKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("ResetDB Del VersionKey error", func() {
			mock.ExpectTxPipeline()
			mock.ExpectDel(metaDB.RepoMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.ImageMetaKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoBlobsKey).SetVal(0)
			mock.ExpectDel(metaDB.RepoLastUpdatedKey).SetVal(0)
			mock.ExpectDel(metaDB.UserDataKey).SetVal(0)
			mock.ExpectDel(metaDB.UserAPIKeysKey).SetVal(0)
			mock.ExpectDel(metaDB.VersionKey).SetErr(ErrTestError)

			err := metaDB.ResetDB()
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("DeleteRepoMeta Del RepoMetaKey error", func() {
			mock.Regexp().ExpectSetNX(metaDB.LocksKey+":Repo:repo", `.*`, 8*time.Second).
				SetVal(true)
			mock.ExpectTxPipeline()
			mock.ExpectHDel(metaDB.RepoMetaKey, "repo").SetErr(ErrTestError)

			err := metaDB.DeleteRepoMeta("repo")
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("DeleteRepoMeta Del RepoBlobsKey error", func() {
			mock.Regexp().ExpectSetNX(metaDB.LocksKey+":Repo:repo", `.*`, 8*time.Second).
				SetVal(true)
			mock.ExpectTxPipeline()
			mock.ExpectHDel(metaDB.RepoMetaKey, "repo").SetVal(0)
			mock.ExpectHDel(metaDB.RepoBlobsKey, "repo").SetErr(ErrTestError)

			err := metaDB.DeleteRepoMeta("repo")
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})

		Convey("DeleteRepoMeta Del RepoLastUpdatedKey error", func() {
			mock.Regexp().ExpectSetNX(metaDB.LocksKey+":Repo:repo", `.*`, 8*time.Second).
				SetVal(true)
			mock.ExpectTxPipeline()
			mock.ExpectHDel(metaDB.RepoMetaKey, "repo").SetVal(0)
			mock.ExpectHDel(metaDB.RepoBlobsKey, "repo").SetVal(0)
			mock.ExpectHDel(metaDB.RepoLastUpdatedKey, "repo").SetErr(ErrTestError)

			err := metaDB.DeleteRepoMeta("repo")
			So(err, ShouldNotBeNil)

			err = mock.ExpectationsWereMet()
			So(err, ShouldBeNil)
		})
	})
}

func TestRedisRepoMeta(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Test repometa implementation", t, func() {
		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		opts, err := goredis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := goredis.NewClient(opts)
		defer DumpKeys(t, client) // Troubleshoot test failures

		params := redis.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redis.New(client, params, log)
		So(err, ShouldBeNil)

		Convey("Test repoMeta ops", func() {
			ctx := context.Background()

			// Create/Get repo meta
			for i := range 5 {
				repoName := fmt.Sprintf("repo%d", i+1)
				digest := fmt.Sprintf("dig%d", i+1)

				initialRepoMeta := mTypes.RepoMeta{
					Name: repoName,
					Tags: map[mTypes.Tag]mTypes.Descriptor{"tag": {Digest: digest}},

					Statistics: map[mTypes.ImageDigest]mTypes.DescriptorStatistics{},
					Signatures: map[mTypes.ImageDigest]mTypes.ManifestSignatures{},
					Referrers:  map[mTypes.ImageDigest][]mTypes.ReferrerInfo{"digest": {{Digest: digest}}},
				}

				err = metaDB.SetRepoMeta(repoName, initialRepoMeta)
				So(err, ShouldBeNil)

				expectedRepoMeta, err := metaDB.GetRepoMeta(ctx, repoName)
				So(err, ShouldBeNil)

				So(expectedRepoMeta.Name, ShouldEqual, initialRepoMeta.Name)
				So(expectedRepoMeta.Tags["tag"].Digest, ShouldEqual, initialRepoMeta.Tags["tag"].Digest)
			}

			// Get Multiple, Filter and Delete repo meta
			repoMetas, err := metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool {
				if strings.Contains(repoMeta.Name, "repo1") || strings.Contains(repoMeta.Name, "repo4") {
					return true
				}

				return false
			})
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 2)
			So(repoMetas[0].Name, ShouldNotEqual, repoMetas[1].Name)

			for _, repoMeta := range repoMetas {
				So(repoMeta.Name, ShouldBeIn, []string{"repo1", "repo4"})
			}

			repoMetas, err = metaDB.FilterRepos(ctx,
				func(repo string) bool {
					return true
				},
				func(repoMeta mTypes.RepoMeta) bool {
					if strings.Contains(repoMeta.Tags["tag"].Digest, "dig2") ||
						strings.Contains(repoMeta.Tags["tag"].Digest, "dig5") {
						return true
					}

					return false
				},
			)
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 2)
			So(repoMetas[0].Tags["tag"].Digest, ShouldNotEqual, repoMetas[1].Tags["tag"].Digest)

			for _, repoMeta := range repoMetas {
				So(repoMeta.Tags["tag"].Digest, ShouldBeIn, []string{"dig2", "dig5"})
			}

			repoNames, err := metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(len(repoNames), ShouldEqual, 5)

			err = metaDB.DeleteRepoMeta("repo2")
			So(err, ShouldBeNil)

			repoMeta, err := metaDB.GetRepoMeta(ctx, "repo2")
			So(err, ShouldNotBeNil)
			So(repoMeta.Name, ShouldBeEmpty)

			repoNames, err = metaDB.GetAllRepoNames()
			So(err, ShouldBeNil)
			So(len(repoNames), ShouldEqual, 4)

			repoMetas, err = metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 4)

			repoMetas, err = metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return false })
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 0)

			repoMetas, err = metaDB.FilterRepos(ctx,
				func(repo string) bool {
					result := strings.Contains(repo, "repo5")

					return result
				},
				func(repoMeta mTypes.RepoMeta) bool {
					if strings.Contains(repoMeta.Tags["tag"].Digest, "dig3") ||
						strings.Contains(repoMeta.Tags["tag"].Digest, "dig5") {
						return true
					}

					return false
				},
			)
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)
			So(repoMetas[0].Tags["tag"].Digest, ShouldEqual, "dig5")

			repoMetas, err = metaDB.SearchRepos(ctx, "repo")
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 4)

			repoMetas, err = metaDB.SearchRepos(ctx, "epo3")
			So(err, ShouldBeNil)
			So(len(repoMetas), ShouldEqual, 1)

			// Stars
			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo1")
			So(err, ShouldBeNil)
			So(repoMeta, ShouldNotBeNil)
			So(repoMeta.StarCount, ShouldEqual, 0)

			err = metaDB.IncrementRepoStars("repo1")
			So(err, ShouldBeNil)
			err = metaDB.IncrementRepoStars("repo1")
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo1")
			So(err, ShouldBeNil)
			So(repoMeta, ShouldNotBeNil)
			So(repoMeta.StarCount, ShouldEqual, 2)

			err = metaDB.DecrementRepoStars("repo1")
			So(err, ShouldBeNil)
			err = metaDB.DecrementRepoStars("repo1")
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo1")
			So(err, ShouldBeNil)
			So(repoMeta, ShouldNotBeNil)
			So(repoMeta.StarCount, ShouldEqual, 0)

			err = metaDB.DecrementRepoStars("repo1")
			So(err, ShouldBeNil)

			repoMeta, err = metaDB.GetRepoMeta(ctx, "repo1")
			So(err, ShouldBeNil)
			So(repoMeta, ShouldNotBeNil)
			So(repoMeta.StarCount, ShouldEqual, 0)
		})
	})
}

func TestRedisUnreachable(t *testing.T) {
	Convey("Redis unreachable", t, func() {
		miniRedis := miniredis.RunT(t)

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		connOpts, err := goredis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)
		workingClient := goredis.NewClient(connOpts)

		params := redis.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redis.New(workingClient, params, log)
		So(err, ShouldBeNil)
		So(metaDB, ShouldNotBeNil)

		connOpts, err = goredis.ParseURL("redis://127.0.0.1:" + test.GetFreePort())
		So(err, ShouldBeNil)
		brokenClient := goredis.NewClient(connOpts)

		// Replace connection with the unreachable server
		metaDB.Client = brokenClient

		metaDB.SetImageTrustStore(imgTrustStore{})

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")

		ctx := userAc.DeriveContext(context.Background())

		repo := "repo"
		reference := "tag"
		digest := godigest.FromString("SomeString")
		image := CreateDefaultImage()
		imageMeta := image.AsImageMeta()

		err = metaDB.SetImageMeta(digest, imageMeta)
		So(err, ShouldNotBeNil)

		err = metaDB.SetRepoReference(ctx, repo, reference, imageMeta)
		So(err, ShouldNotBeNil)

		_, err = metaDB.SearchRepos(ctx, repo)
		So(err, ShouldNotBeNil)

		_, err = metaDB.SearchTags(ctx, repo+":"+reference)
		So(err, ShouldNotBeNil)

		_, err = metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
		So(err, ShouldNotBeNil)

		_, err = metaDB.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetFullImageMeta(ctx, repo, reference)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetImageMeta(digest)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldNotBeNil)

		err = metaDB.AddManifestSignature(repo, digest, mTypes.SignatureMetadata{})
		So(err, ShouldNotBeNil)

		err = metaDB.DeleteSignature(repo, digest, mTypes.SignatureMetadata{})
		So(err, ShouldNotBeNil)

		err = metaDB.UpdateSignaturesValidity(ctx, repo, digest)
		So(err, ShouldNotBeNil)

		err = metaDB.IncrementRepoStars(repo)
		So(err, ShouldNotBeNil)

		err = metaDB.DecrementRepoStars(repo)
		So(err, ShouldNotBeNil)

		err = metaDB.SetRepoMeta(repo, mTypes.RepoMeta{})
		So(err, ShouldNotBeNil)

		err = metaDB.DeleteRepoMeta(repo)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetReferrersInfo(repo, digest, []string{})
		So(err, ShouldNotBeNil)

		err = metaDB.UpdateStatsOnDownload(repo, reference)
		So(err, ShouldNotBeNil)

		_, err = metaDB.FilterImageMeta(ctx, []string{digest.String()})
		So(err, ShouldNotBeNil)

		err = metaDB.RemoveRepoReference(repo, reference, digest)
		So(err, ShouldNotBeNil)

		err = metaDB.ResetRepoReferences(repo, nil)
		So(err, ShouldNotBeNil)

		t := metaDB.GetRepoLastUpdated(repo)
		So(t, ShouldEqual, time.Time{})

		_, err = metaDB.GetAllRepoNames()
		So(err, ShouldNotBeNil)

		err = metaDB.ResetDB()
		So(err, ShouldNotBeNil)

		err = metaDB.PatchDB()
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetStarredRepos(ctx)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetBookmarkedRepos(ctx)
		So(err, ShouldNotBeNil)

		_, err = metaDB.ToggleStarRepo(ctx, repo)
		So(err, ShouldNotBeNil)

		_, err = metaDB.ToggleBookmarkRepo(ctx, repo)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetUserData(ctx)
		So(err, ShouldNotBeNil)

		err = metaDB.SetUserData(ctx, mTypes.UserData{})
		So(err, ShouldNotBeNil)

		err = metaDB.SetUserGroups(ctx, []string{})
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetUserGroups(ctx)
		So(err, ShouldNotBeNil)

		err = metaDB.DeleteUserData(ctx)
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetUserAPIKeyInfo("hash")
		So(err, ShouldNotBeNil)

		_, err = metaDB.GetUserAPIKeys(ctx)
		So(err, ShouldNotBeNil)

		err = metaDB.AddUserAPIKey(ctx, "hash", &mTypes.APIKeyDetails{})
		So(err, ShouldNotBeNil)

		_, err = metaDB.IsAPIKeyExpired(ctx, "hash")
		So(err, ShouldNotBeNil)

		err = metaDB.UpdateUserAPIKeyLastUsed(ctx, "hash")
		So(err, ShouldNotBeNil)

		err = metaDB.DeleteUserAPIKey(ctx, "test")
		So(err, ShouldNotBeNil)
	})
}

func TestWrapperErrors(t *testing.T) {
	image := CreateDefaultImage()
	imageMeta := image.AsImageMeta()
	multiarchImageMeta := CreateMultiarchWith().Images([]Image{image}).Build().AsImageMeta()

	badProtoBlob := []byte("bad-repo-meta")

	goodRepoMetaBlob, err := proto.Marshal(&proto_go.RepoMeta{Name: "repo"})
	if err != nil {
		t.FailNow()
	}

	Convey("Errors", t, func() {
		miniRedis := miniredis.RunT(t)

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		opts, err := goredis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := goredis.NewClient(opts)
		params := redis.DBDriverParameters{KeyPrefix: keyPrefix}

		metaDB, err := redis.New(client, params, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		metaDB.SetImageTrustStore(imgTrustStore{})

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("test")

		ctx := userAc.DeriveContext(context.Background())

		Convey("RemoveRepoReference", func() {
			Convey("getProtoRepoMeta errors", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta errors", func() {
				err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    imageMeta.Digest.String(),
						},
					},
				})
				So(err, ShouldBeNil)

				err = setImageMeta(imageMeta.Digest, badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoBlobs errors", func() {
				err := metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = setRepoBlobInfo("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.RemoveRepoReference("repo", "ref", imageMeta.Digest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("UpdateSignaturesValidity", func() {
			metaDB.SetImageTrustStore(imgTrustStore{})

			digest := image.Digest()

			ctx := context.Background()

			Convey("image meta blob not found", func() {
				err := metaDB.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldBeNil)
			})

			Convey("image meta unmarshal fail", func() {
				err := setImageMeta(digest, badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta blob not found", func() {
				err := metaDB.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = metaDB.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})

			Convey("repo meta unmarshal fail", func() {
				err := metaDB.SetImageMeta(digest, imageMeta)
				So(err, ShouldBeNil)

				err = setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.UpdateSignaturesValidity(ctx, "repo", digest)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetRepoLastUpdated", func() {
			Convey("bad blob in db", func() {
				err := setRepoLastUpdated("repo", []byte("bad-blob"), client)
				So(err, ShouldBeNil)

				lastUpdated := metaDB.GetRepoLastUpdated("repo")
				So(lastUpdated, ShouldEqual, time.Time{})
			})

			Convey("empty blob in db", func() {
				err := setRepoLastUpdated("repo", []byte(""), client)
				So(err, ShouldBeNil)

				lastUpdated := metaDB.GetRepoLastUpdated("repo")
				So(lastUpdated, ShouldEqual, time.Time{})
			})
		})

		Convey("UpdateStatsOnDownload", func() {
			Convey("repo meta not found", func() {
				err = metaDB.UpdateStatsOnDownload("repo", "ref")
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.UpdateStatsOnDownload("repo", "ref")
				So(err, ShouldNotBeNil)
			})

			Convey("ref is tag and tag is not found", func() {
				err := metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = metaDB.UpdateStatsOnDownload("repo", "not-found-tag")
				So(err, ShouldNotBeNil)
			})

			Convey("digest not found in statistics", func() {
				err := metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				err = metaDB.UpdateStatsOnDownload("repo", godigest.FromString("not-found").String())
				So(err, ShouldNotBeNil)
			})

			Convey("statistics entry missing but digest exists in tags - should create and increment", func() {
				// Set repo reference to create tag
				err := metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry to simulate missing Statistics
				// Get proto blob directly from Redis
				key := keyPrefix + ":" + redis.RepoMetaBucket
				repoMetaBlob, err := client.HGet(ctx, key, "repo").Bytes()
				So(err, ShouldBeNil)

				var protoRepoMeta proto_go.RepoMeta
				err = proto.Unmarshal(repoMetaBlob, &protoRepoMeta)
				So(err, ShouldBeNil)
				delete(protoRepoMeta.Statistics, imageMeta.Digest.String())

				repoMetaBlob, err = proto.Marshal(&protoRepoMeta)
				So(err, ShouldBeNil)
				err = setRepoMeta("repo", repoMetaBlob, client)
				So(err, ShouldBeNil)

				// Verify Statistics entry doesn't exist
				repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				_, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeFalse)

				// Update stats - should create Statistics entry and increment
				err = metaDB.UpdateStatsOnDownload("repo", "tag")
				So(err, ShouldBeNil)

				// Verify Statistics entry was created and incremented
				repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)

				// Update stats again - should increment existing entry
				err = metaDB.UpdateStatsOnDownload("repo", "tag")
				So(err, ShouldBeNil)

				repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists = repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 2)
			})

			Convey("statistics entry missing but digest exists in tags - using digest reference", func() {
				// Set repo reference to create tag
				err := metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldBeNil)

				// Manually remove Statistics entry
				key := keyPrefix + ":" + redis.RepoMetaBucket
				repoMetaBlob, err := client.HGet(ctx, key, "repo").Bytes()
				So(err, ShouldBeNil)

				var protoRepoMeta proto_go.RepoMeta
				err = proto.Unmarshal(repoMetaBlob, &protoRepoMeta)
				So(err, ShouldBeNil)
				delete(protoRepoMeta.Statistics, imageMeta.Digest.String())

				repoMetaBlob, err = proto.Marshal(&protoRepoMeta)
				So(err, ShouldBeNil)
				err = setRepoMeta("repo", repoMetaBlob, client)
				So(err, ShouldBeNil)

				// Update stats using digest directly
				err = metaDB.UpdateStatsOnDownload("repo", imageMeta.Digest.String())
				So(err, ShouldBeNil)

				// Verify Statistics entry was created
				repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				stats, exists := repoMeta.Statistics[imageMeta.Digest.String()]
				So(exists, ShouldBeTrue)
				So(stats.DownloadCount, ShouldEqual, 1)
			})
		})

		Convey("GetReferrersInfo", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err = metaDB.GetReferrersInfo("repo", "refDig", []string{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("ResetRepoReferences", func() {
			Convey("repo doesn't exist - returns early without error", func() {
				// Verify repo doesn't exist
				_, err := metaDB.GetRepoMeta(ctx, "nonexistent-repo")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)

				// ResetRepoReferences should return early without error
				err = metaDB.ResetRepoReferences("nonexistent-repo", nil)
				So(err, ShouldBeNil)

				// Verify repo still doesn't exist
				_, err = metaDB.GetRepoMeta(ctx, "nonexistent-repo")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)
			})

			Convey("repo doesn't exist with tagsToKeep - returns early without error", func() {
				// Verify repo doesn't exist
				_, err := metaDB.GetRepoMeta(ctx, "nonexistent-repo2")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)

				// ResetRepoReferences should return early without error even with tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true}
				err = metaDB.ResetRepoReferences("nonexistent-repo2", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify repo still doesn't exist
				_, err = metaDB.GetRepoMeta(ctx, "nonexistent-repo2")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)
			})

			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.ResetRepoReferences("repo", nil)
				So(err, ShouldNotBeNil)
			})

			Convey("preserve tags in tagsToKeep", func() {
				// Create repo with multiple tags
				image1 := CreateRandomImage()
				image2 := CreateRandomImage()

				err := metaDB.SetRepoReference(ctx, "repo", "tag1", image1.AsImageMeta())
				So(err, ShouldBeNil)

				// Wait a bit to ensure different timestamps
				time.Sleep(10 * time.Millisecond)

				err = metaDB.SetRepoReference(ctx, "repo", "tag2", image2.AsImageMeta())
				So(err, ShouldBeNil)

				// Get repo meta to capture TaggedTimestamp
				repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldContainKey, "tag2")

				tag1Timestamp := repoMeta.Tags["tag1"].TaggedTimestamp

				// Reset with only tag1 in tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true}
				err = metaDB.ResetRepoReferences("repo", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify tag1 is preserved with its timestamp
				repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldNotContainKey, "tag2")
				So(repoMeta.Tags["tag1"].TaggedTimestamp, ShouldEqual, tag1Timestamp)
			})

			Convey("remove tags not in tagsToKeep", func() {
				// Create repo with multiple tags
				image1 := CreateRandomImage()
				image2 := CreateRandomImage()
				image3 := CreateRandomImage()

				err := metaDB.SetRepoReference(ctx, "repo", "tag1", image1.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", "tag2", image2.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", "tag3", image3.AsImageMeta())
				So(err, ShouldBeNil)

				// Reset with tag1 and tag2 in tagsToKeep
				tagsToKeep := map[string]bool{"tag1": true, "tag2": true}
				err = metaDB.ResetRepoReferences("repo", tagsToKeep)
				So(err, ShouldBeNil)

				// Verify only tag1 and tag2 are preserved
				repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.Tags, ShouldContainKey, "tag1")
				So(repoMeta.Tags, ShouldContainKey, "tag2")
				So(repoMeta.Tags, ShouldNotContainKey, "tag3")
			})

			Convey("preserve statistics and stars", func() {
				image := CreateRandomImage()

				err := metaDB.SetRepoReference(ctx, "repo", "tag1", image.AsImageMeta())
				So(err, ShouldBeNil)

				err = metaDB.IncrementRepoStars("repo")
				So(err, ShouldBeNil)

				// Get original stats
				repoMeta, err := metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				originalStars := repoMeta.StarCount

				// Reset with empty tagsToKeep
				err = metaDB.ResetRepoReferences("repo", map[string]bool{})
				So(err, ShouldBeNil)

				// Verify statistics and stars are preserved
				repoMeta, err = metaDB.GetRepoMeta(ctx, "repo")
				So(err, ShouldBeNil)
				So(repoMeta.StarCount, ShouldEqual, originalStars)
			})
		})

		Convey("DecrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.DecrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("IncrementRepoStars", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.IncrementRepoStars("repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("DeleteSignature", func() {
			Convey("repo meta not found", func() {
				err = metaDB.DeleteSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.DeleteSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("AddManifestSignature", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.AddManifestSignature("repo", godigest.FromString("dig"), mTypes.SignatureMetadata{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetMultipleRepoMeta", func() {
			Convey("unmarshalProtoRepoMeta error", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err = metaDB.GetMultipleRepoMeta(ctx, func(repoMeta mTypes.RepoMeta) bool { return true })
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetImageMeta", func() {
			Convey("malformed image manifest", func() {
				badImageDigest := godigest.FromString("bad-image-manifest")

				err = setImageMeta(badImageDigest, badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err := metaDB.GetImageMeta(badImageDigest)
				So(err, ShouldNotBeNil)
			})

			Convey("good image index, malformed inside manifest", func() {
				goodIndexBadManifestDigest := godigest.FromString("good-index-bad-manifests")

				err = metaDB.SetImageMeta(goodIndexBadManifestDigest, multiarchImageMeta)
				So(err, ShouldBeNil)

				err = setImageMeta(image.Digest(), badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err := metaDB.GetImageMeta(image.Digest())
				So(err, ShouldNotBeNil)
			})
		})

		Convey("GetFullImageMeta", func() {
			Convey("repo meta not found", func() {
				_, err := metaDB.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err = metaDB.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("tag not found", func() {
				err := setRepoMeta("repo", goodRepoMetaBlob, client)
				So(err, ShouldBeNil)

				_, err = metaDB.GetFullImageMeta(ctx, "repo", "tag-not-found")
				So(err, ShouldNotBeNil)
			})

			Convey("getProtoImageMeta fails", func() {
				err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"tag": {
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("not-found").String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = metaDB.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
			})

			Convey("image is index, missing manifests are skipped gracefully", func() {
				err := metaDB.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// Missing manifests are skipped gracefully, so GetFullImageMeta succeeds
				// but returns an index with no manifests
				fullImageMeta, err := metaDB.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldBeNil)
				So(len(fullImageMeta.Manifests), ShouldEqual, 0)
			})

			Convey("image is index, corrupted manifest data returns error", func() {
				// Create a multiarch image with multiple manifests
				multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
				multiarchImageMeta := multiarchImage.AsImageMeta()
				err := metaDB.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				// Store the first manifest normally
				firstManifest := multiarchImage.Images[0]
				firstManifestMeta := firstManifest.AsImageMeta()
				err = metaDB.SetImageMeta(firstManifestMeta.Digest, firstManifestMeta)
				So(err, ShouldBeNil)

				// Store the second manifest normally first, then corrupt it
				secondManifest := multiarchImage.Images[1]
				secondManifestMeta := secondManifest.AsImageMeta()
				err = metaDB.SetImageMeta(secondManifestMeta.Digest, secondManifestMeta)
				So(err, ShouldBeNil)

				secondManifestDigest := secondManifest.ManifestDescriptor.Digest

				// Corrupt the data for the second manifest by storing invalid protobuf data
				// This will cause getProtoImageMeta to return an unmarshaling error
				// which is not ErrImageMetaNotFound, so it will propagate through getAllContainedMeta
				corruptedData := []byte("invalid protobuf data")

				// Access Redis directly to corrupt the data using the helper function pattern
				err = setImageMeta(secondManifestDigest, corruptedData, client)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", "tag", multiarchImageMeta)
				So(err, ShouldBeNil)

				// GetFullImageMeta should return an error due to corrupted manifest data
				// The error from getAllContainedMeta should propagate
				fullImageMeta, err := metaDB.GetFullImageMeta(ctx, "repo", "tag")
				So(err, ShouldNotBeNil)
				// Should still return a FullImageMeta object (even with error)
				So(fullImageMeta, ShouldNotBeNil)
			})
		})

		Convey("FilterRepos", func() {
			err := setRepoMeta("repo", badProtoBlob, client)
			So(err, ShouldBeNil)

			_, err = metaDB.FilterRepos(ctx, mTypes.AcceptAllRepoNames, mTypes.AcceptAllRepoMeta)
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = metaDB.SearchTags(ctx, "repo:")
				So(err, ShouldNotBeNil)
			})

			Convey("found repo meta", func() {
				Convey("bad image manifest", func() {
					badImageDigest := godigest.FromString("bad-image-manifest")
					err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-manifest": {
								MediaType: ispec.MediaTypeImageManifest,
								Digest:    badImageDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badImageDigest, badProtoBlob, client)
					So(err, ShouldBeNil)

					_, err = metaDB.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad image index", func() {
					badIndexDigest := godigest.FromString("bad-image-manifest")
					err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"bad-image-index": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    badIndexDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = setImageMeta(badIndexDigest, badProtoBlob, client)
					So(err, ShouldBeNil)

					_, err = metaDB.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("good image index, bad inside manifest", func() {
					goodIndexBadManifestDigest := godigest.FromString("good-index-bad-manifests")
					err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"good-index-bad-manifests": {
								MediaType: ispec.MediaTypeImageIndex,
								Digest:    goodIndexBadManifestDigest.String(),
							},
						},
					})
					So(err, ShouldBeNil)

					err = metaDB.SetImageMeta(goodIndexBadManifestDigest, multiarchImageMeta)
					So(err, ShouldBeNil)

					err = setImageMeta(image.Digest(), badProtoBlob, client)
					So(err, ShouldBeNil)

					_, err = metaDB.SearchTags(ctx, "repo:")
					So(err, ShouldNotBeNil)
				})
				Convey("bad media type", func() {
					err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
						Name: "repo",
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"mad-media-type": {
								MediaType: "bad media type",
								Digest:    godigest.FromString("dig").String(),
							},
						},
					})
					So(err, ShouldBeNil)

					_, err = metaDB.SearchTags(ctx, "repo:")
					So(err, ShouldBeNil)
				})
			})
		})

		Convey("FilterTags", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				_, err = metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldNotBeNil)
			})

			Convey("bad media Type fails", func() {
				err := metaDB.SetRepoMeta("repo", mTypes.RepoMeta{
					Name: "repo",
					Tags: map[mTypes.Tag]mTypes.Descriptor{
						"bad-repo-meta": {
							MediaType: "bad media type",
							Digest:    godigest.FromString("dig").String(),
						},
					},
				})
				So(err, ShouldBeNil)

				_, err = metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, mTypes.AcceptAllImageMeta)
				So(err, ShouldBeNil)
			})
		})

		Convey("SearchRepos", func() {
			Convey("unmarshalProtoRepoMeta fails", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = metaDB.SearchRepos(ctx, "repo")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("FilterImageMeta", func() {
			Convey("MediaType ImageIndex, getProtoImageMeta fails", func() {
				err := metaDB.SetImageMeta(multiarchImageMeta.Digest, multiarchImageMeta)
				So(err, ShouldBeNil)

				err = setImageMeta(image.Digest(), badProtoBlob, client)
				So(err, ShouldBeNil)

				// manifests are missing
				_, err = metaDB.FilterImageMeta(ctx, []string{multiarchImageMeta.Digest.String()})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			Convey("getProtoRepoMeta errors", func() {
				err := setRepoMeta("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldNotBeNil)
			})

			Convey("unmarshalProtoRepoBlobs errors", func() {
				err := setRepoMeta("repo", goodRepoMetaBlob, client)
				So(err, ShouldBeNil)

				err = setRepoBlobInfo("repo", badProtoBlob, client)
				So(err, ShouldBeNil)

				err = metaDB.SetRepoReference(ctx, "repo", "tag", imageMeta)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("AddUserAPIKey", func() {
			// no userid found
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = metaDB.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKey", func() {
			// no userid found
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = metaDB.UpdateUserAPIKeyLastUsed(ctx, "") //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey", func() {
			err = metaDB.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldBeNil)

			err = metaDB.AddUserAPIKey(ctx, "hashedKey", &mTypes.APIKeyDetails{})
			So(err, ShouldBeNil)

			Convey("userdata not found", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				err := metaDB.DeleteUserData(ctx)
				So(err, ShouldBeNil)

				err = metaDB.DeleteUserAPIKey(ctx, "")
				So(err, ShouldNotBeNil)
			})

			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = metaDB.DeleteUserAPIKey(ctx, "test") //nolint: contextcheck
			So(err, ShouldNotBeNil)

			err = deleteUserDataBucket(client)
			So(err, ShouldBeNil)

			err = metaDB.DeleteUserAPIKey(ctx, "") //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeyInfo", func() {
			err = deleteUserAPIKeysBucket(client)
			So(err, ShouldBeNil)

			_, err = metaDB.GetUserAPIKeyInfo("")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData", func() {
			err = setUserData("test", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.GetUserData(ctx)
			So(err, ShouldNotBeNil)

			err = deleteUserAPIKeysBucket(client)
			So(err, ShouldBeNil)

			_, err = metaDB.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData", func() {
			userAc := reqCtx.NewUserAccessControl()
			ctx := userAc.DeriveContext(context.Background())

			err = metaDB.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)

			err = deleteUserDataBucket(client)
			So(err, ShouldBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("test")
			ctx = userAc.DeriveContext(context.Background())

			err = metaDB.SetUserData(ctx, mTypes.UserData{}) //nolint: contextcheck
			So(err, ShouldBeNil)
		})

		Convey("DeleteUserData", func() {
			userAc = reqCtx.NewUserAccessControl()
			ctx = userAc.DeriveContext(context.Background()) //nolint:fatcontext // test code

			err = metaDB.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)

			err = deleteUserDataBucket(client)
			So(err, ShouldBeNil)

			userAc = reqCtx.NewUserAccessControl()
			userAc.SetUsername("test")
			ctx = userAc.DeriveContext(context.Background())

			err = metaDB.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups and SetUserGroups", func() {
			userAc = reqCtx.NewUserAccessControl()
			ctx = userAc.DeriveContext(context.Background()) //nolint:fatcontext // test code

			_, err := metaDB.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			err = metaDB.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, no repoMeta found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setRepoMeta("repo", []byte("bad repo"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, bad repoMeta found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			_, err = metaDB.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := metaDB.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := metaDB.GetUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.SetUserData(ctx, mTypes.UserData{})
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserGroups bad context errors", func() {
			_, err := metaDB.GetUserGroups(ctx)
			So(err, ShouldNotBeNil)

			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err = metaDB.GetUserGroups(ctx) //nolint: contextcheck
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserGroups bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("SetUserGroups bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			err = metaDB.SetUserGroups(ctx, []string{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("AddUserAPIKey bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			err = metaDB.AddUserAPIKey(ctx, "", &mTypes.APIKeyDetails{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserAPIKey bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.DeleteUserAPIKey(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserAPIKeys bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.GetUserAPIKeys(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("IsAPIKeyExpired bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			_, err = metaDB.IsAPIKeyExpired(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateUserAPIKeyLastUsed bad UserData found", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setUserData("username", []byte("dsa8"), client)
			So(err, ShouldBeNil)

			err = metaDB.UpdateUserAPIKeyLastUsed(ctx, "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteUserData bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			err := metaDB.DeleteUserData(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetStarredRepos bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := metaDB.GetStarredRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetBookmarkedRepos bad context errors", func() {
			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, "bad context")

			_, err := metaDB.GetBookmarkedRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("username")
			userAc.SetGlobPatterns("read", map[string]bool{
				"repo": true,
			})

			ctx := userAc.DeriveContext(context.Background())

			err = setRepoMeta("repo", []byte("bad repo"), client)
			So(err, ShouldBeNil)

			_, err := metaDB.GetRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})
	})
}

func setRepoMeta(repo string, blob []byte, client *goredis.Client) error { //nolint: unparam
	ctx := context.Background()
	key := keyPrefix + ":" + redis.RepoMetaBucket

	return client.HSet(ctx, key, repo, blob).Err()
}

func setRepoLastUpdated(repo string, blob []byte, client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.RepoLastUpdatedBucket

	return client.HSet(ctx, key, repo, blob).Err()
}

func setImageMeta(digest godigest.Digest, blob []byte, client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.ImageMetaBucket

	return client.HSet(ctx, key, digest.String(), blob).Err()
}

func setRepoBlobInfo(repo string, blob []byte, client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.RepoBlobsBucket

	return client.HSet(ctx, key, repo, blob).Err()
}

func setUserData(userID string, blob []byte, client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.UserDataBucket

	return client.HSet(ctx, key, userID, blob).Err()
}

func deleteUserDataBucket(client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.UserDataBucket

	return client.Del(ctx, key).Err()
}

func deleteUserAPIKeysBucket(client *goredis.Client) error {
	ctx := context.Background()
	key := keyPrefix + ":" + redis.UserAPIKeysBucket

	return client.Del(ctx, key).Err()
}

func DumpKeys(t *testing.T, client goredis.UniversalClient) {
	t.Helper()

	// Retrieve all keys
	keys, err := client.Keys(context.Background(), "*").Result()
	if err != nil {
		t.Log("Error retrieving keys:", err)

		return
	}

	// Print the keys
	t.Log("Keys in Redis:")

	for _, key := range keys {
		keyType, err := client.Type(context.Background(), key).Result()
		if err != nil {
			t.Logf("Error retrieving type for key %s: %v\n", key, err)

			continue
		}

		var value string

		switch keyType {
		case "string":
			value, err = client.Get(context.Background(), key).Result()
		case "list":
			values, err := client.LRange(context.Background(), key, 0, -1).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "hash":
			values, err := client.HGetAll(context.Background(), key).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "set":
			values, err := client.SMembers(context.Background(), key).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		case "zset":
			values, err := client.ZRange(context.Background(), key, 0, -1).Result()
			if err == nil {
				value = fmt.Sprintf("%v", values)
			}
		default:
			value = "Unsupported type"
		}

		if err != nil {
			t.Logf("Error retrieving value for key %s: %v\n", key, err)
		} else {
			t.Logf("Key: %s, Type: %s, Value: %s\n", key, keyType, value)
		}
	}
}
