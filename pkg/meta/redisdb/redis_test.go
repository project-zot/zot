package redisdb_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/redisdb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

var ErrTestError = errors.New("TestError")

func TestRedisMocked(t *testing.T) {
	Convey("Test redis metadb implementation", t, func() {
		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		client, mock := redismock.NewClientMock()
		defer DumpKeys(t, client) // Troubleshoot test failures

		mock.ExpectPing().SetVal("PONG")

		params := redisdb.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redisdb.New(client, params, log)
		So(err, ShouldBeNil)

		Convey("GetAllRepoNames HGetAll error", func() {
			mock.ExpectHGetAll(metaDB.RepoMetaKey).
				SetErr(ErrTestError)

			repoNames, err := metaDB.GetAllRepoNames()
			So(errors.Is(err, ErrTestError), ShouldEqual, true)
			So(len(repoNames), ShouldEqual, 0)
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
		})
	})
}

func TestRedisRepoMeta(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("Test repometa implementation", t, func() {
		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		opts, err := redis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := redis.NewClient(opts)
		defer DumpKeys(t, client) // Troubleshoot test failures

		params := redisdb.DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := redisdb.New(client, params, log)
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

func DumpKeys(t *testing.T, client redis.UniversalClient) {
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
