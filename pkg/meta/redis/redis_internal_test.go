package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
)

func Test(t *testing.T) {
	Convey("Test redis metadb key generation", t, func() {
		miniRedis := miniredis.RunT(t)

		log := log.NewTestLogger()
		So(log, ShouldNotBeNil)

		opts, err := redis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client := redis.NewClient(opts)

		params := DBDriverParameters{KeyPrefix: "zot"}

		metaDB, err := New(client, params, log)
		So(err, ShouldBeNil)
		So(metaDB.ImageMetaKey, ShouldEqual, "zot:ImageMeta")
		So(metaDB.RepoMetaKey, ShouldEqual, "zot:RepoMeta")
		So(metaDB.RepoLastUpdatedKey, ShouldEqual, "zot:RepoLastUpdated")
		So(metaDB.RepoBlobsKey, ShouldEqual, "zot:RepoBlobsMeta")
		So(metaDB.UserDataKey, ShouldEqual, "zot:UserData")
		So(metaDB.UserAPIKeysKey, ShouldEqual, "zot:UserAPIKeys")
		So(metaDB.VersionKey, ShouldEqual, "zot:Version")
		So(metaDB.FastRestartStampKey, ShouldEqual, "zot:FastRestartStamp")
		So(metaDB.LocksKey, ShouldEqual, "zot:Locks")

		So(metaDB.getUserLockKey("user1"), ShouldEqual, "zot:Locks:User:user1")
		So(metaDB.getRepoLockKey("repo1"), ShouldEqual, "zot:Locks:Repo:repo1")
		So(metaDB.getImageLockKey("image1"), ShouldEqual, "zot:Locks:Image:image1")
		So(metaDB.getVersionLockKey(), ShouldEqual, "zot:Locks:Version")

		params = DBDriverParameters{KeyPrefix: "someprefix"}

		metaDB, err = New(client, params, log)
		So(err, ShouldBeNil)
		So(metaDB.ImageMetaKey, ShouldEqual, "someprefix:ImageMeta")
		So(metaDB.RepoMetaKey, ShouldEqual, "someprefix:RepoMeta")
		So(metaDB.RepoLastUpdatedKey, ShouldEqual, "someprefix:RepoLastUpdated")
		So(metaDB.RepoBlobsKey, ShouldEqual, "someprefix:RepoBlobsMeta")
		So(metaDB.UserDataKey, ShouldEqual, "someprefix:UserData")
		So(metaDB.UserAPIKeysKey, ShouldEqual, "someprefix:UserAPIKeys")
		So(metaDB.VersionKey, ShouldEqual, "someprefix:Version")
		So(metaDB.FastRestartStampKey, ShouldEqual, "someprefix:FastRestartStamp")
		So(metaDB.LocksKey, ShouldEqual, "someprefix:Locks")

		So(metaDB.getUserLockKey("user1"), ShouldEqual, "someprefix:Locks:User:user1")
		So(metaDB.getRepoLockKey("repo1"), ShouldEqual, "someprefix:Locks:Repo:repo1")
		So(metaDB.getImageLockKey("image1"), ShouldEqual, "someprefix:Locks:Image:image1")
		So(metaDB.getVersionLockKey(), ShouldEqual, "someprefix:Locks:Version")
	})
}

func TestRepoReferenceCASRejectsStaleSnapshot(t *testing.T) {
	Convey("repo reference CAS rejects a stale snapshot from another Redis client", t, func() {
		miniRedis := miniredis.RunT(t)
		logger := log.NewTestLogger()
		opts, err := redis.ParseURL("redis://" + miniRedis.Addr())
		So(err, ShouldBeNil)

		client1 := redis.NewClient(opts)
		client2 := redis.NewClient(opts)
		defer client1.Close()
		defer client2.Close()

		metaDB1, err := New(client1, DBDriverParameters{KeyPrefix: "cas"}, logger)
		So(err, ShouldBeNil)
		_, err = New(client2, DBDriverParameters{KeyPrefix: "cas"}, logger)
		So(err, ShouldBeNil)

		ctx := context.Background()
		repo := "repo"
		metaV1 := []byte("meta-v1")
		blobsV1 := []byte("blobs-v1")
		lastUpdatedV1 := []byte("last-updated-v1")
		So(client1.HSet(ctx, metaDB1.RepoMetaKey, repo, metaV1).Err(), ShouldBeNil)
		So(client1.HSet(ctx, metaDB1.RepoBlobsKey, repo, blobsV1).Err(), ShouldBeNil)
		So(client1.HSet(ctx, metaDB1.RepoLastUpdatedKey, repo, lastUpdatedV1).Err(), ShouldBeNil)

		metaV2 := []byte("meta-v2")
		blobsV2 := []byte("blobs-v2")
		lastUpdatedV2 := []byte("last-updated-v2")
		So(metaDB1.commitRepoReferenceWithCAS(ctx, repo, metaV1, true, blobsV1, true, lastUpdatedV1, true,
			lastUpdatedV2, blobsV2, metaV2), ShouldBeNil)

		So(client2.HSet(ctx, metaDB1.RepoMetaKey, repo, []byte("other-writer")).Err(), ShouldBeNil)
		err = metaDB1.commitRepoReferenceWithCAS(ctx, repo, metaV2, true, blobsV2, true, lastUpdatedV2, true,
			[]byte("stale-last-updated"), []byte("stale-blobs"), []byte("stale-meta"))
		So(errors.Is(err, errRedisRepoReferenceConflict), ShouldBeTrue)
	})
}
