package redisdb

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/log"
)

func Test(t *testing.T) {
	Convey("Test redis metadb key generation", t, func() {
		miniRedis := miniredis.RunT(t)

		log := log.NewLogger("debug", "")
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
		So(metaDB.LocksKey, ShouldEqual, "someprefix:Locks")

		So(metaDB.getUserLockKey("user1"), ShouldEqual, "someprefix:Locks:User:user1")
		So(metaDB.getRepoLockKey("repo1"), ShouldEqual, "someprefix:Locks:Repo:repo1")
		So(metaDB.getImageLockKey("image1"), ShouldEqual, "someprefix:Locks:Image:image1")
		So(metaDB.getVersionLockKey(), ShouldEqual, "someprefix:Locks:Version")
	})
}
