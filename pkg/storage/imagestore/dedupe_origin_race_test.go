package imagestore_test

import (
	"bytes"
	"context"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// recordRemovingCache removes the digest's cache record right before the first PutDuplicate, as
// another node deleting the origin between this node's lookup and its registration would.
type recordRemovingCache struct {
	storageTypes.Cache

	remove bool
	origin string
}

func (c *recordRemovingCache) PutDuplicate(digest godigest.Digest, path string) error {
	if c.remove {
		c.remove = false

		if err := c.Cache.DeleteBlob(digest, c.origin); err != nil {
			return err
		}
	}

	return c.Cache.PutDuplicate(digest, path)
}

func TestDedupeRegistrationNeverCreatesOrigin(t *testing.T) {
	content := []byte("dedupe-registration-content")
	digest := godigest.FromBytes(content)

	setup := func() (storageTypes.ImageStore, *recordRemovingCache, storageTypes.Cache, string) {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		racing := &recordRemovingCache{Cache: cacheDriver}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			&remoteNamedDriver{Driver: local.New(true)}, racing, nil, nil)

		So(imgStore.InitRepo(context.Background(), "repo-origin"), ShouldBeNil)

		origin := imgStore.BlobPath("repo-origin", digest)
		So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(origin, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)

		racing.origin = origin

		return imgStore, racing, cacheDriver, origin
	}

	Convey("CheckBlob does not make a placeholder the origin when the record was removed", t, func() {
		imgStore, racing, cacheDriver, _ := setup()
		racing.remove = true

		ok, _, err := imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldNotBeNil)
		So(ok, ShouldBeFalse)

		_, err = cacheDriver.GetBlob(digest)
		So(err, ShouldEqual, zerr.ErrCacheMiss)
	})

	Convey("A push whose origin record was removed becomes the origin", t, func() {
		imgStore, racing, cacheDriver, _ := setup()
		racing.remove = true

		_, size, err := imgStore.FullBlobUpload(context.Background(), "repo-push", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, len(content))

		pushed := imgStore.BlobPath("repo-push", digest)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, pushed)

		data, err := os.ReadFile(pushed)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})
}

// originChangingCache moves the origin to another copy right before a ReplaceBlob, as another
// node handing the same content off would.
type originChangingCache struct {
	storageTypes.Cache

	moveTo string
}

func (c *originChangingCache) ReplaceBlob(digest godigest.Digest, oldPath, newPath string) error {
	if c.moveTo != "" {
		target := c.moveTo
		c.moveTo = ""

		if err := c.Cache.SetOrigin(digest, target); err != nil {
			return err
		}
	}

	return c.Cache.ReplaceBlob(digest, oldPath, newPath)
}

func TestDeleteDedupeOriginConflict(t *testing.T) {
	Convey("A hand-off names the copy holding the content when another node named one without", t, func() {
		content := []byte("handoff-conflict-content")
		digest := godigest.FromBytes(content)

		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		changing := &originChangingCache{Cache: cacheDriver}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			&remoteNamedDriver{Driver: local.New(true)}, changing, nil, nil)

		ctx := context.Background()

		plant := func(repo string, body []byte) string {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

			return blobPath
		}

		plant("repo-a", content)
		second := plant("repo-b", []byte{})
		third := plant("repo-c", []byte{})

		changing.moveTo = third

		So(imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, second)
		So(cacheDriver.HasBlob(digest, third), ShouldBeTrue)

		data, err := os.ReadFile(second)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})
}
