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

// fullCache rejects every new copy of a digest as a record that cannot grow.
type fullCache struct {
	storageTypes.Cache
}

func (c *fullCache) PutDuplicate(_ godigest.Digest, _ string) error {
	return zerr.ErrCacheFull
}

func TestDedupeWhenCacheRecordIsFull(t *testing.T) {
	content := []byte("dedupe-capacity-content")
	digest := godigest.FromBytes(content)

	setup := func(originContent []byte) (storageTypes.ImageStore, storageTypes.Cache, string) {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			&remoteNamedDriver{Driver: local.New(true)}, &fullCache{Cache: cacheDriver}, nil, nil)

		So(imgStore.InitRepo(context.Background(), "repo-origin"), ShouldBeNil)

		origin := imgStore.BlobPath("repo-origin", digest)
		So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(origin, originContent, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)

		return imgStore, cacheDriver, origin
	}

	Convey("A push keeps a full copy when the record cannot track it", t, func() {
		imgStore, cacheDriver, origin := setup(content)

		_, size, err := imgStore.FullBlobUpload(context.Background(), "repo-push", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(size, ShouldEqual, len(content))

		pushed := imgStore.BlobPath("repo-push", digest)

		data, err := os.ReadFile(pushed)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(cacheDriver.HasBlob(digest, pushed), ShouldBeFalse)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, origin)
	})

	Convey("A push still repairs wrong origin content when it keeps a full copy", t, func() {
		imgStore, _, origin := setup(content[:4])

		_, _, err := imgStore.FullBlobUpload(context.Background(), "repo-push", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		for _, blobPath := range []string{origin, imgStore.BlobPath("repo-push", digest)} {
			data, err := os.ReadFile(blobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		}
	})

	Convey("CheckBlob keeps a full copy when the record cannot track it", t, func() {
		imgStore, cacheDriver, origin := setup(content)

		ok, size, err := imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, len(content))

		copied := imgStore.BlobPath("repo-copy", digest)

		data, err := os.ReadFile(copied)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(cacheDriver.HasBlob(digest, copied), ShouldBeFalse)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, origin)

		// the store lock was given back: another operation can take it
		ok, _, err = imgStore.CheckBlob(context.Background(), "repo-origin", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)

		uploads, err := imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	})

	Convey("CheckBlob does not keep a copy whose content does not match the digest", t, func() {
		imgStore, _, _ := setup([]byte("corrupt-origin-content!"))

		ok, _, err := imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldNotBeNil)
		So(ok, ShouldBeFalse)

		_, err = os.Stat(imgStore.BlobPath("repo-copy", digest))
		So(os.IsNotExist(err), ShouldBeTrue)

		uploads, err := imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	})
}
