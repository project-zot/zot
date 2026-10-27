package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
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

var errStagingFailed = errors.New("staging failed") //nolint: gochecknoglobals

// racingReadDriver runs onRead the first time the origin is read, while CheckBlob has released
// the store lock to stage its copy, and then fails the read if failRead is set. It also counts
// the moves onto the destination.
type racingReadDriver struct {
	storageTypes.Driver

	origin   string
	onRead   func()
	failRead bool
	dest     string
	moves    int
}

func (d *racingReadDriver) Reader(path string, offset int64) (io.ReadCloser, error) {
	if path == d.origin && d.onRead != nil {
		hook := d.onRead
		d.onRead = nil

		hook()

		if d.failRead {
			return nil, errStagingFailed
		}
	}

	return d.Driver.Reader(path, offset)
}

func (d *racingReadDriver) Move(sourcePath, destPath string) error {
	if destPath == d.dest {
		d.moves++
	}

	return d.Driver.Move(sourcePath, destPath)
}

func TestKeepFullCopyRacesWithPush(t *testing.T) {
	content := []byte("dedupe-capacity-race-content")
	digest := godigest.FromBytes(content)

	setup := func(failRead bool) (storageTypes.ImageStore, *racingReadDriver, string) {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		driver := &racingReadDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}, failRead: failRead}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			driver, &fullCache{Cache: cacheDriver}, nil, nil)

		So(imgStore.InitRepo(context.Background(), "repo-origin"), ShouldBeNil)

		origin := imgStore.BlobPath("repo-origin", digest)
		So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(origin, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)

		dest := imgStore.BlobPath("repo-copy", digest)

		driver.origin = origin
		driver.dest = dest
		// a push into the same repository lands a full copy while the lock is released
		driver.onRead = func() {
			_, _, err := imgStore.FullBlobUpload(context.Background(), "repo-copy", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)
		}

		return imgStore, driver, dest
	}

	Convey("A failed staging does not remove a copy a concurrent push committed", t, func() {
		imgStore, driver, dest := setup(true)

		ok, size, err := imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, len(content))

		data, err := os.ReadFile(dest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		// the push moved its upload onto the copy; CheckBlob did not
		So(driver.moves, ShouldEqual, 1)

		uploads, err := imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	})

	Convey("A successful staging does not overwrite a copy a concurrent push committed", t, func() {
		imgStore, driver, dest := setup(false)

		ok, size, err := imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, len(content))

		data, err := os.ReadFile(dest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(driver.moves, ShouldEqual, 1)

		// the staged copy was dropped
		uploads, err := imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	})
}
