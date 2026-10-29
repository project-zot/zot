package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
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

// faultWriterDriver fails the staging writer: opening it, its Commit, or its Close.
type faultWriterDriver struct {
	storageTypes.Driver

	mode string
}

func (d *faultWriterDriver) Writer(filepath string, isAppend bool) (driver.FileWriter, error) {
	if d.mode == "open" {
		return nil, errStagingFailed
	}

	writer, err := d.Driver.Writer(filepath, isAppend)
	if err != nil {
		return nil, err
	}

	return &faultWriter{FileWriter: writer, mode: d.mode}, nil
}

type faultWriter struct {
	driver.FileWriter

	mode string
}

func (w *faultWriter) Commit(ctx context.Context) error {
	if w.mode == "commit" {
		return errStagingFailed
	}

	return w.FileWriter.Commit(ctx)
}

func (w *faultWriter) Close() error {
	if w.mode == "close" {
		_ = w.FileWriter.Close()

		return errStagingFailed
	}

	return w.FileWriter.Close()
}

// erroringCache fails every PutDuplicate with an error that is neither a miss nor a full record.
type erroringCache struct {
	storageTypes.Cache
}

func (c *erroringCache) PutDuplicate(_ godigest.Digest, _ string) error {
	return errStagingFailed
}

func TestKeepFullCopyFailures(t *testing.T) {
	content := []byte("dedupe-capacity-failure-content")
	digest := godigest.FromBytes(content)

	type fixture struct {
		imgStore storageTypes.ImageStore
		cache    storageTypes.Cache
		origin   string
		dest     string
	}

	setup := func(dedupe bool, wrap func(storageTypes.Driver) storageTypes.Driver,
		storeCache func(storageTypes.Cache) storageTypes.Cache,
	) fixture {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		var storeDriver storageTypes.Driver = &remoteNamedDriver{Driver: local.New(true)}
		if wrap != nil {
			storeDriver = wrap(storeDriver)
		}

		var cacheForStore storageTypes.Cache = &fullCache{Cache: cacheDriver}
		if storeCache != nil {
			cacheForStore = storeCache(cacheDriver)
		}

		imgStore := imagestore.NewImageStore(dir, dir, dedupe, true, log, monitoring.NewNopMetricServer(), nil,
			storeDriver, cacheForStore, nil, nil)

		So(imgStore.InitRepo(context.Background(), "repo-origin"), ShouldBeNil)

		origin := imgStore.BlobPath("repo-origin", digest)
		So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(origin, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)

		return fixture{imgStore: imgStore, cache: cacheDriver, origin: origin, dest: imgStore.BlobPath("repo-copy", digest)}
	}

	expectNoCopy := func(fix fixture) {
		_, err := os.Stat(fix.dest)
		So(os.IsNotExist(err), ShouldBeTrue)

		uploads, err := fix.imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	}

	Convey("A placeholder is filled under a read lock when dedupe is off", t, func() {
		fix := setup(false, nil, nil)

		So(fix.imgStore.InitRepo(context.Background(), "repo-copy"), ShouldBeNil)
		So(os.MkdirAll(path.Dir(fix.dest), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(fix.dest, nil, storageConstants.DefaultFilePerms), ShouldBeNil)

		ok, size, err := fix.imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, len(content))

		data, err := os.ReadFile(fix.dest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("A placeholder removed while staging is filled", t, func() {
		var racing *racingReadDriver

		fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
			racing = &racingReadDriver{Driver: d}

			return racing
		}, nil)

		racing.origin = fix.origin
		racing.onRead = func() { So(os.Remove(fix.dest), ShouldBeNil) }

		ok, _, err := fix.imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)

		data, err := os.ReadFile(fix.dest)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("A copy that cannot be stat'd after staging fails, and the staged copy is dropped", t, func() {
		var (
			racing *racingReadDriver
			stats  *statFailingDriver
		)

		fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
			racing = &racingReadDriver{Driver: d}
			stats = &statFailingDriver{Driver: racing}

			return stats
		}, nil)

		racing.origin = fix.origin
		racing.onRead = func() { stats.failPath = fix.dest }

		ok, _, err := fix.imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(errors.Is(err, errHandOffCache), ShouldBeTrue)
		So(ok, ShouldBeFalse)

		uploads, err := fix.imgStore.ListBlobUploads("repo-copy")
		So(err, ShouldBeNil)
		So(uploads, ShouldBeEmpty)
	})

	Convey("A move that fails after staging removes both the staged copy and the placeholder", t, func() {
		fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
			return &failingMoveDriver{Driver: d, failures: 1}
		}, nil)

		ok, _, err := fix.imgStore.CheckBlob(context.Background(), "repo-copy", digest)
		So(errors.Is(err, errMoveFailed), ShouldBeTrue)
		So(ok, ShouldBeFalse)

		expectNoCopy(fix)
	})

	Convey("A staging that cannot be written fails and leaves nothing behind", t, func() {
		for _, mode := range []string{"open", "commit", "close"} {
			Convey("the writer fails on "+mode, func() {
				fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
					return &faultWriterDriver{Driver: d, mode: mode}
				}, nil)

				ok, _, err := fix.imgStore.CheckBlob(context.Background(), "repo-copy", digest)
				So(errors.Is(err, errStagingFailed), ShouldBeTrue)
				So(ok, ShouldBeFalse)

				expectNoCopy(fix)
			})
		}
	})

	Convey("A staging cancelled by its context fails and leaves nothing behind", t, func() {
		var racing *racingReadDriver

		fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
			racing = &racingReadDriver{Driver: d}

			return racing
		}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		racing.origin = fix.origin
		racing.onRead = cancel

		ok, _, err := fix.imgStore.CheckBlob(ctx, "repo-copy", digest)
		So(errors.Is(err, context.Canceled), ShouldBeTrue)
		So(ok, ShouldBeFalse)

		expectNoCopy(fix)
	})

	Convey("A push fails when the record cannot be updated for another reason", t, func() {
		fix := setup(true, nil, func(c storageTypes.Cache) storageTypes.Cache {
			return &erroringCache{Cache: c}
		})

		_, _, err := fix.imgStore.FullBlobUpload(context.Background(), "repo-push", bytes.NewReader(content), digest)
		So(errors.Is(err, errStagingFailed), ShouldBeTrue)
	})

	Convey("A push fails when the upload cannot replace the linked copy", t, func() {
		fix := setup(true, func(d storageTypes.Driver) storageTypes.Driver {
			return &failingMoveDriver{Driver: d, failures: 1}
		}, nil)

		_, _, err := fix.imgStore.FullBlobUpload(context.Background(), "repo-push", bytes.NewReader(content), digest)
		So(errors.Is(err, errMoveFailed), ShouldBeTrue)
	})
}
