package imagestore_test

import (
	"context"
	"errors"
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
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

var errMoveFailed = errors.New("move failed") //nolint: gochecknoglobals

// failingMoveDriver fails the first failures calls to Move, then delegates.
type failingMoveDriver struct {
	storageTypes.Driver

	failures int
}

func (d *failingMoveDriver) Move(sourcePath, destPath string) error {
	if d.failures > 0 {
		d.failures--

		return errMoveFailed
	}

	return d.Driver.Move(sourcePath, destPath)
}

var errSetOriginFailed = errors.New("set origin failed") //nolint: gochecknoglobals

// failingSetOriginCache fails the first failures calls that change the origin, SetOrigin or
// ReplaceBlob, then delegates.
type failingSetOriginCache struct {
	storageTypes.Cache

	failures int
}

func (c *failingSetOriginCache) SetOrigin(digest godigest.Digest, path string) error {
	if c.failures > 0 {
		c.failures--

		return errSetOriginFailed
	}

	return c.Cache.SetOrigin(digest, path)
}

func (c *failingSetOriginCache) ReplaceBlob(digest godigest.Digest, oldPath, newPath string) error {
	if c.failures > 0 {
		c.failures--

		return errSetOriginFailed
	}

	return c.Cache.ReplaceBlob(digest, oldPath, newPath)
}

// newLocalDedupeStoreAt returns a local image store with dedupe on and a BoltDB cache that
// stores relative paths, as local storage does.
func newLocalDedupeStoreAt(dir string, storeDriver storageTypes.Driver) (storageTypes.ImageStore, storageTypes.Cache) {
	log := zlog.NewTestLogger()

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)
	So(err, ShouldBeNil)

	return imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
		storeDriver, cacheDriver, nil, nil), cacheDriver
}

func TestDeleteDedupeOrigin(t *testing.T) {
	Convey("Deleting the dedupe origin removes it and leaves the next copy readable", t, func() {
		content := []byte("handoff-content")

		for _, testCase := range []struct {
			name      string
			driver    storageTypes.Driver
			relPaths  bool
			digest    godigest.Digest
			origin    []byte
			nextCopy  []byte
			nextAfter []byte
		}{
			{
				// the hand-off moves the origin onto the placeholder, which removes it
				name:   "remote, next copy is a placeholder",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(content), origin: content, nextCopy: []byte{}, nextAfter: content,
			},
			{
				// the hand-off has nothing to do, so the delete must remove the origin itself
				name:   "remote, next copy already holds the content",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(content), origin: content, nextCopy: content, nextAfter: content,
			},
			{
				name:   "remote, empty digest",
				driver: &remoteNamedDriver{Driver: local.New(true)},
				digest: godigest.FromBytes(nil), origin: []byte{}, nextCopy: []byte{}, nextAfter: []byte{},
			},
			{
				// older dedupe walks recorded zero-size local copies without repairing them: the
				// origin's content moves onto such a copy instead of being lost with the origin
				name:     "local, next copy is a corrupt zero-size copy",
				driver:   local.New(true),
				relPaths: true,
				digest:   godigest.FromBytes(content), origin: content, nextCopy: []byte{}, nextAfter: content,
			},
			{
				// relative cache paths, as local storage uses
				name:     "local",
				driver:   local.New(true),
				relPaths: true,
				digest:   godigest.FromBytes(content), origin: content, nextCopy: content, nextAfter: content,
			},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				plant := func(repo string, body []byte) string {
					So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

					blobPath := imgStore.BlobPath(repo, testCase.digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
					So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
					So(cacheDriver.PutBlob(testCase.digest, blobPath), ShouldBeNil)

					return blobPath
				}

				origin := plant("repo-origin", testCase.origin)
				nextCopy := plant("repo-copy", testCase.nextCopy)

				So(imgStore.DeleteBlob("repo-origin", testCase.digest), ShouldBeNil)

				_, err = os.Stat(origin)
				So(os.IsNotExist(err), ShouldBeTrue)

				// the cache no longer records the deleted copy, and points at the next one
				So(cacheDriver.HasBlob(testCase.digest, origin), ShouldBeFalse)

				record, err := cacheDriver.GetBlob(testCase.digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, nextCopy)

				data, err := os.ReadFile(nextCopy)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, testCase.nextAfter)
			})
		}
	})

	Convey("Deleting the dedupe origin succeeds when the next copy has gone", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		So(err, ShouldBeNil)

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			local.New(true), cacheDriver, nil, nil)

		ctx := context.Background()
		content := []byte("handoff-content")
		digest := godigest.FromBytes(content)

		var copies []string

		for _, repo := range []string{"repo-origin", "repo-copy"} {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, content, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

			copies = append(copies, blobPath)
		}

		// the cache still records the next copy, which is no longer on storage
		So(os.Remove(copies[1]), ShouldBeNil)

		So(imgStore.DeleteBlob("repo-origin", digest), ShouldBeNil)

		_, err = os.Stat(copies[0])
		So(os.IsNotExist(err), ShouldBeTrue)
	})

	Convey("A next copy missing from storage is dropped, and the one after it takes the content", t, func() {
		content := []byte("handoff-content")

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
			content  []byte
			nextCopy []byte
		}{
			{"remote, placeholder after it", &remoteNamedDriver{Driver: local.New(true)}, false, content, []byte{}},
			{"local, corrupt copy after it", local.New(true), true, content, []byte{}},
			// nothing to move for the empty digest, but the missing copy must still be dropped
			{"local, empty digest", local.New(true), true, []byte{}, []byte{}},
		} {
			Convey(testCase.name, func() {
				digest := godigest.FromBytes(testCase.content)

				dir := t.TempDir()
				log := zlog.NewTestLogger()

				cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: testCase.relPaths,
				}, log)
				So(err, ShouldBeNil)

				imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
					testCase.driver, cacheDriver, nil, nil)

				ctx := context.Background()

				plant := func(repo string, body []byte) string {
					So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

					blobPath := imgStore.BlobPath(repo, digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
					So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
					So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

					return blobPath
				}

				// the cache promotes copies in path order, so the missing one comes first
				origin := plant("repo-a-origin", testCase.content)
				missing := plant("repo-b-missing", testCase.content)
				nextCopy := plant("repo-c-next", testCase.nextCopy)
				So(os.Remove(missing), ShouldBeNil)

				So(imgStore.DeleteBlob("repo-a-origin", digest), ShouldBeNil)

				_, err = os.Stat(origin)
				So(os.IsNotExist(err), ShouldBeTrue)

				data, err := os.ReadFile(nextCopy)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, testCase.content)

				So(cacheDriver.HasBlob(digest, missing), ShouldBeFalse)

				record, err := cacheDriver.GetBlob(digest)
				So(err, ShouldBeNil)

				if testCase.relPaths {
					record = path.Join(dir, record)
				}

				So(record, ShouldEqual, nextCopy)
			})
		}
	})

	Convey("Failed hand-offs and cache updates never lose the content across retries", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		boltCache, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		storeDriver := &failingMoveDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}, failures: 1}
		cacheDriver := &failingSetOriginCache{Cache: boltCache, failures: 1}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			storeDriver, cacheDriver, nil, nil)

		ctx := context.Background()
		content := []byte("handoff-content")
		digest := godigest.FromBytes(content)

		plant := func(repo string, body []byte) string {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(boltCache.PutBlob(digest, blobPath), ShouldBeNil)

			return blobPath
		}

		origin := plant("repo-origin", content)
		placeholder := plant("repo-placeholder", []byte{})

		// the hand-off fails before the cache is touched
		So(errors.Is(imgStore.DeleteBlob("repo-origin", digest), errMoveFailed), ShouldBeTrue)

		data, err := os.ReadFile(origin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		record, err := boltCache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, origin)

		// the hand-off succeeds and the cache update fails: the content is already in the
		// placeholder, so nothing a later retry does can lose it
		So(errors.Is(imgStore.DeleteBlob("repo-origin", digest), errSetOriginFailed), ShouldBeTrue)

		data, err = os.ReadFile(placeholder)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(imgStore.DeleteBlob("repo-origin", digest), ShouldNotBeNil)

		ok, size, err := imgStore.CheckBlob(ctx, "repo-placeholder", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, len(content))
	})

	Convey("A copy holding the content is not deleted as a duplicate after a failed cache update", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		boltCache, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		cacheDriver := &failingSetOriginCache{Cache: boltCache, failures: 1}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			&remoteNamedDriver{Driver: local.New(true)}, cacheDriver, nil, nil)

		ctx := context.Background()
		content := []byte("handoff-content")
		digest := godigest.FromBytes(content)

		plant := func(repo string, body []byte) string {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(boltCache.PutBlob(digest, blobPath), ShouldBeNil)

			return blobPath
		}

		origin := plant("repo-a", content)
		second := plant("repo-b", []byte{})
		third := plant("repo-c", []byte{})

		// the content moves onto the second copy, but the cache still names the first
		So(errors.Is(imgStore.DeleteBlob("repo-a", digest), errSetOriginFailed), ShouldBeTrue)

		_, err = os.Stat(origin)
		So(os.IsNotExist(err), ShouldBeTrue)

		record, err := boltCache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, origin)

		// deleting the second copy hands the content on instead of losing it
		So(imgStore.DeleteBlob("repo-b", digest), ShouldBeNil)

		_, err = os.Stat(second)
		So(os.IsNotExist(err), ShouldBeTrue)

		data, err := os.ReadFile(third)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		record, err = boltCache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, third)
	})

	Convey("A failed repair of the next copy keeps the deleted copy as the cache origin", t, func() {
		dir := t.TempDir()
		storeDriver := &failingMoveDriver{Driver: local.New(true), failures: 1}
		imgStore, cacheDriver := newLocalDedupeStoreAt(dir, storeDriver)

		ctx := context.Background()
		content := []byte("handoff-content")
		digest := godigest.FromBytes(content)

		plant := func(repo string, body []byte) string {
			So(imgStore.InitRepo(ctx, repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
			So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

			return blobPath
		}

		origin := plant("repo-origin", content)
		corrupt := plant("repo-copy", []byte{})

		So(errors.Is(imgStore.DeleteBlob("repo-origin", digest), errMoveFailed), ShouldBeTrue)

		// nothing was lost, and the cache still names the copy holding the content
		data, err := os.ReadFile(origin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		record, err := cacheDriver.GetBlob(digest)
		So(err, ShouldBeNil)
		So(path.Join(dir, record), ShouldEqual, origin)

		// so the retry repairs the next copy rather than deleting the content
		So(imgStore.DeleteBlob("repo-origin", digest), ShouldBeNil)

		_, err = os.Stat(origin)
		So(os.IsNotExist(err), ShouldBeTrue)

		data, err = os.ReadFile(corrupt)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("Deleting one of two links to a truncated inode removes it", t, func() {
		dir := t.TempDir()
		imgStore, cacheDriver := newLocalDedupeStoreAt(dir, local.New(true))

		ctx := context.Background()
		digest := godigest.FromBytes([]byte("handoff-content"))

		origin := imgStore.BlobPath("repo-origin", digest)
		other := imgStore.BlobPath("repo-copy", digest)

		So(imgStore.InitRepo(ctx, "repo-origin"), ShouldBeNil)
		So(imgStore.InitRepo(ctx, "repo-copy"), ShouldBeNil)
		So(os.MkdirAll(path.Dir(origin), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.MkdirAll(path.Dir(other), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(origin, nil, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(os.Link(origin, other), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, origin), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, other), ShouldBeNil)

		// both links are zero-size, so there is no content to move, and renaming one link of
		// an inode onto another would succeed without removing either
		So(imgStore.DeleteBlob("repo-origin", digest), ShouldBeNil)

		_, err := os.Stat(origin)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(other)
		So(err, ShouldBeNil)
	})
}

// hookedMoveDriver runs onMove right before the first Move, while the hand-off has decided on its
// destination, as another node acting on that destination would.
type hookedMoveDriver struct {
	storageTypes.Driver

	onMove func(sourcePath, destPath string)
}

func (d *hookedMoveDriver) Move(sourcePath, destPath string) error {
	if d.onMove != nil {
		hook := d.onMove
		d.onMove = nil

		hook(sourcePath, destPath)
	}

	return d.Driver.Move(sourcePath, destPath)
}

// recordDroppingCache drops newPath from the record right before the first ReplaceBlob, as a
// delete of that copy on another node would.
type recordDroppingCache struct {
	storageTypes.Cache

	drop bool
}

func (c *recordDroppingCache) ReplaceBlob(digest godigest.Digest, oldPath, newPath string) error {
	if c.drop {
		c.drop = false

		if err := c.Cache.DeleteBlob(digest, newPath); err != nil {
			return err
		}
	}

	return c.Cache.ReplaceBlob(digest, oldPath, newPath)
}

func TestDeleteDedupeOriginWhileNextCopyIsDeleted(t *testing.T) {
	content := []byte("handoff-race-content")
	digest := godigest.FromBytes(content)

	type fixture struct {
		imgStore storageTypes.ImageStore
		cache    storageTypes.Cache
		dir      string
		relPaths bool
	}

	setup := func(driver storageTypes.Driver, cacheWrap func(storageTypes.Cache) storageTypes.Cache,
		relPaths bool,
	) fixture {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: relPaths,
		}, log)
		So(err, ShouldBeNil)

		storeCache := cacheDriver
		if cacheWrap != nil {
			storeCache = cacheWrap(cacheDriver)
		}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			driver, storeCache, nil, nil)

		return fixture{imgStore: imgStore, cache: cacheDriver, dir: dir, relPaths: relPaths}
	}

	plant := func(fix fixture, repo string, body []byte) string {
		So(fix.imgStore.InitRepo(context.Background(), repo), ShouldBeNil)

		blobPath := fix.imgStore.BlobPath(repo, digest)
		So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(fix.cache.PutBlob(digest, blobPath), ShouldBeNil)

		return blobPath
	}

	origin := func(fix fixture) string {
		record, err := fix.cache.GetBlob(digest)
		So(err, ShouldBeNil)

		if fix.relPaths {
			record = path.Join(fix.dir, record)
		}

		return record
	}

	// another node deletes the copy the hand-off is about to fill, record and file
	deleteNext := func(fix fixture) func(string, string) {
		return func(_, destPath string) {
			So(fix.cache.DeleteBlob(digest, destPath), ShouldBeNil)
			So(os.Remove(destPath), ShouldBeNil)
		}
	}

	Convey("The copy that received the content becomes the origin", t, func() {
		for _, testCase := range []struct {
			name     string
			driver   *hookedMoveDriver
			relPaths bool
		}{
			{
				"remote, next copy is a placeholder",
				&hookedMoveDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}}, false,
			},
			{"local, next copy is a corrupt zero-size copy", &hookedMoveDriver{Driver: local.New(true)}, true},
		} {
			Convey(testCase.name, func() {
				fix := setup(testCase.driver, nil, testCase.relPaths)
				testCase.driver.onMove = deleteNext(fix)

				first := plant(fix, "repo-a", content)
				second := plant(fix, "repo-b", []byte{})

				So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

				_, err := os.Stat(first)
				So(os.IsNotExist(err), ShouldBeTrue)

				data, err := os.ReadFile(second)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

				So(origin(fix), ShouldEqual, second)
				So(fix.cache.HasBlob(digest, second), ShouldBeTrue)
				So(fix.cache.HasBlob(digest, first), ShouldBeFalse)

				ok, size, err := fix.imgStore.CheckBlob(context.Background(), "repo-b", digest)
				So(err, ShouldBeNil)
				So(ok, ShouldBeTrue)
				So(size, ShouldEqual, len(content))
			})
		}
	})

	Convey("The copy that received the content is recorded under an origin another node named", t, func() {
		driver := &hookedMoveDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}}
		fix := setup(driver, nil, false)

		first := plant(fix, "repo-a", content)
		second := plant(fix, "repo-b", []byte{})
		third := plant(fix, "repo-c", content)

		driver.onMove = func(_, destPath string) {
			So(fix.cache.DeleteBlob(digest, destPath), ShouldBeNil)
			So(os.Remove(destPath), ShouldBeNil)
			So(fix.cache.SetOrigin(digest, third), ShouldBeNil)
		}

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		_, err := os.Stat(first)
		So(os.IsNotExist(err), ShouldBeTrue)

		So(origin(fix), ShouldEqual, third)
		So(fix.cache.HasBlob(digest, second), ShouldBeTrue)

		data, err := os.ReadFile(second)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("A hand-off that moved nothing leaves the origin in place on a conflict", t, func() {
		fix := setup(&remoteNamedDriver{Driver: local.New(true)}, func(c storageTypes.Cache) storageTypes.Cache {
			return &recordDroppingCache{Cache: c, drop: true}
		}, false)

		first := plant(fix, "repo-a", content)
		plant(fix, "repo-b", content)

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldEqual, zerr.ErrCacheConflict)

		data, err := os.ReadFile(first)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		So(origin(fix), ShouldEqual, first)
		So(fix.cache.HasBlob(digest, first), ShouldBeTrue)
	})

	Convey("Deleting a copy that has gone drops it as the origin", t, func() {
		fix := setup(&remoteNamedDriver{Driver: local.New(true)}, nil, false)

		first := plant(fix, "repo-a", content)
		second := plant(fix, "repo-b", content)

		So(os.Remove(first), ShouldBeNil)

		So(errors.Is(fix.imgStore.DeleteBlob("repo-a", digest), zerr.ErrBlobNotFound), ShouldBeTrue)

		So(origin(fix), ShouldEqual, second)
		So(fix.cache.HasBlob(digest, first), ShouldBeFalse)
	})
}

var errHandOffCache = errors.New("hand-off cache failure") //nolint: gochecknoglobals

// faultyCache makes ReplaceBlob report a conflict while conflict is set, and, once armed, lets
// allow more GetBlob calls through before failing the rest.
type faultyCache struct {
	storageTypes.Cache

	conflict bool
	armed    bool
	allow    int
}

func (c *faultyCache) GetBlob(digest godigest.Digest) (string, error) {
	if c.armed {
		if c.allow == 0 {
			return "", errHandOffCache
		}

		c.allow--
	}

	return c.Cache.GetBlob(digest)
}

func (c *faultyCache) ReplaceBlob(digest godigest.Digest, oldPath, newPath string) error {
	if c.conflict {
		return zerr.ErrCacheConflict
	}

	return c.Cache.ReplaceBlob(digest, oldPath, newPath)
}

// statFailingDriver fails Stat for one path with a transient error.
type statFailingDriver struct {
	storageTypes.Driver

	failPath string
}

func (d *statFailingDriver) Stat(path string) (driver.FileInfo, error) {
	if path == d.failPath {
		return nil, errclass.MarkTransient(errHandOffCache)
	}

	return d.Driver.Stat(path)
}

func TestDeleteDedupeOriginCacheFailures(t *testing.T) {
	content := []byte("handoff-failure-content")
	digest := godigest.FromBytes(content)

	type fixture struct {
		imgStore storageTypes.ImageStore
		cache    storageTypes.Cache
		faulty   *faultyCache
		moves    *hookedMoveDriver
		stats    *statFailingDriver
		first    string
		second   string
		third    string
	}

	setup := func() fixture {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		faulty := &faultyCache{Cache: cacheDriver}
		moves := &hookedMoveDriver{Driver: &remoteNamedDriver{Driver: local.New(true)}}
		stats := &statFailingDriver{Driver: moves}

		imgStore := imagestore.NewImageStore(dir, dir, true, true, log, monitoring.NewNopMetricServer(), nil,
			stats, faulty, nil, nil)

		plant := func(repo string, body []byte, record bool) string {
			So(imgStore.InitRepo(context.Background(), repo), ShouldBeNil)

			blobPath := imgStore.BlobPath(repo, digest)
			So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
			So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)

			if record {
				So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)
			}

			return blobPath
		}

		return fixture{
			imgStore: imgStore, cache: cacheDriver, faulty: faulty, moves: moves, stats: stats,
			first:  plant("repo-a", content, true),
			second: plant("repo-b", []byte{}, true),
			third:  plant("repo-c", content, false),
		}
	}

	Convey("The whole record removed during the hand-off: the copy becomes the origin", t, func() {
		fix := setup()
		fix.moves.onMove = func(_, _ string) {
			So(fix.cache.DeleteBlob(digest, fix.second), ShouldBeNil)
			So(fix.cache.DeleteBlob(digest, fix.first), ShouldBeNil)
		}

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		record, err := fix.cache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, fix.second)
	})

	Convey("The origin already moved to the copy by another node: nothing to publish", t, func() {
		fix := setup()
		fix.moves.onMove = func(_, _ string) {
			So(fix.cache.SetOrigin(digest, fix.second), ShouldBeNil)
		}

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldBeNil)

		record, err := fix.cache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, fix.second)
		So(fix.cache.HasBlob(digest, fix.first), ShouldBeFalse)
	})

	Convey("A cache that cannot be read for the publication fails the delete", t, func() {
		fix := setup()
		fix.moves.onMove = func(_, _ string) { fix.faulty.armed = true }

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldEqual, errHandOffCache)

		// the content is in the copy, and the record is unchanged for the retry
		data, err := os.ReadFile(fix.second)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		fix.faulty.armed = false

		record, err := fix.cache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, fix.first)
	})

	Convey("A cache that cannot be read while recording the copy fails the delete", t, func() {
		fix := setup()
		fix.faulty.conflict = true
		fix.moves.onMove = func(_, _ string) {
			fix.faulty.armed = true
			fix.faulty.allow = 1
		}

		So(fix.imgStore.DeleteBlob("repo-a", digest), ShouldEqual, errHandOffCache)

		data, err := os.ReadFile(fix.second)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
	})

	Convey("An origin that cannot be stat'd while recording the copy fails the delete", t, func() {
		fix := setup()
		fix.faulty.conflict = true
		fix.stats.failPath = fix.third
		fix.moves.onMove = func(_, _ string) {
			So(fix.cache.SetOrigin(digest, fix.third), ShouldBeNil)
		}

		err := fix.imgStore.DeleteBlob("repo-a", digest)
		So(errors.Is(err, errHandOffCache), ShouldBeTrue)

		record, err := fix.cache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, fix.third)
	})
}
