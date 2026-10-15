package imagestore_test

import (
	"context"
	"errors"
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

// staleReadCache answers the first GetBlob after a DeleteBlob with the deleted path, as an
// eventually consistent cache (DynamoDB) can.
type staleReadCache struct {
	storageTypes.Cache

	staleReads int
	deleted    string
}

func (c *staleReadCache) DeleteBlob(digest godigest.Digest, path string) error {
	c.deleted = path

	return c.Cache.DeleteBlob(digest, path)
}

func (c *staleReadCache) GetBlob(digest godigest.Digest) (string, error) {
	if c.deleted != "" && c.staleReads > 0 {
		c.staleReads--

		return c.deleted, nil
	}

	return c.Cache.GetBlob(digest)
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
		digest := godigest.FromBytes(content)

		for _, testCase := range []struct {
			name     string
			driver   storageTypes.Driver
			relPaths bool
			nextCopy []byte
		}{
			{"remote, placeholder after it", &remoteNamedDriver{Driver: local.New(true)}, false, []byte{}},
			{"local, corrupt copy after it", local.New(true), true, []byte{}},
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

					blobPath := imgStore.BlobPath(repo, digest)
					So(os.MkdirAll(path.Dir(blobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
					So(os.WriteFile(blobPath, body, storageConstants.DefaultFilePerms), ShouldBeNil)
					So(cacheDriver.PutBlob(digest, blobPath), ShouldBeNil)

					return blobPath
				}

				// the cache promotes copies in path order, so the missing one comes first
				origin := plant("repo-a-origin", content)
				missing := plant("repo-b-missing", content)
				nextCopy := plant("repo-c-next", testCase.nextCopy)
				So(os.Remove(missing), ShouldBeNil)

				So(imgStore.DeleteBlob("repo-a-origin", digest), ShouldBeNil)

				_, err = os.Stat(origin)
				So(os.IsNotExist(err), ShouldBeTrue)

				data, err := os.ReadFile(nextCopy)
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)

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

	Convey("A stale cache read that still names the deleted origin does not delete the content", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()

		boltCache, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
		So(err, ShouldBeNil)

		cacheDriver := &staleReadCache{Cache: boltCache, staleReads: 1}

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

		origin := plant("repo-origin", content)
		placeholder := plant("repo-placeholder", []byte{})

		err = imgStore.DeleteBlob("repo-origin", digest)
		So(errors.Is(err, zerr.ErrCacheStaleOrigin), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)

		// the only content copy survives, and is still the cache origin
		data, err := os.ReadFile(origin)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)

		record, err := boltCache.GetBlob(digest)
		So(err, ShouldBeNil)
		So(record, ShouldEqual, origin)

		// once the cache reads current, the retry hands the content off
		So(imgStore.DeleteBlob("repo-origin", digest), ShouldBeNil)

		_, err = os.Stat(origin)
		So(os.IsNotExist(err), ShouldBeTrue)

		data, err = os.ReadFile(placeholder)
		So(err, ShouldBeNil)
		So(data, ShouldResemble, content)
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
