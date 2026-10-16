package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

var errInjectedFault = errors.New("injected fault")

// faultyDriver is the local driver, failing the operations fail selects by name and path.
type faultyDriver struct {
	storageTypes.Driver

	fail func(op, path string) bool
}

func (d *faultyDriver) failed(op, path string) bool {
	return d.fail != nil && d.fail(op, path)
}

func (d *faultyDriver) Stat(path string) (driver.FileInfo, error) {
	if d.failed("Stat", path) {
		return nil, errInjectedFault
	}

	return d.Driver.Stat(path)
}

func (d *faultyDriver) EnsureDir(path string) error {
	if d.failed("EnsureDir", path) {
		return errInjectedFault
	}

	return d.Driver.EnsureDir(path)
}

func (d *faultyDriver) Link(src, dest string) error {
	if d.failed("Link", dest) {
		return errInjectedFault
	}

	return d.Driver.Link(src, dest)
}

func (d *faultyDriver) Delete(path string) error {
	if d.failed("Delete", path) {
		return errInjectedFault
	}

	return d.Driver.Delete(path)
}

func (d *faultyDriver) WriteFile(path string, content []byte) (int, error) {
	if d.failed("WriteFile", path) {
		return 0, errInjectedFault
	}

	return d.Driver.WriteFile(path, content)
}

func (d *faultyDriver) List(path string) ([]string, error) {
	if d.failed("List", path) {
		return nil, errInjectedFault
	}

	return d.Driver.List(path)
}

func (d *faultyDriver) Walk(path string, f driver.WalkFn) error {
	if d.failed("Walk", path) {
		return errInjectedFault
	}

	return d.Driver.Walk(path, f)
}

// faultyCache is a cache failing the writes fail selects by name and path.
type faultyCache struct {
	storageTypes.Cache

	fail func(op, path string) bool
}

func (c *faultyCache) failed(op, path string) bool {
	return c.fail != nil && c.fail(op, path)
}

func (c *faultyCache) PutBlob(digest godigest.Digest, path string) error {
	if c.failed("PutBlob", path) {
		return errInjectedFault
	}

	return c.Cache.PutBlob(digest, path)
}

func (c *faultyCache) DeleteBlob(digest godigest.Digest, path string) error {
	if c.failed("DeleteBlob", path) {
		return errInjectedFault
	}

	return c.Cache.DeleteBlob(digest, path)
}

// faultyLifecycle wraps a store's blob lifecycle, failing the steps a test selects. Without a
// hardlink count, the reclaim check asks the cache, as on platforms that report none.
type faultyLifecycle struct {
	imagestore.BlobLifecycle

	shouldDeleteErr   error
	removeMigratedErr error
	noLinkCount       bool
}

func (l *faultyLifecycle) ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
	isDigestReferenced func(godigest.Digest) (bool, error),
) (bool, error) {
	if l.shouldDeleteErr != nil {
		return false, l.shouldDeleteErr
	}

	if l.noLinkCount {
		referenced, err := isDigestReferenced(digest)

		return !referenced, err
	}

	return l.BlobLifecycle.ShouldDeleteGlobalBlob(globalBlobPath, digest, isDigestReferenced)
}

func (l *faultyLifecycle) RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath string) error {
	if l.removeMigratedErr != nil {
		return l.removeMigratedErr
	}

	return l.BlobLifecycle.RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath)
}

func inGlobalBlobstore(blobPath string) bool {
	return strings.Contains(blobPath, "/"+storageConstants.GlobalBlobsRepo+"/")
}

func newBoltCache(dir string) storageTypes.Cache {
	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, zlog.NewTestLogger())
	So(err, ShouldBeNil)

	return cacheDriver
}

// openFaultyStore opens a local store with dedupe on over dir, through a driver and a cache
// whose failures the test sets; it is nil when the store could not be created.
func openFaultyStore(dir string, storeDriver *faultyDriver, cacheDriver *faultyCache) storageTypes.ImageStore {
	return imagestore.NewImageStore(dir, dir, true, true, zlog.NewTestLogger(), monitoring.NewNopMetricServer(),
		nil, storeDriver, cacheDriver, nil, nil)
}

func TestGlobalBlobstoreFirstPushFailures(t *testing.T) {
	content := []byte("first-push-failures")
	digest := godigest.FromBytes(content)

	Convey("A first push that fails before the upload is renamed leaves it for the client to retry", t, func() {
		dir := t.TempDir()
		storeDriver := &faultyDriver{Driver: local.New(true)}
		cacheDriver := &faultyCache{Cache: newBoltCache(dir)}
		imgStore := openFaultyStore(dir, storeDriver, cacheDriver)
		So(imgStore, ShouldNotBeNil)

		push := func() error {
			_, _, err := imgStore.FullBlobUpload(context.Background(), "repo", bytes.NewReader(content), digest)

			return err
		}

		for _, testCase := range []struct {
			name        string
			driverFault func(op, path string) bool
			cacheFault  func(op, path string) bool
		}{
			{
				name:        "creating the blobstore directory fails",
				driverFault: func(op, p string) bool { return op == "EnsureDir" && inGlobalBlobstore(p) },
			},
			{
				name:        "linking the upload into the blobstore fails",
				driverFault: func(op, p string) bool { return op == "Link" && inGlobalBlobstore(p) },
			},
			{
				name:       "recording the blobstore copy fails",
				cacheFault: func(op, p string) bool { return op == "PutBlob" && inGlobalBlobstore(p) },
			},
		} {
			Convey(testCase.name, func() {
				storeDriver.fail, cacheDriver.fail = testCase.driverFault, testCase.cacheFault
				So(errors.Is(push(), errInjectedFault), ShouldBeTrue)

				_, err := os.Stat(imgStore.BlobPath("repo", digest))
				So(os.IsNotExist(err), ShouldBeTrue)

				storeDriver.fail, cacheDriver.fail = nil, nil
				So(push(), ShouldBeNil)

				data, err := os.ReadFile(imgStore.BlobPath("repo", digest))
				So(err, ShouldBeNil)
				So(data, ShouldResemble, content)
			})
		}

		Convey("failing to record the repo copy after the rename still commits the blob", func() {
			cacheDriver.fail = func(op, p string) bool { return op == "PutBlob" && !inGlobalBlobstore(p) }
			So(push(), ShouldBeNil)

			data, err := os.ReadFile(imgStore.BlobPath("repo", digest))
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)
		})

		Convey("a malformed digest is rejected before any blobstore path is built from it", func() {
			err := imgStore.DedupeBlob(path.Join(dir, "upload"), godigest.Digest("sha256:malformed"), "repo",
				path.Join(dir, "repo", "blob"))
			So(err, ShouldNotBeNil)

			_, err = os.Stat(path.Join(dir, storageConstants.GlobalBlobsRepo, ispec.ImageBlobsDir))
			So(os.IsNotExist(err), ShouldBeTrue)
		})
	})
}

func TestGlobalBlobstoreReclaimFailures(t *testing.T) {
	content := []byte("reclaim-failures")
	digest := godigest.FromBytes(content)

	Convey("A failed reclaim never fails the repo delete, and keeps or forgets the blobstore copy", t, func() {
		dir := t.TempDir()
		storeDriver := &faultyDriver{Driver: local.New(true)}
		cacheDriver := &faultyCache{Cache: newBoltCache(dir)}
		imgStore := openFaultyStore(dir, storeDriver, cacheDriver)
		So(imgStore, ShouldNotBeNil)

		globalBlobPath := imgStore.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		push := func(repo string) {
			_, _, err := imgStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
			So(err, ShouldBeNil)
		}

		globalCopyExists := func() bool {
			_, err := os.Stat(globalBlobPath)

			return err == nil
		}

		push("repo")

		Convey("the reclaim check fails: the copy stays", func() {
			imagestore.WrapLifecycle(imgStore, func(lifecycle imagestore.BlobLifecycle) imagestore.BlobLifecycle {
				return &faultyLifecycle{BlobLifecycle: lifecycle, shouldDeleteErr: errInjectedFault}
			})

			So(imgStore.DeleteBlob("repo", digest), ShouldBeNil)
			So(globalCopyExists(), ShouldBeTrue)
		})

		Convey("deleting the copy fails: it stays", func() {
			storeDriver.fail = func(op, p string) bool { return op == "Delete" && inGlobalBlobstore(p) }

			So(imgStore.DeleteBlob("repo", digest), ShouldBeNil)
			So(globalCopyExists(), ShouldBeTrue)
		})

		Convey("forgetting the copy fails: the file is gone and the record names a missing origin", func() {
			cacheDriver.fail = func(op, p string) bool { return op == "DeleteBlob" && inGlobalBlobstore(p) }

			So(imgStore.DeleteBlob("repo", digest), ShouldBeNil)
			So(globalCopyExists(), ShouldBeFalse)
		})

		Convey("without a hardlink count, the cache decides when the copy is unused", func() {
			imagestore.WrapLifecycle(imgStore, func(lifecycle imagestore.BlobLifecycle) imagestore.BlobLifecycle {
				return &faultyLifecycle{BlobLifecycle: lifecycle, noLinkCount: true}
			})
			push("other-repo")

			So(imgStore.DeleteBlob("repo", digest), ShouldBeNil)
			So(globalCopyExists(), ShouldBeTrue)

			So(imgStore.DeleteBlob("other-repo", digest), ShouldBeNil)
			So(globalCopyExists(), ShouldBeFalse)
		})
	})

	Convey("Failing to forget a deleted manifest's record does not fail the delete", t, func() {
		dir := t.TempDir()

		oldStore := imagestore.NewImageStore(dir, dir, false, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)

		img := image.CreateRandomImage()
		So(image.WriteImageToFileSystem(img, "repo", "tag", storage.StoreController{DefaultStore: oldStore}),
			ShouldBeNil)

		// the upgrade records the manifest's repo copy in the cache
		cacheDriver := &faultyCache{Cache: newBoltCache(dir)}
		imgStore := openFaultyStore(dir, &faultyDriver{Driver: local.New(true)}, cacheDriver)
		So(imgStore, ShouldNotBeNil)

		cacheDriver.fail = func(op, p string) bool { return op == "DeleteBlob" && !inGlobalBlobstore(p) }

		So(imgStore.DeleteImageManifest(context.Background(), "repo", img.Digest().String(), false), ShouldBeNil)

		_, err := os.Stat(imgStore.BlobPath("repo", img.Digest()))
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}

func TestUpgradeToGlobalBlobstoreFailures(t *testing.T) {
	content := []byte("upgrade-failures")
	digest := godigest.FromBytes(content)

	markerExists := func(dir string) bool {
		_, err := os.Stat(path.Join(dir, storageConstants.BlobstoreMigratedMarker))

		return err == nil
	}

	// legacyLayout lays out what an earlier release left with dedupe on: two repos sharing an
	// inode, both recorded in the cache, and no migration marker
	legacyLayout := func(dir string, cacheDriver storageTypes.Cache) string {
		oldStore := imagestore.NewImageStore(dir, dir, false, true, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)

		repoA := path.Join(dir, "repo-a", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
		repoB := path.Join(dir, "repo-b", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

		for _, repo := range []string{"repo-a", "repo-b"} {
			So(oldStore.InitRepo(context.Background(), repo), ShouldBeNil)
		}

		So(os.MkdirAll(path.Dir(repoA), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.MkdirAll(path.Dir(repoB), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(repoA, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(os.Link(repoA, repoB), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, repoA), ShouldBeNil)
		So(cacheDriver.PutBlob(digest, repoB), ShouldBeNil)

		return repoA
	}

	Convey("An upgrade that fails stops the store from being created and is not marked done", t, func() {
		for _, testCase := range []struct {
			name        string
			driverFault func(op, path string) bool
			cacheFault  func(op, path string) bool
		}{
			{
				name: "checking for the marker fails",
				driverFault: func(op, p string) bool {
					return op == "Stat" && path.Base(p) == storageConstants.BlobstoreMigratedMarker
				},
			},
			{
				name:        "listing the repos fails",
				driverFault: func(op, p string) bool { return op == "Walk" },
			},
			{
				name:        "creating the blobstore directory fails",
				driverFault: func(op, p string) bool { return op == "EnsureDir" && inGlobalBlobstore(p) },
			},
			{
				name:        "linking a repo copy into the blobstore fails",
				driverFault: func(op, p string) bool { return op == "Link" && inGlobalBlobstore(p) },
			},
			{
				name:       "recording a repo copy fails",
				cacheFault: func(op, p string) bool { return op == "PutBlob" && !inGlobalBlobstore(p) },
			},
		} {
			Convey(testCase.name, func() {
				dir := t.TempDir()
				boltCache := newBoltCache(dir)
				legacyLayout(dir, boltCache)

				storeDriver := &faultyDriver{Driver: local.New(true), fail: testCase.driverFault}
				So(openFaultyStore(dir, storeDriver, &faultyCache{Cache: boltCache, fail: testCase.cacheFault}),
					ShouldBeNil)
				So(markerExists(dir), ShouldBeFalse)

				// the next start completes it
				So(openFaultyStore(dir, &faultyDriver{Driver: local.New(true)}, &faultyCache{Cache: boltCache}),
					ShouldNotBeNil)
				So(markerExists(dir), ShouldBeTrue)
			})
		}
	})

	Convey("A repo that cannot be listed is skipped, and the upgrade is not marked done", t, func() {
		dir := t.TempDir()
		boltCache := newBoltCache(dir)
		legacyLayout(dir, boltCache)

		storeDriver := &faultyDriver{Driver: local.New(true), fail: func(op, p string) bool {
			return op == "List" && strings.Contains(p, "/repo-b/")
		}}
		So(openFaultyStore(dir, storeDriver, &faultyCache{Cache: boltCache}), ShouldNotBeNil)
		So(markerExists(dir), ShouldBeFalse)

		So(openFaultyStore(dir, &faultyDriver{Driver: local.New(true)}, &faultyCache{Cache: boltCache}),
			ShouldNotBeNil)
		So(markerExists(dir), ShouldBeTrue)
	})

	Convey("Failing to write the marker only means the next start upgrades again", t, func() {
		dir := t.TempDir()
		boltCache := newBoltCache(dir)
		legacyLayout(dir, boltCache)

		storeDriver := &faultyDriver{Driver: local.New(true), fail: func(op, p string) bool {
			return op == "WriteFile" && path.Base(p) == storageConstants.BlobstoreMigratedMarker
		}}
		So(openFaultyStore(dir, storeDriver, &faultyCache{Cache: boltCache}), ShouldNotBeNil)
		So(markerExists(dir), ShouldBeFalse)
	})

	Convey("Resuming an upgrade keeps a blobstore copy with content over empty repo copies", t, func() {
		dir := t.TempDir()
		boltCache := newBoltCache(dir)
		repoA := legacyLayout(dir, boltCache)

		// a previous pass promoted the content before the repo copies were emptied
		globalBlobPath := path.Join(dir, storageConstants.GlobalBlobsRepo, ispec.ImageBlobsDir,
			digest.Algorithm().String(), digest.Encoded())
		So(os.MkdirAll(path.Dir(globalBlobPath), storageConstants.DefaultDirPerms), ShouldBeNil)
		So(os.WriteFile(globalBlobPath, content, storageConstants.DefaultFilePerms), ShouldBeNil)
		So(os.Truncate(repoA, 0), ShouldBeNil)

		Convey("the blobstore copy becomes the origin", func() {
			So(openFaultyStore(dir, &faultyDriver{Driver: local.New(true)}, &faultyCache{Cache: boltCache}),
				ShouldNotBeNil)

			data, err := os.ReadFile(globalBlobPath)
			So(err, ShouldBeNil)
			So(data, ShouldResemble, content)

			record, err := boltCache.GetBlob(digest)
			So(err, ShouldBeNil)
			So(path.Join(dir, record), ShouldEqual, globalBlobPath)
		})

		Convey("failing to check the blobstore copy fails the upgrade", func() {
			storeDriver := &faultyDriver{Driver: local.New(true), fail: func(op, p string) bool {
				return op == "Stat" && inGlobalBlobstore(p)
			}}
			So(openFaultyStore(dir, storeDriver, &faultyCache{Cache: boltCache}), ShouldBeNil)
		})
	})

	Convey("Failing to remove a migrated repo copy fails the upgrade", t, func() {
		dir := t.TempDir()
		boltCache := newBoltCache(dir)
		legacyLayout(dir, boltCache)

		imgStore := openFaultyStore(dir, &faultyDriver{Driver: local.New(true)}, &faultyCache{Cache: boltCache})
		So(imgStore, ShouldNotBeNil)

		// the local lifecycle never removes repo copies, hardlinks of the blobstore copy, so
		// stand in for one that does and fails
		So(os.Remove(path.Join(dir, storageConstants.BlobstoreMigratedMarker)), ShouldBeNil)
		imagestore.WrapLifecycle(imgStore, func(lifecycle imagestore.BlobLifecycle) imagestore.BlobLifecycle {
			return &faultyLifecycle{BlobLifecycle: lifecycle, removeMigratedErr: errInjectedFault}
		})

		So(errors.Is(imagestore.UpgradeToGlobalBlobstore(imgStore), errInjectedFault), ShouldBeTrue)
		So(markerExists(dir), ShouldBeFalse)
	})
}
