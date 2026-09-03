package storage_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestStoreControllerSyncStagingRoots(t *testing.T) {
	Convey("StoreController sync staging root accessors", t, func() {
		logger := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		Convey("SyncStagingRoots returns downloadDir when set", func() {
			downloadDir := t.TempDir()
			localStore := local.NewImageStore(t.TempDir(), false, false, logger, metrics, nil, nil, nil, nil)

			sc := storage.StoreController{
				DefaultStore:    localStore,
				SyncDownloadDir: downloadDir,
			}

			So(sc.SyncStagingRoots(), ShouldResemble, []string{downloadDir})
		})

		Convey("SyncStagingRoots returns local store roots when downloadDir is empty", func() {
			defaultRoot := t.TempDir()
			subRoot := t.TempDir()
			defaultStore := local.NewImageStore(defaultRoot, false, false, logger, metrics, nil, nil, nil, nil)
			subStore := local.NewImageStore(subRoot, false, false, logger, metrics, nil, nil, nil, nil)

			storeController := storage.StoreController{
				DefaultStore: defaultStore,
				SubStore: map[string]storageTypes.ImageStore{
					"/a": subStore,
				},
			}

			roots := storeController.SyncStagingRoots()
			So(roots, ShouldContain, defaultRoot)
			So(roots, ShouldContain, subRoot)
			So(len(roots), ShouldEqual, 2)
		})

		Convey("SyncStagingRoots skips non-local stores", func() {
			remote := mocks.MockedImageStore{
				NameFn:    func() string { return "s3" },
				RootDirFn: func() string { return "/remote" },
			}

			sc := storage.StoreController{DefaultStore: remote}

			So(sc.SyncStagingRoots(), ShouldBeEmpty)
		})

		Convey("SyncStagingRootForImageStore returns downloadDir when set", func() {
			downloadDir := t.TempDir()
			localRoot := t.TempDir()
			localStore := local.NewImageStore(localRoot, false, false, logger, metrics, nil, nil, nil, nil)

			sc := storage.StoreController{SyncDownloadDir: downloadDir}

			So(sc.SyncStagingRootForImageStore(localStore), ShouldEqual, downloadDir)
		})

		Convey("SyncStagingRootForImageStore returns root for local stores", func() {
			localRoot := t.TempDir()
			localStore := local.NewImageStore(localRoot, false, false, logger, metrics, nil, nil, nil, nil)

			So(storage.StoreController{}.SyncStagingRootForImageStore(localStore), ShouldEqual, localRoot)
		})

		Convey("SyncStagingRootForImageStore returns empty for non-local stores", func() {
			remote := mocks.MockedImageStore{
				NameFn:    func() string { return "s3" },
				RootDirFn: func() string { return "/remote" },
			}

			So(storage.StoreController{}.SyncStagingRootForImageStore(remote), ShouldBeEmpty)
		})

		Convey("SyncStagingRootForRepo resolves the serving store", func() {
			defaultRoot := t.TempDir()
			subRoot := t.TempDir()
			defaultStore := local.NewImageStore(defaultRoot, false, false, logger, metrics, nil, nil, nil, nil)
			subStore := local.NewImageStore(subRoot, false, false, logger, metrics, nil, nil, nil, nil)

			storeController := storage.StoreController{
				DefaultStore: defaultStore,
				SubStore: map[string]storageTypes.ImageStore{
					"/a": subStore,
				},
			}

			So(storeController.SyncStagingRootForRepo("centos"), ShouldEqual, defaultRoot)
			So(storeController.SyncStagingRootForRepo("a/myrepo"), ShouldEqual, subRoot)
		})

		Convey("SyncStagingRoots deduplicates identical local roots", func() {
			sharedRoot := t.TempDir()
			sharedStore := local.NewImageStore(sharedRoot, false, false, logger, metrics, nil, nil, nil, nil)

			storeController := storage.StoreController{
				DefaultStore: sharedStore,
				SubStore: map[string]storageTypes.ImageStore{
					"/a": sharedStore,
				},
			}

			So(storeController.SyncStagingRoots(), ShouldResemble, []string{sharedRoot})
		})
	})
}
