package meta_test

import (
	"context"
	"errors"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

func TestOnUpdateManifest(t *testing.T) {
	Convey("On UpdateManifest", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil, nil, nil)

		params := boltdb.DBParameters{
			RootDir: rootDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		image := CreateDefaultImage()

		err = WriteImageToFileSystem(CreateDefaultImage(), "repo", "tag1", storeController)
		So(err, ShouldBeNil)

		err = meta.OnUpdateManifest(context.Background(), "repo", "tag1", ispec.MediaTypeImageManifest, image.Digest(),
			image.ManifestDescriptor.Data, storeController, metaDB, log)
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), "repo")
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, "tag1")
	})
}

func TestUpdateErrors(t *testing.T) {
	Convey("Update operations", t, func() {
		imageStore := mocks.MockedImageStore{}
		storeController := storage.StoreController{DefaultStore: &imageStore}
		metaDB := mocks.MetaDBMock{}
		log := log.NewTestLogger()

		Convey("IsReferrersTag true update", func() {
			err := meta.OnUpdateManifest(context.Background(), "repo", "sha256-123", "digest", "media", []byte("bad"),
				storeController, metaDB, log)
			So(err, ShouldBeNil)
		})
		Convey("IsReferrersTag true delete", func() {
			err := meta.OnDeleteManifest("repo", "sha256-123", "digest", "media", []byte("bad"),
				storeController, metaDB, log)
			So(err, ShouldBeNil)
		})
	})
}
