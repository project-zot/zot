package meta_test

import (
	"context"
	"errors"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

func TestOnUpdateManifest(t *testing.T) {
	Convey("On UpdateManifest", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		storeController.DefaultStore = local.NewImageStore(rootDir, true, true, log, metrics, nil, nil)

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
		log := log.NewLogger("debug", "")

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
