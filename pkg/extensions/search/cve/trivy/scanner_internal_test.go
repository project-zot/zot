package trivy

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

func generateTestImage(storeController storage.StoreController, image string) {
	repoName, tag := common.GetImageDirAndTag(image)

	config, layers, manifest, err := test.GetImageComponents(10)
	So(err, ShouldBeNil)

	store := storeController.GetImageStore(repoName)
	err = store.InitRepo(repoName)
	So(err, ShouldBeNil)

	for _, layerBlob := range layers {
		layerReader := bytes.NewReader(layerBlob)
		layerDigest := godigest.FromBytes(layerBlob)
		_, _, err = store.FullBlobUpload(repoName, layerReader, layerDigest.String())
		So(err, ShouldBeNil)
	}

	configBlob, err := json.Marshal(config)
	So(err, ShouldBeNil)
	configReader := bytes.NewReader(configBlob)
	configDigest := godigest.FromBytes(configBlob)
	_, _, err = store.FullBlobUpload(repoName, configReader, configDigest.String())
	So(err, ShouldBeNil)

	manifestBlob, err := json.Marshal(manifest)
	So(err, ShouldBeNil)
	_, err = store.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBlob)
	So(err, ShouldBeNil)
}

func TestMultipleStoragePath(t *testing.T) {
	Convey("Test multiple storage path", t, func() {
		// Create temporary directory
		firstRootDir := t.TempDir()
		secondRootDir := t.TempDir()
		thirdRootDir := t.TempDir()

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		// Create ImageStore
		firstStore := local.NewImageStore(firstRootDir, false, storConstants.DefaultGCDelay,
			false, false, log, metrics, nil)

		secondStore := local.NewImageStore(secondRootDir, false, storConstants.DefaultGCDelay,
			false, false, log, metrics, nil)

		thirdStore := local.NewImageStore(thirdRootDir, false, storConstants.DefaultGCDelay,
			false, false, log, metrics, nil)

		storeController := storage.StoreController{}

		storeController.DefaultStore = firstStore

		subStore := make(map[string]storage.ImageStore)

		subStore["/a"] = secondStore
		subStore["/b"] = thirdStore

		storeController.SubStore = subStore

		layoutUtils := common.NewBaseOciLayoutUtils(storeController, log)

		scanner := NewScanner(storeController, layoutUtils, log)

		So(scanner.storeController.DefaultStore, ShouldNotBeNil)
		So(scanner.storeController.SubStore, ShouldNotBeNil)

		img0 := "test/image0:tag0"
		img1 := "a/test/image1:tag1"
		img2 := "b/test/image2:tag2"

		ctx := scanner.getTrivyContext(img0)
		So(ctx.Input, ShouldEqual, path.Join(firstStore.RootDir(), img0))

		ctx = scanner.getTrivyContext(img1)
		So(ctx.Input, ShouldEqual, path.Join(secondStore.RootDir(), img1))

		ctx = scanner.getTrivyContext(img2)
		So(ctx.Input, ShouldEqual, path.Join(thirdStore.RootDir(), img2))

		generateTestImage(storeController, img0)
		generateTestImage(storeController, img1)
		generateTestImage(storeController, img2)

		// Scanning image in default store
		cveMap, err := scanner.ScanImage(img0)
		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image in substore
		cveMap, err = scanner.ScanImage(img1)
		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image which does not exist
		cveMap, err = scanner.ScanImage("a/test/image2:tag100")
		So(err, ShouldNotBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Download the DB to a default store location without permissions
		err = os.Chmod(firstRootDir, 0o000)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB()
		So(err, ShouldNotBeNil)

		// Check the download works correctly when permissions allow
		err = os.Chmod(firstRootDir, 0o777)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		// Download the DB to a substore location without permissions
		err = os.Chmod(secondRootDir, 0o000)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB()
		So(err, ShouldNotBeNil)

		err = os.Chmod(secondRootDir, 0o777)
		So(err, ShouldBeNil)
	})
}
