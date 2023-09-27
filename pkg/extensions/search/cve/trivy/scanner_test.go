//go:build search

package trivy_test

import (
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	"zotregistry.io/zot/pkg/meta/boltdb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test/common"
	"zotregistry.io/zot/pkg/test/deprecated"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
)

func TestScanBigTestFile(t *testing.T) {
	Convey("Scan zot-test", t, func() {
		projRootDir, err := GetProjectRootDir()
		So(err, ShouldBeNil)

		testImage := filepath.Join(projRootDir, "test/data/zot-test")

		tempDir := t.TempDir()
		port := GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Storage.RootDirectory = tempDir
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			},
		}
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		err = CopyFiles(testImage, filepath.Join(tempDir, "zot-test"))
		So(err, ShouldBeNil)

		cm := NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		// scan
		scanner := trivy.NewScanner(ctlr.StoreController, ctlr.MetaDB, "ghcr.io/project-zot/trivy-db", "", ctlr.Log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage("zot-test:0.0.1")
		So(err, ShouldBeNil)
		So(cveMap, ShouldNotBeNil)
	})
}

func TestScanningByDigest(t *testing.T) {
	Convey("Scan the individual manifests inside an index", t, func() {
		// start server
		tempDir := t.TempDir()
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Storage.RootDirectory = tempDir
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			},
		}
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		cm := NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		// push index with 2 manifests: one with vulns and one without
		vulnImage := CreateDefaultVulnerableImage()

		simpleImage := CreateRandomImage()

		multiArch := deprecated.GetMultiarchImageForImages([]Image{simpleImage, //nolint:staticcheck
			vulnImage})

		err := UploadMultiarchImage(multiArch, baseURL, "multi-arch", "multi-arch-tag")
		So(err, ShouldBeNil)

		// scan
		scanner := trivy.NewScanner(ctlr.StoreController, ctlr.MetaDB, "ghcr.io/project-zot/trivy-db", "", ctlr.Log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage("multi-arch@" + vulnImage.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)

		cveMap, err = scanner.ScanImage("multi-arch@" + simpleImage.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldBeEmpty)

		cveMap, err = scanner.ScanImage("multi-arch@" + multiArch.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)

		cveMap, err = scanner.ScanImage("multi-arch:multi-arch-tag")
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)
	})
}

func TestScannerErrors(t *testing.T) {
	digest := godigest.FromString("dig")

	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("IsImageFormatSanable", func() {
			metaDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{}, zerr.ErrManifestDataNotFound
			}
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{}, zerr.ErrManifestDataNotFound
			}
			scanner := trivy.NewScanner(storeController, metaDB, "", "", log)

			_, err := scanner.ScanImage("repo@" + digest.String())
			So(err, ShouldNotBeNil)
		})
	})
}

func TestVulnerableLayer(t *testing.T) {
	Convey("Vulnerable layer", t, func() {
		vulnerableLayer, err := GetLayerWithVulnerability()
		So(err, ShouldBeNil)

		created, err := time.Parse(time.RFC3339, "2023-03-29T18:19:24Z")
		So(err, ShouldBeNil)

		config := ispec.Image{
			Created: &created,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			Config: ispec.ImageConfig{
				Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
				Cmd: []string{"/bin/sh"},
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
			},
		}

		img := CreateImageWith().
			LayerBlobs([][]byte{vulnerableLayer}).
			ImageConfig(config).
			Build()

		tempDir := t.TempDir()

		log := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(tempDir, false, false,
			log, monitoring.NewMetricsServer(false, log), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		err = WriteImageToFileSystem(img, "repo", img.DigestStr(), storeController)
		So(err, ShouldBeNil)

		params := boltdb.DBParameters{
			RootDir: tempDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage("repo@" + img.DigestStr())
		So(err, ShouldBeNil)
		t.Logf("cveMap: %v", cveMap)
		// As of September 17 2023 there are 5 CVEs:
		// CVE-2023-1255, CVE-2023-2650, CVE-2023-2975, CVE-2023-3817, CVE-2023-3446
		// There may be more discovered in the future
		So(len(cveMap), ShouldBeGreaterThanOrEqualTo, 5)
		So(cveMap, ShouldContainKey, "CVE-2023-1255")
		So(cveMap, ShouldContainKey, "CVE-2023-2650")
		So(cveMap, ShouldContainKey, "CVE-2023-2975")
		So(cveMap, ShouldContainKey, "CVE-2023-3817")
		So(cveMap, ShouldContainKey, "CVE-2023-3446")
	})
}
