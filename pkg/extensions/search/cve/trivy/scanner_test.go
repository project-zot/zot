package trivy_test

import (
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
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

func TestScanningByDigest(t *testing.T) {
	Convey("Scan the individual manifests inside an index", t, func() {
		// start server
		tempDir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
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

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		// push index with 2 manifests: one with vulns and one without
		vulnImage, err := test.GetVulnImage("")
		So(err, ShouldBeNil)
		vulnDigest, err := vulnImage.Digest()
		So(err, ShouldBeNil)

		simpleImage, err := test.GetRandomImage("")
		So(err, ShouldBeNil)
		simpleDigest, err := simpleImage.Digest()
		So(err, ShouldBeNil)

		multiArch := test.GetMultiarchImageForImages("multi-arch-tag", []test.Image{simpleImage, vulnImage})
		multiArchDigest, err := multiArch.Digest()
		So(err, ShouldBeNil)

		err = test.UploadMultiarchImage(multiArch, baseURL, "multi-arch")
		So(err, ShouldBeNil)

		// scan
		scanner := trivy.NewScanner(ctlr.StoreController, ctlr.RepoDB, "ghcr.io/project-zot/trivy-db", "", ctlr.Log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage("multi-arch@" + vulnDigest.String())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, test.Vulnerability1ID)
		So(cveMap, ShouldContainKey, test.Vulnerability2ID)
		So(cveMap, ShouldContainKey, test.Vulnerability3ID)

		cveMap, err = scanner.ScanImage("multi-arch@" + simpleDigest.String())
		So(err, ShouldBeNil)
		So(cveMap, ShouldBeEmpty)

		cveMap, err = scanner.ScanImage("multi-arch@" + multiArchDigest.String())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, test.Vulnerability1ID)
		So(cveMap, ShouldContainKey, test.Vulnerability2ID)
		So(cveMap, ShouldContainKey, test.Vulnerability3ID)

		cveMap, err = scanner.ScanImage("multi-arch:multi-arch-tag")
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, test.Vulnerability1ID)
		So(cveMap, ShouldContainKey, test.Vulnerability2ID)
		So(cveMap, ShouldContainKey, test.Vulnerability3ID)
	})
}

func TestScannerErrors(t *testing.T) {
	digest := godigest.FromString("dig")

	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		repoDB := mocks.RepoDBMock{}
		log := log.NewLogger("debug", "")

		Convey("IsImageFormatSanable", func() {
			repoDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
				return repodb.ManifestData{}, zerr.ErrManifestDataNotFound
			}
			repoDB.GetIndexDataFn = func(indexDigest godigest.Digest) (repodb.IndexData, error) {
				return repodb.IndexData{}, zerr.ErrManifestDataNotFound
			}
			scanner := trivy.NewScanner(storeController, repoDB, "", "", log)

			_, err := scanner.ScanImage("repo@" + digest.String())
			So(err, ShouldNotBeNil)
		})
	})
}

func TestVulnerableLayer(t *testing.T) {
	Convey("Vulnerable layer", t, func() {
		vulnerableLayer, err := test.GetLayerWithVulnerability(1)
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

		img, err := test.GetImageWithComponents(
			config,
			[][]byte{
				vulnerableLayer,
			},
		)
		So(err, ShouldBeNil)
		imgDigest, err := img.Digest()
		So(err, ShouldBeNil)

		tempDir := t.TempDir()

		log := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(tempDir, false, 0, false, false,
			log, monitoring.NewMetricsServer(false, log), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		err = test.WriteImageToFileSystem(img, "repo", storeController)
		So(err, ShouldBeNil)

		params := bolt.DBParameters{
			RootDir: tempDir,
		}
		boltDriver, err := bolt.GetBoltDriver(params)
		So(err, ShouldBeNil)

		repoDB, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(repoDB, storeController, log)
		So(err, ShouldBeNil)

		scanner := trivy.NewScanner(storeController, repoDB, "ghcr.io/project-zot/trivy-db", "", log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage("repo@" + imgDigest.String())
		So(err, ShouldBeNil)
		t.Logf("cveMap: %v", cveMap)
		// As of July 15 2023 there are 3 CVEs: CVE-2023-1255, CVE-2023-2650, CVE-2023-2975
		// There may be more discovered in the future
		So(len(cveMap), ShouldBeGreaterThanOrEqualTo, 3)
	})
}
