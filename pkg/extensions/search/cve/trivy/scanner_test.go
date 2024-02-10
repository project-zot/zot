//go:build search

package trivy_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	"zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	. "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

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

		err = scanner.UpdateDB(context.Background())
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage(context.Background(), "zot-test:0.0.1")
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

		multiArch := CreateMultiarchWith().Images([]Image{simpleImage, //nolint:staticcheck
			vulnImage}).Build()

		err := UploadMultiarchImage(multiArch, baseURL, "multi-arch", "multi-arch-tag")
		So(err, ShouldBeNil)

		// scan
		scanner := trivy.NewScanner(ctlr.StoreController, ctlr.MetaDB, "ghcr.io/project-zot/trivy-db", "", ctlr.Log)

		ctx := context.Background()

		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage(ctx, "multi-arch@"+vulnImage.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)

		cveMap, err = scanner.ScanImage(ctx, "multi-arch@"+simpleImage.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldBeEmpty)

		cveMap, err = scanner.ScanImage(ctx, "multi-arch@"+multiArch.DigestStr())
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)

		cveMap, err = scanner.ScanImage(ctx, "multi-arch:multi-arch-tag")
		So(err, ShouldBeNil)
		So(cveMap, ShouldContainKey, Vulnerability1ID)
		So(cveMap, ShouldContainKey, Vulnerability2ID)
		So(cveMap, ShouldContainKey, Vulnerability3ID)
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

		err = scanner.UpdateDB(context.Background())
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage(context.Background(), "repo@"+img.DigestStr())
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

	Convey("Vulnerable layer with vulnerability in language-specific file", t, func() {
		vulnerableLayer, err := GetLayerWithLanguageFileVulnerability()
		So(err, ShouldBeNil)

		created, err := time.Parse(time.RFC3339, "2024-02-15T09:56:01.500079786Z")
		So(err, ShouldBeNil)

		config := ispec.Image{
			Created: &created,
			Platform: ispec.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
			Config: ispec.ImageConfig{
				Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{"sha256:d789b0723f3e6e5064d612eb3c84071cc84a7cf7921d549642252c3295e5f937"},
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

		scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db",
			"ghcr.io/aquasecurity/trivy-java-db", log)

		err = scanner.UpdateDB(context.Background())
		So(err, ShouldBeNil)

		cveMap, err := scanner.ScanImage(context.Background(), "repo@"+img.DigestStr())
		So(err, ShouldBeNil)
		t.Logf("cveMap: %v", cveMap)

		// As of Feb 15 2024, there is 1 CVE in this layer:
		So(len(cveMap), ShouldBeGreaterThanOrEqualTo, 1)
		So(cveMap, ShouldContainKey, "CVE-2016-1000027")

		cveData := cveMap["CVE-2016-1000027"]
		vulnerablePackages := cveData.PackageList

		// There is only 1 vulnerable package in this layer
		So(len(vulnerablePackages), ShouldEqual, 1)
		vulnerableSpringWebPackage := vulnerablePackages[0]
		So(vulnerableSpringWebPackage.Name, ShouldEqual, "org.springframework:spring-web")
		So(vulnerableSpringWebPackage.InstalledVersion, ShouldEqual, "5.3.31")
		So(vulnerableSpringWebPackage.FixedVersion, ShouldEqual, "6.0.0")
		So(vulnerableSpringWebPackage.PackagePath, ShouldEqual, "usr/local/artifacts/spring-web-5.3.31.jar")
	})
}

func TestScannerErrors(t *testing.T) {
	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("IsImageFormatScannable", func() {
			storeController.DefaultStore = mocks.MockedImageStore{}
			metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
				return types.ImageMeta{}, ErrTestError
			}
			scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

			_, err := scanner.IsImageFormatScannable("repo", godigest.FromString("dig").String())
			So(err, ShouldNotBeNil)
		})
		Convey("IsImageMediaScannable", func() {
			storeController.DefaultStore = mocks.MockedImageStore{}
			metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
				return types.ImageMeta{}, ErrTestError
			}
			scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

			Convey("Manifest", func() {
				_, err := scanner.IsImageMediaScannable("repo", godigest.FromString("dig").String(), ispec.MediaTypeImageManifest)
				So(err, ShouldNotBeNil)
			})
			Convey("Index", func() {
				_, err := scanner.IsImageMediaScannable("repo", godigest.FromString("dig").String(), ispec.MediaTypeImageIndex)
				So(err, ShouldNotBeNil)
			})
			Convey("Index with nil index", func() {
				metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, nil
				}
				scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

				_, err := scanner.IsImageMediaScannable("repo", godigest.FromString("dig").String(), ispec.MediaTypeImageIndex)
				So(err, ShouldNotBeNil)
			})
			Convey("Index with good index", func() {
				metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{
						Index: &ispec.Index{
							Manifests: []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer}},
						},
						Manifests: []types.ManifestMeta{{Manifest: ispec.Manifest{
							Layers: []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer}},
						}}},
					}, nil
				}
				scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

				_, err := scanner.IsImageMediaScannable("repo", godigest.FromString("dig").String(), ispec.MediaTypeImageIndex)
				So(err, ShouldBeNil)
			})
		})
		Convey("ScanImage", func() {
			storeController.DefaultStore = mocks.MockedImageStore{}
			metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
				return types.ImageMeta{}, ErrTestError
			}

			scanner := trivy.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

			_, err := scanner.ScanImage(context.Background(), "image@"+godigest.FromString("digest").String())
			So(err, ShouldNotBeNil)
		})
	})
}
