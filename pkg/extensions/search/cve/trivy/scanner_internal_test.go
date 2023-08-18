//go:build search
// +build search

package trivy

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	"zotregistry.io/zot/pkg/meta/boltdb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

func generateTestImage(storeController storage.StoreController, image string) {
	repoName, tag := common.GetImageDirAndTag(image)

	config, layers, manifest, err := test.GetImageComponents(10) //nolint:staticcheck
	So(err, ShouldBeNil)

	store := storeController.GetImageStore(repoName)
	err = store.InitRepo(repoName)
	So(err, ShouldBeNil)

	for _, layerBlob := range layers {
		layerReader := bytes.NewReader(layerBlob)
		layerDigest := godigest.FromBytes(layerBlob)
		_, _, err = store.FullBlobUpload(repoName, layerReader, layerDigest)
		So(err, ShouldBeNil)
	}

	configBlob, err := json.Marshal(config)
	So(err, ShouldBeNil)
	configReader := bytes.NewReader(configBlob)
	configDigest := godigest.FromBytes(configBlob)
	_, _, err = store.FullBlobUpload(repoName, configReader, configDigest)
	So(err, ShouldBeNil)

	manifestBlob, err := json.Marshal(manifest)
	So(err, ShouldBeNil)
	_, _, err = store.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBlob)
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

		// Create ImageStore

		firstStore := local.NewImageStore(firstRootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics,
			nil, nil)

		secondStore := local.NewImageStore(secondRootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics,
			nil, nil)

		thirdStore := local.NewImageStore(thirdRootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics,
			nil, nil)

		storeController := storage.StoreController{}

		storeController.DefaultStore = firstStore

		subStore := make(map[string]storageTypes.ImageStore)

		subStore["/a"] = secondStore
		subStore["/b"] = thirdStore

		storeController.SubStore = subStore

		params := boltdb.DBParameters{
			RootDir: firstRootDir,
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		scanner := NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		So(scanner.storeController.DefaultStore, ShouldNotBeNil)
		So(scanner.storeController.SubStore, ShouldNotBeNil)

		img0 := "test/image0:tag0"
		img1 := "a/test/image1:tag1"
		img2 := "b/test/image2:tag2"

		opts := scanner.getTrivyOptions(img0)
		So(opts.ScanOptions.Target, ShouldEqual, path.Join(firstStore.RootDir(), img0))

		opts = scanner.getTrivyOptions(img1)
		So(opts.ScanOptions.Target, ShouldEqual, path.Join(secondStore.RootDir(), img1))

		opts = scanner.getTrivyOptions(img2)
		So(opts.ScanOptions.Target, ShouldEqual, path.Join(thirdStore.RootDir(), img2))

		generateTestImage(storeController, img0)
		generateTestImage(storeController, img1)
		generateTestImage(storeController, img2)

		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		// Try to scan without the DB being downloaded
		_, err = scanner.ScanImage(img0)
		So(err, ShouldNotBeNil)
		So(err, ShouldWrap, zerr.ErrCVEDBNotFound)

		// Download DB since DB download on scan is disabled
		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

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

func TestTrivyLibraryErrors(t *testing.T) {
	Convey("Test trivy API errors", t, func() {
		// Create temporary directory
		rootDir := t.TempDir()

		storageCtlr := test.GetDefaultStoreController(rootDir, log.NewLogger("debug", ""))
		err := test.WriteImageToFileSystem(test.CreateDefaultVulnerableImage(), "zot-test", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)

		// Create ImageStore
		store := local.NewImageStore(rootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = store

		params := boltdb.DBParameters{
			RootDir: rootDir,
		}

		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		img := "zot-test:0.0.1" //nolint:goconst

		// Download DB fails for missing DB url
		scanner := NewScanner(storeController, metaDB, "", "", log)

		err = scanner.UpdateDB()
		So(err, ShouldNotBeNil)

		// Try to scan without the DB being downloaded
		opts := scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(opts)
		So(err, ShouldNotBeNil)
		So(err, ShouldWrap, zerr.ErrCVEDBNotFound)

		// Download DB fails for invalid Java DB
		scanner = NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db",
			"ghcr.io/project-zot/trivy-not-db", log)

		err = scanner.UpdateDB()
		So(err, ShouldNotBeNil)

		// Download DB passes for valid Trivy DB url, and missing Trivy Java DB url
		// Download DB is necessary since DB download on scan is disabled
		scanner = NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		// Scanning image with correct options
		opts = scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(opts)
		So(err, ShouldBeNil)

		// Scanning image with incorrect cache options
		// to trigger runner initialization errors
		opts.CacheOptions.CacheBackend = "redis://asdf!$%&!*)("
		_, err = scanner.runTrivy(opts)
		So(err, ShouldNotBeNil)

		// Scanning image with invalid input to trigger a scanner error
		opts = scanner.getTrivyOptions("nilnonexisting_image:0.0.1")
		_, err = scanner.runTrivy(opts)
		So(err, ShouldNotBeNil)

		// Scanning image with incorrect report options
		// to trigger report filtering errors
		opts = scanner.getTrivyOptions(img)
		opts.ReportOptions.IgnorePolicy = "invalid file path"
		_, err = scanner.runTrivy(opts)
		So(err, ShouldNotBeNil)
	})
}

func TestImageScannable(t *testing.T) {
	rootDir := t.TempDir()

	params := boltdb.DBParameters{
		RootDir: rootDir,
	}

	boltDriver, err := boltdb.GetBoltDriver(params)
	if err != nil {
		panic(err)
	}

	log := log.NewLogger("debug", "")

	metaDB, err := boltdb.New(boltDriver, log)
	if err != nil {
		panic(err)
	}

	// Create test data for the following cases
	// - Error: RepoMeta not found in DB
	// - Error: Tag not found in DB
	// - Error: Digest in RepoMeta is invalid
	// - Error: ManifestData not found in metadb
	// - Error: ManifestData cannot be unmarshalled
	// - Error: ManifestData contains unscannable layer type
	// - Valid Scannable image

	// Create metadb data for scannable image
	timeStamp := time.Date(2008, 1, 1, 12, 0, 0, 0, time.UTC)

	validConfigBlob, err := json.Marshal(ispec.Image{
		Created: &timeStamp,
	})
	if err != nil {
		panic(err)
	}

	validManifestBlob, err := json.Marshal(ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Size:      0,
			Digest:    godigest.FromBytes(validConfigBlob),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Size:      0,
				Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	validRepoMeta := mTypes.ManifestData{
		ManifestBlob: validManifestBlob,
		ConfigBlob:   validConfigBlob,
	}

	digestValidManifest := godigest.FromBytes(validManifestBlob)

	err = metaDB.SetManifestData(digestValidManifest, validRepoMeta)
	if err != nil {
		panic(err)
	}

	err = metaDB.SetRepoReference("repo1", "valid", digestValidManifest, ispec.MediaTypeImageManifest)
	if err != nil {
		panic(err)
	}

	// Create MetaDB data for manifest with unscannable layers
	manifestBlobUnscannableLayer, err := json.Marshal(ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Size:      0,
			Digest:    godigest.FromBytes(validConfigBlob),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "unscannable_media_type",
				Size:      0,
				Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
			},
		},
	})
	if err != nil {
		panic(err)
	}

	repoMetaUnscannableLayer := mTypes.ManifestData{
		ManifestBlob: manifestBlobUnscannableLayer,
		ConfigBlob:   validConfigBlob,
	}

	digestManifestUnscannableLayer := godigest.FromBytes(manifestBlobUnscannableLayer)

	err = metaDB.SetManifestData(digestManifestUnscannableLayer, repoMetaUnscannableLayer)
	if err != nil {
		panic(err)
	}

	err = metaDB.SetRepoReference("repo1", "unscannable-layer", digestManifestUnscannableLayer,
		ispec.MediaTypeImageManifest)
	if err != nil {
		panic(err)
	}

	// Create MetaDB data for unmarshable manifest
	unmarshableManifestBlob := []byte("Some string")
	repoMetaUnmarshable := mTypes.ManifestData{
		ManifestBlob: unmarshableManifestBlob,
		ConfigBlob:   validConfigBlob,
	}

	digestUnmarshableManifest := godigest.FromBytes(unmarshableManifestBlob)

	err = metaDB.SetManifestData(digestUnmarshableManifest, repoMetaUnmarshable)
	if err != nil {
		panic(err)
	}

	err = metaDB.SetRepoReference("repo1", "unmarshable", digestUnmarshableManifest, ispec.MediaTypeImageManifest)
	if err != nil {
		panic(err)
	}

	// Manifest meta cannot be found
	digestMissingManifest := godigest.FromBytes([]byte("Some other string"))

	err = metaDB.SetRepoReference("repo1", "missing", digestMissingManifest, ispec.MediaTypeImageManifest)
	if err != nil {
		panic(err)
	}

	// RepoMeta contains invalid digest
	err = metaDB.SetRepoReference("repo1", "invalid-digest", "invalid", ispec.MediaTypeImageManifest)
	if err != nil {
		panic(err)
	}

	// Continue with initializing the objects the scanner depends on
	metrics := monitoring.NewMetricsServer(false, log)

	store := local.NewImageStore(rootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics, nil, nil)

	storeController := storage.StoreController{}
	storeController.DefaultStore = store

	scanner := NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db",
		"ghcr.io/aquasecurity/trivy-java-db", log)

	Convey("Valid image should be scannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "valid")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Image with layers of unsupported types should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "unscannable-layer")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Image with unmarshable manifests should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "unmarshable")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Image with missing manifest meta should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "missing")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Image with invalid manifest digest should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "invalid-digest")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Image with unknown tag should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "unknown-tag")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Image with unknown repo should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("unknown-repo", "sometag")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})
}

func TestDefaultTrivyDBUrl(t *testing.T) {
	Convey("Test trivy DB download from default location", t, func() {
		// Create temporary directory
		rootDir := t.TempDir()

		err := test.CopyFiles("../../../../../test/data/zot-test", path.Join(rootDir, "zot-test"))
		So(err, ShouldBeNil)

		err = test.CopyFiles("../../../../../test/data/zot-cve-java-test", path.Join(rootDir, "zot-cve-java-test"))
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)

		// Create ImageStore
		store := local.NewImageStore(rootDir, false, storageConstants.DefaultGCDelay, false, false, log, metrics, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = store

		params := boltdb.DBParameters{
			RootDir: rootDir,
		}

		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		scanner := NewScanner(storeController, metaDB, "ghcr.io/aquasecurity/trivy-db",
			"ghcr.io/aquasecurity/trivy-java-db", log)

		// Download DB since DB download on scan is disabled
		err = scanner.UpdateDB()
		So(err, ShouldBeNil)

		// Scanning image
		img := "zot-test:0.0.1" //nolint:goconst

		opts := scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(opts)
		So(err, ShouldBeNil)

		// Scanning image containing a jar file
		img = "zot-cve-java-test:0.0.1"

		opts = scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(opts)
		So(err, ShouldBeNil)
	})
}

func TestIsIndexScanable(t *testing.T) {
	Convey("IsIndexScanable", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = &local.ImageStoreLocal{}

		metaDB := &boltdb.BoltDB{}
		log := log.NewLogger("debug", "")

		Convey("Find index in cache", func() {
			scanner := NewScanner(storeController, metaDB, "", "", log)

			scanner.cache.Add("digest", make(map[string]model.CVE))

			found, err := scanner.isIndexScanable("digest")
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
		})
	})
}

func TestScanIndexErrors(t *testing.T) {
	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("GetIndexData fails", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{}, godigest.ErrDigestUnsupported
			}

			scanner := NewScanner(storeController, metaDB, "", "", log)

			_, err := scanner.scanIndex("repo", "digest")
			So(err, ShouldNotBeNil)
		})

		Convey("Bad Index Blob, Unamrshal fails", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{
					IndexBlob: []byte(`bad-blob`),
				}, nil
			}

			scanner := NewScanner(storeController, metaDB, "", "", log)

			_, err := scanner.scanIndex("repo", "digest")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestIsIndexScanableErrors(t *testing.T) {
	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("GetIndexData errors", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{}, zerr.ErrManifestDataNotFound
			}
			scanner := NewScanner(storeController, metaDB, "", "", log)

			_, err := scanner.isIndexScanable("digest")
			So(err, ShouldNotBeNil)
		})

		Convey("bad index data, can't unmarshal", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{IndexBlob: []byte(`bad`)}, nil
			}
			scanner := NewScanner(storeController, metaDB, "", "", log)

			ok, err := scanner.isIndexScanable("digest")
			So(err, ShouldNotBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("is Manifest Scanable errors", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{IndexBlob: []byte(`{
					"manifests": [{
						"digest": "digest2"
						},
						{
							"digest": "digest1"
						}
					]
				}`)}, nil
			}
			metaDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				switch manifestDigest {
				case "digest1":
					return mTypes.ManifestData{
						ManifestBlob: []byte("{}"),
					}, nil
				case "digest2":
					return mTypes.ManifestData{}, zerr.ErrBadBlob
				}

				return mTypes.ManifestData{}, nil
			}
			scanner := NewScanner(storeController, metaDB, "", "", log)

			ok, err := scanner.isIndexScanable("digest")
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("is Manifest Scanable returns false because no manifest is scanable", func() {
			metaDB.GetIndexDataFn = func(indexDigest godigest.Digest) (mTypes.IndexData, error) {
				return mTypes.IndexData{IndexBlob: []byte(`{
					"manifests": [{
						"digest": "digest2"
						}
					]
				}`)}, nil
			}
			metaDB.GetManifestDataFn = func(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
				return mTypes.ManifestData{}, zerr.ErrBadBlob
			}
			scanner := NewScanner(storeController, metaDB, "", "", log)

			ok, err := scanner.isIndexScanable("digest")
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})
	})
}
