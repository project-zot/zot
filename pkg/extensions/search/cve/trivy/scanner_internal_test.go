//go:build search

package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	fanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/sync/singleflight"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	cvecache "zotregistry.dev/zot/v2/pkg/extensions/search/cve/cache"
	"zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type fakeArtifactRunner struct {
	reportFn    func(ctx context.Context, opts flag.Options, report trivyTypes.Report) error
	scanImageFn func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error)
}

func (f fakeArtifactRunner) ScanImage(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	if f.scanImageFn != nil {
		return f.scanImageFn(ctx, opts)
	}

	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) ScanFilesystem(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) ScanRootfs(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) ScanRepository(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) ScanSBOM(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) ScanVM(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
	return trivyTypes.Report{}, nil
}

func (f fakeArtifactRunner) Filter(ctx context.Context, opts flag.Options, report trivyTypes.Report) (trivyTypes.Report, error) {
	return report, nil
}

func (f fakeArtifactRunner) Report(ctx context.Context, opts flag.Options, report trivyTypes.Report) error {
	if f.reportFn != nil {
		return f.reportFn(ctx, opts, report)
	}

	return nil
}

func (f fakeArtifactRunner) Close(ctx context.Context) error {
	return nil
}

var _ artifact.Runner = fakeArtifactRunner{}

func generateTestImage(storeController storage.StoreController, imageName string) Image {
	repoName, tag := zcommon.GetImageDirAndTag(imageName)

	image := CreateRandomImage()

	err := WriteImageToFileSystem(
		image, repoName, tag, storeController)
	So(err, ShouldBeNil)

	return image
}

func TestGenerateSBOM(t *testing.T) {
	Convey("generateSBOM writes report to file and returns digest metadata", t, func() {
		logger := log.NewTestLogger()
		scanner := Scanner{
			log: logger,
			sbomOptions: sbomOptions{
				enabled:        true,
				reportFormat:   trivyTypes.FormatSPDXJSON,
				artifactType:   defaultSBOMArtifactType,
				layerMediaType: defaultSBOMLayerMediaType,
			},
			scanSingleFlightGroup: &singleflight.Group{},
		}

		expectedSBOM := []byte(`{"spdxVersion":"SPDX-2.3"}`)
		mockRunner := fakeArtifactRunner{
			reportFn: func(ctx context.Context, opts flag.Options, report trivyTypes.Report) error {
				So(opts.ReportOptions.Output, ShouldNotEqual, "")
				So(opts.ReportOptions.Format, ShouldEqual, trivyTypes.FormatSPDXJSON)
				So(opts.ReportOptions.ListAllPkgs, ShouldBeTrue)
				So(opts.ReportOptions.DependencyTree, ShouldBeTrue)

				return os.WriteFile(opts.ReportOptions.Output, expectedSBOM, 0o600)
			},
		}

		generated, err := scanner.generateSBOM(context.Background(), mockRunner, flag.Options{}, trivyTypes.Report{})
		So(err, ShouldBeNil)
		So(generated, ShouldNotBeNil)
		So(generated.filePath, ShouldNotEqual, "")
		defer os.Remove(generated.filePath)

		storedSBOM, err := os.ReadFile(generated.filePath)
		So(err, ShouldBeNil)
		So(storedSBOM, ShouldResemble, expectedSBOM)
		So(generated.size, ShouldEqual, int64(len(expectedSBOM)))
		So(generated.digest, ShouldEqual, godigest.FromBytes(expectedSBOM))
	})
}

func TestRunTrivySBOMGenerationFailureIsNonFatal(t *testing.T) {
	Convey("runTrivy should return report and nil error when SBOM generation fails", t, func() {
		logger := log.NewTestLogger()
		rootDir := t.TempDir()

		dbDir := path.Join(rootDir, "_trivy", "db")
		err := os.MkdirAll(dbDir, 0o755)
		So(err, ShouldBeNil)
		err = os.WriteFile(metadata.Path(dbDir), []byte(`{"Version":2}`), 0o600)
		So(err, ShouldBeNil)

		store := local.NewImageStore(rootDir, false, false, logger, monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		storeController := storage.StoreController{DefaultStore: store}

		scanner := Scanner{
			log:             logger,
			storeController: storeController,
			sbomOptions: sbomOptions{
				enabled:      true,
				reportFormat: trivyTypes.FormatSPDXJSON,
			},
			scanSingleFlightGroup: &singleflight.Group{},
		}

		sbomErr := errors.New("sbom generation failed")
		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				reportFn: func(ctx context.Context, opts flag.Options, report trivyTypes.Report) error {
					return sbomErr
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		report, generated, err := scanner.runTrivy(context.Background(), flag.Options{
			Input: "repo:tag",
		})

		So(err, ShouldBeNil)
		So(report, ShouldResemble, trivyTypes.Report{})
		So(generated, ShouldBeNil)
	})
}

func TestMultipleStoragePath(t *testing.T) {
	Convey("Test multiple storage path", t, func() {
		// Create temporary directory
		firstRootDir := t.TempDir()
		secondRootDir := t.TempDir()
		thirdRootDir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		// Create ImageStore

		firstStore := local.NewImageStore(firstRootDir, false, false, log, metrics, nil, nil, nil, nil)

		secondStore := local.NewImageStore(secondRootDir, false, false, log, metrics, nil, nil, nil, nil)

		thirdStore := local.NewImageStore(thirdRootDir, false, false, log, metrics, nil, nil, nil, nil)

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

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, log)

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
		_, err = scanner.ScanImage(context.Background(), img0)
		So(err, ShouldNotBeNil)
		So(err, ShouldWrap, zerr.ErrCVEDBNotFound)

		// Try to scan with a context done

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = scanner.ScanImage(ctx, img0)
		So(err, ShouldNotBeNil)

		ctx = context.Background()

		// Download DB since DB download on scan is disabled
		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		// Scanning image in default store
		scanResult, err := scanner.ScanImage(ctx, img0)
		cveMap := scanResult.CVEMap

		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image in substore
		scanResult, err = scanner.ScanImage(ctx, img1)
		cveMap = scanResult.CVEMap
		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image which does not exist
		scanResult, err = scanner.ScanImage(ctx, "a/test/image2:tag100")
		cveMap = scanResult.CVEMap
		So(err, ShouldNotBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Download the DB to a default store location without permissions
		err = os.Chmod(firstRootDir, 0o000)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		// Check the download works correctly when permissions allow
		err = os.Chmod(firstRootDir, 0o777)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		// Download the DB to a substore location without permissions
		err = os.Chmod(secondRootDir, 0o000)
		So(err, ShouldBeNil)
		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		err = os.Chmod(secondRootDir, 0o777)
		So(err, ShouldBeNil)
	})
}

func TestTrivyLibraryErrors(t *testing.T) {
	Convey("Test trivy API errors", t, func() {
		// Create temporary directory
		rootDir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		// Create ImageStore
		store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = store

		err := WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-test", "0.0.1", storeController)
		So(err, ShouldBeNil)

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

		// Download DB fails for invalid DB url
		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-not-db",
			},
		}, log)

		ctx := context.Background()

		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		// Try to scan without a valid DB being downloaded
		opts := scanner.getTrivyOptions(img)
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)
		So(err, ShouldWrap, zerr.ErrCVEDBNotFound)

		// Download DB fails for invalid Java DB
		scanner = NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository:     "ghcr.io/project-zot/trivy-db",
				JavaDBRepository: "ghcr.io/project-zot/trivy-not-db",
			},
		}, log)

		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		// Download DB passes for valid Trivy DB url, and missing Trivy Java DB url
		// Download DB is necessary since DB download on scan is disabled
		scanner = NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, log)

		// UpdateDB with good ctx
		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		// Scanning image with correct options
		opts = scanner.getTrivyOptions(img)
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)

		// Scanning image with incorrect cache options
		// to trigger runner initialization errors
		opts.CacheOptions.CacheBackend = "redis://asdf!$%&!*)("
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)

		// Scanning image with invalid input to trigger a scanner error
		opts = scanner.getTrivyOptions("nilnonexisting_image:0.0.1")
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)

		// Scanning image with incorrect report options
		// to trigger report filtering errors
		opts = scanner.getTrivyOptions(img)
		opts.ReportOptions.IgnorePolicy = "invalid file path"
		_, _, err = scanner.runTrivy(ctx, opts)
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
		t.Fatal(err)
	}

	log := log.NewTestLogger()

	metaDB, err := boltdb.New(boltDriver, log)
	if err != nil {
		t.Fatal(err)
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

	validConfig := ispec.Image{
		Created: &timeStamp,
	}

	validImage := CreateImageWith().
		Layers([]Layer{{
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    ispec.DescriptorEmptyJSON.Digest,
			Blob:      ispec.DescriptorEmptyJSON.Data,
		}}).ImageConfig(validConfig).Build()

	err = metaDB.SetRepoReference(context.Background(), "repo1", "valid", validImage.AsImageMeta())
	if err != nil {
		t.Fatal(err)
	}

	validZstdImage := CreateImageWith().
		Layers([]Layer{{
			MediaType: ispec.MediaTypeImageLayerZstd,
			Digest:    ispec.DescriptorEmptyJSON.Digest,
			Blob:      ispec.DescriptorEmptyJSON.Data,
		}}).ImageConfig(validConfig).Build()

	err = metaDB.SetRepoReference(context.Background(), "repo1", "valid-zstd", validZstdImage.AsImageMeta())
	if err != nil {
		t.Fatal(err)
	}

	// Create MetaDB data for manifest with unscannable layers
	imageWithUnscannableLayer := CreateImageWith().
		Layers([]Layer{{
			MediaType: "unscannable_media_type",
			Digest:    ispec.DescriptorEmptyJSON.Digest,
			Blob:      ispec.DescriptorEmptyJSON.Data,
		}}).ImageConfig(validConfig).Build()

	err = metaDB.SetRepoReference(context.Background(), "repo1",
		"unscannable-layer", imageWithUnscannableLayer.AsImageMeta())
	if err != nil {
		t.Fatal(err)
	}

	// Continue with initializing the objects the scanner depends on
	metrics := monitoring.NewNopMetricServer()

	store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

	storeController := storage.StoreController{}
	storeController.DefaultStore = store

	scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
		Trivy: &extconf.TrivyConfig{
			DBRepository:     "ghcr.io/project-zot/trivy-db",
			JavaDBRepository: "ghcr.io/project-zot/trivy-java-db",
		},
	}, log)

	Convey("Valid image should be scannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "valid")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Valid image with zstd layer media type should be scannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "valid-zstd")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Image with layers of unsupported types should be unscannable", t, func() {
		result, err := scanner.IsImageFormatScannable("repo1", "unscannable-layer")
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

func TestTrivyDBUrl(t *testing.T) {
	Convey("Test trivy DB download", t, func() {
		// Create temporary directory
		rootDir := t.TempDir()

		err := test.CopyFiles("../../../../../test/data/zot-test", path.Join(rootDir, "zot-test"))
		So(err, ShouldBeNil)

		err = test.CopyFiles("../../../../../test/data/zot-cve-java-test", path.Join(rootDir, "zot-cve-java-test"))
		So(err, ShouldBeNil)

		log := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		// Create ImageStore
		store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

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

		// Ideally we would want to also test the default urls
		// But we are getting `response status code 429: toomanyrequests` from
		// `ghcr.io/aquasecurity/trivy-db` and `ghcr.io/aquasecurity/trivy-java-db`
		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository:     "ghcr.io/project-zot/trivy-db",
				JavaDBRepository: "ghcr.io/project-zot/trivy-java-db",
			},
		}, log)

		ctx := context.Background()

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Download DB with context done should return ctx error.
		err = scanner.UpdateDB(cancelCtx)
		So(err, ShouldNotBeNil)

		// Download DB since DB download on scan is disabled
		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		// Scanning image
		img := "zot-test:0.0.1" //nolint:goconst

		opts := scanner.getTrivyOptions(img)
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)

		// Scanning image containing a jar file
		img = "zot-cve-java-test:0.0.1"

		opts = scanner.getTrivyOptions(img)
		_, _, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)
	})
}

func TestIsIndexScanable(t *testing.T) {
	Convey("IsIndexScanable", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}
		log := log.NewTestLogger()

		Convey("Index digests are not cache keys for scannability", func() {
			metaDBMock := mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, zerr.ErrManifestNotFound
				},
			}

			scanner := Scanner{
				log:                   log,
				metaDB:                metaDBMock,
				storeController:       storeController,
				cache:                 cvecache.NewCveCache(cacheSize, log),
				scanSingleFlightGroup: &singleflight.Group{},
			}

			// Caching under an index digest must not short-circuit isIndexScannable.
			scanner.cache.Add("digest", make(map[string]zcommon.CVE))

			found, err := scanner.isIndexScannable("digest")
			So(err, ShouldNotBeNil)
			So(found, ShouldBeFalse)
		})
	})
}

func TestIsIndexScannableErrors(t *testing.T) {
	Convey("Errors", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = mocks.MockedImageStore{}

		metaDB := mocks.MetaDBMock{}
		log := log.NewTestLogger()

		Convey("all manifests of a index are not scannable", func() {
			unscannableLayer := []Layer{{MediaType: "unscannable-layer-type", Digest: godigest.FromString("123")}}
			img1 := CreateImageWith().Layers(unscannableLayer).RandomConfig().Build()
			img2 := CreateImageWith().Layers(unscannableLayer).RandomConfig().Build()
			multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

			metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
				return map[string]types.ImageMeta{
					img1.DigestStr():      img1.AsImageMeta(),
					img2.DigestStr():      img2.AsImageMeta(),
					multiarch.DigestStr(): multiarch.AsImageMeta(),
				}[digest.String()], nil
			}

			scanner := Scanner{
				log:                   log,
				metaDB:                metaDB,
				storeController:       storeController,
				cache:                 cvecache.NewCveCache(cacheSize, log),
				scanSingleFlightGroup: &singleflight.Group{},
			}

			ok, err := scanner.isIndexScannable(multiarch.DigestStr())
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})
	})
}

func TestScanIndexSkipsFailingChild(t *testing.T) {
	Convey("scanIndex continues when one child is missing from storage", t, func() {
		log := log.NewTestLogger()

		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB := mocks.MetaDBMock{
			GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
				return map[string]types.ImageMeta{
					img1.DigestStr():      img1.AsImageMeta(),
					img2.DigestStr():      img2.AsImageMeta(),
					multiarch.DigestStr(): multiarch.AsImageMeta(),
				}[digest.String()], nil
			},
		}

		store := mocks.MockedImageStore{
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				if digest.String() == img2.DigestStr() {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				}

				return true, 1, time.Time{}, nil
			},
		}

		scanner := Scanner{
			log:                   log,
			metaDB:                metaDB,
			storeController:       storage.StoreController{DefaultStore: store},
			cache:                 cvecache.NewCveCache(cacheSize, log),
			scanSingleFlightGroup: &singleflight.Group{},
		}

		cachedCVE := map[string]zcommon.CVE{
			"CVE-2024-1": {ID: "CVE-2024-1", Severity: "HIGH"},
		}
		scanner.cache.Add(img1.DigestStr(), cachedCVE)

		result, wasCached, err := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
		So(err, ShouldBeNil)
		So(result["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")
		So(wasCached, ShouldBeTrue)
		// Index aggregates are never cached under the index digest (presence is repo-local).
		So(scanner.cache.Get(multiarch.DigestStr()), ShouldBeNil)

		// Missing img2 is skipped; only present scannable img1 must be cached.
		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeTrue)
		agg := scanner.GetCachedResult("repo", multiarch.DigestStr())
		So(agg["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")
	})

	Convey("IsResultCached/GetCachedResult incomplete when a present child is uncached", t, func() {
		log := log.NewTestLogger()

		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB := mocks.MetaDBMock{
			GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
				return map[string]types.ImageMeta{
					img1.DigestStr():      img1.AsImageMeta(),
					img2.DigestStr():      img2.AsImageMeta(),
					multiarch.DigestStr(): multiarch.AsImageMeta(),
				}[digest.String()], nil
			},
		}

		store := mocks.MockedImageStore{
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				return true, 1, time.Time{}, nil
			},
		}

		scanner := Scanner{
			log:                   log,
			metaDB:                metaDB,
			storeController:       storage.StoreController{DefaultStore: store},
			cache:                 cvecache.NewCveCache(cacheSize, log),
			scanSingleFlightGroup: &singleflight.Group{},
		}

		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{
			"CVE-2024-1": {ID: "CVE-2024-1", Severity: "HIGH"},
		})

		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeFalse)

		scanner.cache.Add(img2.DigestStr(), map[string]zcommon.CVE{})
		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeTrue)
		agg := scanner.GetCachedResult("repo", multiarch.DigestStr())
		So(agg["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")

		_, wasCached, err := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
		So(err, ShouldBeNil)
		So(wasCached, ShouldBeTrue)
	})

	Convey("IsResultCached incomplete when present child scannability lookup fails", t, func() {
		log := log.NewTestLogger()

		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB := mocks.MetaDBMock{
			GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
				if digest.String() == img2.DigestStr() {
					return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
				}

				return map[string]types.ImageMeta{
					img1.DigestStr():      img1.AsImageMeta(),
					multiarch.DigestStr(): multiarch.AsImageMeta(),
				}[digest.String()], nil
			},
		}

		store := mocks.MockedImageStore{
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				return true, 1, time.Time{}, nil
			},
		}

		scanner := Scanner{
			log:                   log,
			metaDB:                metaDB,
			storeController:       storage.StoreController{DefaultStore: store},
			cache:                 cvecache.NewCveCache(cacheSize, log),
			scanSingleFlightGroup: &singleflight.Group{},
		}

		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{
			"CVE-2024-1": {ID: "CVE-2024-1", Severity: "HIGH"},
		})

		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeFalse)

		_, _, err := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
		So(err, ShouldNotBeNil)
	})

	Convey("IsResultCached skips unscannable present children", t, func() {
		log := log.NewTestLogger()

		unscannableLayer := []Layer{{MediaType: "unscannable-layer-type", Digest: godigest.FromString("123")}}
		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().Layers(unscannableLayer).RandomConfig().Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB := mocks.MetaDBMock{
			GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
				return map[string]types.ImageMeta{
					img1.DigestStr():      img1.AsImageMeta(),
					img2.DigestStr():      img2.AsImageMeta(),
					multiarch.DigestStr(): multiarch.AsImageMeta(),
				}[digest.String()], nil
			},
		}

		store := mocks.MockedImageStore{
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				return true, 1, time.Time{}, nil
			},
		}

		scanner := Scanner{
			log:                   log,
			metaDB:                metaDB,
			storeController:       storage.StoreController{DefaultStore: store},
			cache:                 cvecache.NewCveCache(cacheSize, log),
			scanSingleFlightGroup: &singleflight.Group{},
		}

		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{
			"CVE-2024-1": {ID: "CVE-2024-1", Severity: "HIGH"},
		})

		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeTrue)
		agg := scanner.GetCachedResult("repo", multiarch.DigestStr())
		So(agg["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")
	})

	Convey("scanIndex recurses into nested indexes without caching under nested digest", t, func() {
		log := log.NewTestLogger()

		leaf1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		leaf2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		inner := CreateMultiarchWith().Images([]Image{leaf1, leaf2}).Build()

		topLeaf := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()

		outerIndex := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    inner.Digest(),
					Size:      inner.IndexDescriptor.Size,
				},
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    topLeaf.ManifestDescriptor.Digest,
					Size:      topLeaf.ManifestDescriptor.Size,
				},
			},
		}
		outerBlob, err := json.Marshal(outerIndex)
		So(err, ShouldBeNil)
		outerDigest := godigest.FromBytes(outerBlob)
		outerMeta := types.ImageMeta{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    outerDigest,
			Size:      int64(len(outerBlob)),
			Index:     &outerIndex,
			Manifests: append(inner.AsImageMeta().Manifests, topLeaf.AsImageMeta().Manifests...),
		}

		metaDB := mocks.MetaDBMock{
			GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
				return map[string]types.ImageMeta{
					leaf1.DigestStr():    leaf1.AsImageMeta(),
					leaf2.DigestStr():    leaf2.AsImageMeta(),
					inner.DigestStr():    inner.AsImageMeta(),
					topLeaf.DigestStr():  topLeaf.AsImageMeta(),
					outerDigest.String(): outerMeta,
				}[digest.String()], nil
			},
		}

		store := mocks.MockedImageStore{
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				// Sparse: leaf2 under the nested index is absent in this repo.
				if digest.String() == leaf2.DigestStr() {
					return false, -1, time.Time{}, zerr.ErrBlobNotFound
				}

				return true, 1, time.Time{}, nil
			},
		}

		scanner := Scanner{
			log:                   log,
			metaDB:                metaDB,
			storeController:       storage.StoreController{DefaultStore: store},
			cache:                 cvecache.NewCveCache(cacheSize, log),
			scanSingleFlightGroup: &singleflight.Group{},
		}

		// Poison: a full nested-index "scan" result that must not be reused as a cache key.
		scanner.cache.Add(inner.DigestStr(), map[string]zcommon.CVE{
			"CVE-POISON": {ID: "CVE-POISON", Severity: "CRITICAL"},
		})
		scanner.cache.Add(leaf1.DigestStr(), map[string]zcommon.CVE{
			"CVE-2024-1": {ID: "CVE-2024-1", Severity: "HIGH"},
		})
		scanner.cache.Add(topLeaf.DigestStr(), map[string]zcommon.CVE{
			"CVE-2024-2": {ID: "CVE-2024-2", Severity: "LOW"},
		})

		result, wasCached, err := scanner.scanIndex(context.Background(), "repo", outerDigest.String())
		So(err, ShouldBeNil)
		So(wasCached, ShouldBeTrue)
		So(result["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")
		So(result["CVE-2024-2"].ID, ShouldEqual, "CVE-2024-2")
		So(result["CVE-POISON"].ID, ShouldEqual, "")
		So(scanner.cache.Get(outerDigest.String()), ShouldBeNil)

		So(scanner.IsResultCached("repo", outerDigest.String()), ShouldBeTrue)
		agg := scanner.GetCachedResult("repo", outerDigest.String())
		So(agg["CVE-POISON"].ID, ShouldEqual, "")
		So(agg["CVE-2024-1"].ID, ShouldEqual, "CVE-2024-1")
	})

	Convey("GetCachedResult returns empty map when index aggregate incomplete", t, func() {
		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return map[string]types.ImageMeta{
						img1.DigestStr():      img1.AsImageMeta(),
						img2.DigestStr():      img2.AsImageMeta(),
						multiarch.DigestStr(): multiarch.AsImageMeta(),
					}[digest.String()], nil
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{"CVE-1": {ID: "CVE-1"}})

		agg := scanner.GetCachedResult("repo", multiarch.DigestStr())
		So(agg, ShouldBeEmpty)
	})

	Convey("isIndexDigest false when meta lookup fails", t, func() {
		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
				},
			},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		So(scanner.isIndexDigest("sha256:"+strings.Repeat("a", 64)), ShouldBeFalse)
		So(scanner.IsResultCached("repo", "sha256:"+strings.Repeat("a", 64)), ShouldBeFalse)
	})

	Convey("cachedIndexAggregate/scanIndex incomplete on StatBlob storage errors", t, func() {
		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1}).Build()

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return map[string]types.ImageMeta{
						img1.DigestStr():      img1.AsImageMeta(),
						multiarch.DigestStr(): multiarch.AsImageMeta(),
					}[digest.String()], nil
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errors.New("s3 unavailable")
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{})

		So(scanner.IsResultCached("repo", multiarch.DigestStr()), ShouldBeFalse)
		_, _, err := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
		So(err, ShouldNotBeNil)
	})

	Convey("cachedIndexAggregate incomplete when nested child aggregate incomplete", t, func() {
		leaf1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		leaf2 := CreateImageWith().DefaultLayers().PlatformConfig("arm64", "linux").Build()
		inner := CreateMultiarchWith().Images([]Image{leaf1, leaf2}).Build()

		outerIndex := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    inner.Digest(),
				Size:      inner.IndexDescriptor.Size,
			}},
		}
		outerBlob, err := json.Marshal(outerIndex)
		So(err, ShouldBeNil)
		outerDigest := godigest.FromBytes(outerBlob)

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return map[string]types.ImageMeta{
						leaf1.DigestStr(): leaf1.AsImageMeta(),
						leaf2.DigestStr(): leaf2.AsImageMeta(),
						inner.DigestStr(): inner.AsImageMeta(),
						outerDigest.String(): {
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    outerDigest,
							Index:     &outerIndex,
						},
					}[digest.String()], nil
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(leaf1.DigestStr(), map[string]zcommon.CVE{})

		So(scanner.IsResultCached("repo", outerDigest.String()), ShouldBeFalse)
	})

	Convey("indexChildIsIndex falls back to meta when media type unknown", t, func() {
		leaf := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		inner := CreateMultiarchWith().Images([]Image{leaf}).Build()

		outerIndex := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{{
				MediaType: "application/vnd.unknown.manifest.v1+json",
				Digest:    inner.Digest(),
				Size:      inner.IndexDescriptor.Size,
			}},
		}
		outerBlob, err := json.Marshal(outerIndex)
		So(err, ShouldBeNil)
		outerDigest := godigest.FromBytes(outerBlob)

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return map[string]types.ImageMeta{
						leaf.DigestStr():  leaf.AsImageMeta(),
						inner.DigestStr(): inner.AsImageMeta(),
						outerDigest.String(): {
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    outerDigest,
							Index:     &outerIndex,
						},
					}[digest.String()], nil
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(leaf.DigestStr(), map[string]zcommon.CVE{"CVE-1": {ID: "CVE-1"}})

		So(scanner.indexChildIsIndex(outerIndex.Manifests[0]), ShouldBeTrue)
		So(scanner.IsResultCached("repo", outerDigest.String()), ShouldBeTrue)
	})

	Convey("scanIndex/cachedIndexAggregate break cycles in nested indexes", t, func() {
		leaf := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()

		digA := godigest.FromString("cycle-index-a")
		digB := godigest.FromString("cycle-index-b")
		indexA := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageIndex, Digest: digB, Size: 1},
				{MediaType: ispec.MediaTypeImageManifest, Digest: leaf.ManifestDescriptor.Digest, Size: leaf.ManifestDescriptor.Size},
			},
		}
		indexB := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageIndex, Digest: digA, Size: 1},
			},
		}

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					switch digest.String() {
					case digA.String():
						return types.ImageMeta{MediaType: ispec.MediaTypeImageIndex, Digest: digA, Index: &indexA}, nil
					case digB.String():
						return types.ImageMeta{MediaType: ispec.MediaTypeImageIndex, Digest: digB, Index: &indexB}, nil
					case leaf.DigestStr():
						return leaf.AsImageMeta(), nil
					default:
						return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
					}
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(leaf.DigestStr(), map[string]zcommon.CVE{"CVE-1": {ID: "CVE-1"}})

		result, wasCached, err := scanner.scanIndex(context.Background(), "repo", digA.String())
		So(err, ShouldBeNil)
		So(wasCached, ShouldBeTrue)
		So(result["CVE-1"].ID, ShouldEqual, "CVE-1")
		So(scanner.IsResultCached("repo", digA.String()), ShouldBeTrue)
	})

	Convey("scanIndex errors when index meta missing or nested meta fails", t, func() {
		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
				},
			},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		_, _, err := scanner.scanIndex(context.Background(), "repo", "sha256:"+strings.Repeat("b", 64))
		So(err, ShouldNotBeNil)

		leaf := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		innerDig := godigest.FromString("nested-missing-meta")
		outerIndex := ispec.Index{
			SchemaVersion: 2,
			MediaType:     ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    innerDig,
				Size:      1,
			}},
		}
		outerBlob, err := json.Marshal(outerIndex)
		So(err, ShouldBeNil)
		outerDigest := godigest.FromBytes(outerBlob)

		scanner = Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					if digest.String() == outerDigest.String() {
						return types.ImageMeta{
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    outerDigest,
							Index:     &outerIndex,
						}, nil
					}

					return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		_, _, err = scanner.scanIndex(context.Background(), "repo", outerDigest.String())
		So(err, ShouldNotBeNil)
		_ = leaf
	})

	Convey("scanIndex skips ErrScanNotSupported children", t, func() {
		unscannableLayer := []Layer{{MediaType: "unscannable-layer-type", Digest: godigest.FromString("123")}}
		img1 := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()
		img2 := CreateImageWith().Layers(unscannableLayer).RandomConfig().Build()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return map[string]types.ImageMeta{
						img1.DigestStr():      img1.AsImageMeta(),
						img2.DigestStr():      img2.AsImageMeta(),
						multiarch.DigestStr(): multiarch.AsImageMeta(),
					}[digest.String()], nil
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		scanner.cache.Add(img1.DigestStr(), map[string]zcommon.CVE{"CVE-1": {ID: "CVE-1"}})

		result, wasCached, err := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
		So(err, ShouldBeNil)
		So(wasCached, ShouldBeTrue)
		So(result["CVE-1"].ID, ShouldEqual, "CVE-1")
	})

	Convey("cachedIndexAggregate false when index meta missing Index", t, func() {
		dig := godigest.FromString("index-without-body")
		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					return types.ImageMeta{MediaType: ispec.MediaTypeImageIndex, Digest: dig}, nil
				},
			},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		So(scanner.IsResultCached("repo", dig.String()), ShouldBeFalse)
	})
}

func TestVulnSeveritySourcesDefaulting(t *testing.T) {
	Convey("NewScanner defaults VulnSeveritySources to auto when empty", t, func() {
		scanner := NewScanner(storage.StoreController{}, nil, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, log.NewTestLogger())
		So(scanner, ShouldNotBeNil)
		So(scanner.vulnSeveritySources, ShouldResemble, []dbTypes.SourceID{"auto"})
	})

	Convey("NewScanner preserves provided VulnSeveritySources", t, func() {
		scanner := NewScanner(storage.StoreController{}, nil, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository:        "ghcr.io/project-zot/trivy-db",
				VulnSeveritySources: []string{"nvd", "ghsa"},
			},
		}, log.NewTestLogger())
		So(scanner, ShouldNotBeNil)
		So(scanner.vulnSeveritySources, ShouldResemble, []dbTypes.SourceID{"nvd", "ghsa"})
	})

	Convey("NewScanner enables SBOM generation with default options", t, func() {
		scanner := NewScanner(storage.StoreController{}, nil, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
				SBOM: &extconf.SBOMConfig{
					Enable: true,
				},
			},
		}, log.NewTestLogger())
		So(scanner, ShouldNotBeNil)
		So(scanner.sbomOptions.enabled, ShouldBeTrue)
		So(scanner.sbomOptions.reportFormat, ShouldEqual, trivyTypes.FormatSPDXJSON)
		So(scanner.sbomOptions.artifactType, ShouldEqual, defaultSBOMArtifactType)
		So(scanner.sbomOptions.layerMediaType, ShouldEqual, defaultSBOMLayerMediaType)
	})

	Convey("NewScanner supports CycloneDX SBOM format", t, func() {
		scanner := NewScanner(storage.StoreController{}, nil, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
				SBOM: &extconf.SBOMConfig{
					Enable: true,
					Format: string(trivyTypes.FormatCycloneDX),
				},
			},
		}, log.NewTestLogger())
		So(scanner, ShouldNotBeNil)
		So(scanner.sbomOptions.reportFormat, ShouldEqual, trivyTypes.FormatCycloneDX)
		So(scanner.sbomOptions.artifactType, ShouldEqual, cycloneDXArtifactType)
		So(scanner.sbomOptions.layerMediaType, ShouldEqual, cycloneDXLayerMediaType)
	})
}

func TestIgnoreFileConfiguration(t *testing.T) {
	Convey("getNewScanOptions passes the configured ignore file to Trivy", t, func() {
		const ignoreFile = "/etc/zot/.trivyignore.yaml"

		opts := getNewScanOptions(t.TempDir(), nil, nil, []dbTypes.SourceID{"auto"}, ignoreFile, false, trivyScanTuning{})

		So(opts.ReportOptions.IgnoreFile, ShouldEqual, ignoreFile)
	})
}

func TestScanTuningConfiguration(t *testing.T) {
	// Regression test: enabling SBOM generation used to imply comprehensive CVE detection, which stops
	// Trivy filtering OS-owned files and re-reports them as language packages matched against NVD.
	Convey("enabling SBOM generation does not widen vulnerability detection", t, func() {
		tuning := getTrivyScanTuning(&extconf.TrivyConfig{
			SBOM: &extconf.SBOMConfig{Enable: true},
		}, log.NewTestLogger())

		opts := getNewScanOptions(t.TempDir(), nil, nil, []dbTypes.SourceID{"auto"}, "", true, tuning)

		So(opts.ScanOptions.DetectionPriority, ShouldEqual, fanalTypes.PriorityPrecise)
		So(opts.ImageOptions.ScanRemovedPkgs, ShouldBeFalse)
		So(opts.PackageOptions.IncludeDevDeps, ShouldBeFalse)

		So(opts.LicenseOptions.LicenseFull, ShouldBeTrue)
		So(opts.ScanOptions.Scanners, ShouldContain, trivyTypes.LicenseScanner)
	})

	Convey("scan tuning defaults to precise detection", t, func() {
		tuning := getTrivyScanTuning(&extconf.TrivyConfig{}, log.NewTestLogger())

		So(tuning.detectionPriority, ShouldEqual, fanalTypes.PriorityPrecise)
		So(tuning.scanRemovedPkgs, ShouldBeFalse)
		So(tuning.includeDevDeps, ShouldBeFalse)
	})

	Convey("scan tuning honors explicit configuration", t, func() {
		tuning := getTrivyScanTuning(&extconf.TrivyConfig{
			DetectionPriority: string(fanalTypes.PriorityComprehensive),
			ScanRemovedPkgs:   true,
			IncludeDevDeps:    true,
		}, log.NewTestLogger())

		opts := getNewScanOptions(t.TempDir(), nil, nil, []dbTypes.SourceID{"auto"}, "", false, tuning)

		So(opts.ScanOptions.DetectionPriority, ShouldEqual, fanalTypes.PriorityComprehensive)
		So(opts.ImageOptions.ScanRemovedPkgs, ShouldBeTrue)
		So(opts.PackageOptions.IncludeDevDeps, ShouldBeTrue)
	})

	Convey("detection priority is case insensitive", t, func() {
		tuning := getTrivyScanTuning(&extconf.TrivyConfig{
			DetectionPriority: "COMPREHENSIVE",
		}, log.NewTestLogger())

		So(tuning.detectionPriority, ShouldEqual, fanalTypes.PriorityComprehensive)
	})

	Convey("unsupported detection priority falls back to precise", t, func() {
		tuning := getTrivyScanTuning(&extconf.TrivyConfig{
			DetectionPriority: "aggressive",
		}, log.NewTestLogger())

		So(tuning.detectionPriority, ShouldEqual, fanalTypes.PriorityPrecise)
	})

	Convey("NewScanner propagates scan tuning to the store scan options", t, func() {
		logger := log.NewTestLogger()
		store := local.NewImageStore(t.TempDir(), false, false, logger,
			monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		scanner := NewScanner(storage.StoreController{DefaultStore: store}, nil, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository:      "ghcr.io/project-zot/trivy-db",
				DetectionPriority: string(fanalTypes.PriorityComprehensive),
				ScanRemovedPkgs:   true,
				IncludeDevDeps:    true,
			},
		}, logger)
		So(scanner, ShouldNotBeNil)

		opts := scanner.cveController.DefaultCveConfig
		So(opts, ShouldNotBeNil)
		So(opts.ScanOptions.DetectionPriority, ShouldEqual, fanalTypes.PriorityComprehensive)
		So(opts.ImageOptions.ScanRemovedPkgs, ShouldBeTrue)
		So(opts.PackageOptions.IncludeDevDeps, ShouldBeTrue)
	})
}

func TestStoreSBOMAsOCIArtifact(t *testing.T) {
	Convey("storeSBOMAsOCIArtifact stores SBOM once as OCI referrer", t, func() {
		rootDir := t.TempDir()

		logger := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		store := local.NewImageStore(rootDir, false, false, logger, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{
			DefaultStore: store,
		}

		params := boltdb.DBParameters{RootDir: rootDir}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, logger)
		So(err, ShouldBeNil)

		generateTestImage(storeController, "repo:1.0")

		_, subjectDigest, _, err := store.GetImageManifest("repo", "1.0")
		So(err, ShouldBeNil)

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
				SBOM: &extconf.SBOMConfig{
					Enable: true,
				},
			},
		}, logger)

		ctx := context.Background()

		sbomBlob := []byte(`{"spdxVersion":"SPDX-2.3"}`)
		sbomFile, err := os.CreateTemp("", "zot-trivy-sbom-test-*.json")
		So(err, ShouldBeNil)

		_, err = sbomFile.Write(sbomBlob)
		So(err, ShouldBeNil)

		err = sbomFile.Close()
		So(err, ShouldBeNil)
		defer os.Remove(sbomFile.Name())

		sbom := &generatedSBOM{
			filePath: sbomFile.Name(),
			digest:   godigest.FromBytes(sbomBlob),
			size:     int64(len(sbomBlob)),
		}

		err = scanner.storeSBOMAsOCIArtifact(ctx, "repo", subjectDigest.String(), sbom)
		So(err, ShouldBeNil)

		referrers, err := store.GetReferrers("repo", subjectDigest, []string{defaultSBOMArtifactType})
		So(err, ShouldBeNil)
		So(len(referrers.Manifests), ShouldEqual, 1)
		So(referrers.Manifests[0].ArtifactType, ShouldEqual, defaultSBOMArtifactType)

		metaReferrers, err := metaDB.GetReferrersInfo("repo", subjectDigest, []string{defaultSBOMArtifactType})
		So(err, ShouldBeNil)
		So(len(metaReferrers), ShouldEqual, 1)
		So(metaReferrers[0].Digest, ShouldEqual, referrers.Manifests[0].Digest.String())

		refManifestBlob, _, _, err := store.GetImageManifest("repo", referrers.Manifests[0].Digest.String())
		So(err, ShouldBeNil)

		var refManifest ispec.Manifest
		err = json.Unmarshal(refManifestBlob, &refManifest)
		So(err, ShouldBeNil)
		So(refManifest.Subject.Digest, ShouldEqual, subjectDigest)
		So(refManifest.Layers[0].MediaType, ShouldEqual, defaultSBOMLayerMediaType)

		err = scanner.storeSBOMAsOCIArtifact(ctx, "repo", subjectDigest.String(), sbom)
		So(err, ShouldBeNil)

		referrers, err = store.GetReferrers("repo", subjectDigest, []string{defaultSBOMArtifactType})
		So(err, ShouldBeNil)
		So(len(referrers.Manifests), ShouldEqual, 1)
	})
}

func TestGetCVEReference(t *testing.T) {
	Convey("getCVEReference", t, func() {
		ref := getCVEReference("CVE-2023-2650", "primary", []string{})
		So(ref, ShouldResemble, "primary")

		ref = getCVEReference("CVE-2023-2650", "", []string{"secondary"})
		So(ref, ShouldResemble, "secondary")

		ref = getCVEReference("CVE-2023-2650", "", []string{""})
		So(ref, ShouldResemble, "")

		ref = getCVEReference(
			"CVE-2023-2650",
			"",
			[]string{"https://nvd.nist.gov/vuln/detail/CVE-2023-2650"},
		)
		So(ref, ShouldResemble, "https://nvd.nist.gov/vuln/detail/CVE-2023-2650")

		ref = getCVEReference(
			"CVE-2026-42496",
			"https://avd.aquasec.com/nvd/cve-2026-42496",
			[]string{},
		)
		So(ref, ShouldResemble, "https://www.cve.org/CVERecord?id=CVE-2026-42496")

		ref = getCVEReference("", "https://avd.aquasec.com/nvd/cve-2026-42496", []string{})
		So(ref, ShouldResemble, "https://avd.aquasec.com/nvd/cve-2026-42496")

		ref = getCVEReference("GHSA-abcd-1234", "https://avd.aquasec.com/nvd/cve-2026-42496", []string{})
		So(ref, ShouldResemble, "https://avd.aquasec.com/nvd/cve-2026-42496")
	})
}

func initMockStoreWithFakeScannerDB(tempDir string) (storage.StoreController, error) {
	storeController := storage.StoreController{}
	store := mocks.MockedImageStore{}
	store.RootDirFn = func() string {
		return tempDir
	}
	storeController.DefaultStore = store

	err := os.MkdirAll(path.Join(tempDir, "_trivy", "db"), 0o755)
	if err != nil {
		return storeController, err
	}

	err = os.WriteFile(path.Join(tempDir, "_trivy", "db", "metadata.json"), []byte{1}, 0o644)

	return storeController, err
}

// flightGate holds the shared trivy scan open from the first scanImageFn entry until Release.
// Launch concurrent ScanImage callers only after WaitStarted (or while the leader is blocked
// in Hold) so they join the in-progress singleflight. Do not signal arrival before ScanImage:
// that can unblock the leader before anyone has joined and lets stragglers start another flight.
type flightGate struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newFlightGate() *flightGate {
	return &flightGate{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (g *flightGate) Hold() {
	g.once.Do(func() { close(g.started) })
	<-g.release
}

func (g *flightGate) WaitStarted(t *testing.T) {
	t.Helper()

	select {
	case <-g.started:
	case <-time.After(5 * time.Second):
		t.Fatal("shared scan did not start")
	}
}

func (g *flightGate) Release() {
	close(g.release)
}

// callCounter is a mutex-protected map of trivy target -> invocation count.
type callCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func newCallCounter() *callCounter {
	return &callCounter{m: map[string]int{}}
}

func (c *callCounter) Incr(target string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.m[target]++
}

func (c *callCounter) Get(target string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.m[target]
}

func (c *callCounter) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.m)
}

// runCoalescedScanWave starts one ScanImage to become the singleflight leader (blocked in
// gate.Hold), then starts the remaining callers so they join that flight, then releases.
// Failed scans are not cached, so followers that miss the open flight each start another
// uncached scan — hence the settle sleep while the leader still holds.
func runCoalescedScanWave(t *testing.T, n int, gate *flightGate,
	scan func() (model.ScanResult, error),
) ([]model.ScanResult, []error) {
	t.Helper()

	results := make([]model.ScanResult, 0, n)
	errs := make([]error, 0, n)
	var mu sync.Mutex
	var wg sync.WaitGroup

	collect := func() {
		defer wg.Done()

		res, err := scan()

		mu.Lock()
		results = append(results, res)
		errs = append(errs, err)
		mu.Unlock()
	}

	// Leader: enters the flight and blocks inside the fake runner's Hold.
	wg.Add(1)
	go collect()

	gate.WaitStarted(t)

	// Followers join the in-progress flight while the leader is still holding it open.
	for range n - 1 {
		wg.Add(1)
		go collect()
	}

	time.Sleep(100 * time.Millisecond)

	gate.Release()
	wg.Wait()

	return results, errs
}

func TestScannerCacheMissWithMultipleCallersSynchronization(t *testing.T) {
	Convey("Multiple concurrent scans for the same uncached digest should trigger only one scan", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		metaDB := mocks.MetaDBMock{}

		img1 := CreateRandomImage()

		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr(): img1.AsImageMeta(),
			}[digest.String()], nil
		}

		metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (types.RepoMeta, error) {
			imgDesc := types.Descriptor{
				Digest:          img1.DigestStr(),
				MediaType:       img1.Manifest.MediaType,
				TaggedTimestamp: time.Now(),
			}
			return types.RepoMeta{
				Name: repo,
				Tags: map[types.Tag]types.Descriptor{
					"1.0": imgDesc,
				},
			}, nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		calls := newCallCounter()
		var gate atomic.Pointer[flightGate]
		gate.Store(newFlightGate())

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					calls.Incr(opts.Target)
					gate.Load().Hold()

					return trivyTypes.Report{}, nil
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		runWave := func() {
			g := newFlightGate()
			gate.Store(g)

			results, errs := runCoalescedScanWave(t, 50, g, func() (model.ScanResult, error) {
				return scanner.ScanImage(context.Background(), "repo:1.0")
			})

			for _, scanErr := range errs {
				So(scanErr, ShouldBeNil)
			}

			for _, r := range results {
				So(r.Digest, ShouldNotBeEmpty)
			}
		}

		runWave()

		So(calls.Len(), ShouldEqual, 1)
		scanPath := path.Join(tempDir, "repo@"+img1.DigestStr())
		So(calls.Get(scanPath), ShouldEqual, 1)

		scanner.cache.Purge()
		runWave()

		So(calls.Len(), ShouldEqual, 1)
		So(calls.Get(scanPath), ShouldEqual, 2)
	})

	Convey("Multiple concurrent scans for the same uncached index should trigger only one scan", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		metaDB := mocks.MetaDBMock{}

		img1 := CreateRandomImage()
		img2 := CreateRandomImage()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr():      img1.AsImageMeta(),
				img2.DigestStr():      img2.AsImageMeta(),
				multiarch.DigestStr(): multiarch.AsImageMeta(),
			}[digest.String()], nil
		}

		metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (types.RepoMeta, error) {
			multiDesc := types.Descriptor{
				Digest:          multiarch.DigestStr(),
				MediaType:       multiarch.Index.MediaType,
				TaggedTimestamp: time.Now(),
			}
			return types.RepoMeta{
				Name: repo,
				Tags: map[types.Tag]types.Descriptor{
					"3.0": multiDesc,
				},
			}, nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		calls := newCallCounter()
		var gate atomic.Pointer[flightGate]
		gate.Store(newFlightGate())

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					calls.Incr(opts.Target)
					// First child holds until Release; later children see a closed release
					// channel and proceed immediately (index scans children sequentially).
					gate.Load().Hold()

					return trivyTypes.Report{}, nil
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		runWave := func() {
			g := newFlightGate()
			gate.Store(g)

			results, errs := runCoalescedScanWave(t, 50, g, func() (model.ScanResult, error) {
				return scanner.ScanImage(context.Background(), "repo:3.0")
			})

			for _, scanErr := range errs {
				So(scanErr, ShouldBeNil)
			}

			for _, r := range results {
				So(r.Digest, ShouldNotBeEmpty)
			}
		}

		runWave()

		So(calls.Len(), ShouldEqual, 2)
		scanPath := path.Join(tempDir, "repo@"+img1.DigestStr())
		So(calls.Get(scanPath), ShouldEqual, 1)
		scanPath2 := path.Join(tempDir, "repo@"+img2.DigestStr())
		So(calls.Get(scanPath2), ShouldEqual, 1)

		scanner.cache.Purge()
		runWave()

		So(calls.Len(), ShouldEqual, 2)
		So(calls.Get(scanPath), ShouldEqual, 2)
		So(calls.Get(scanPath2), ShouldEqual, 2)
	})

	Convey("Concurrent scans on an index resulting in an error should return the error for all callers", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		metaDB := mocks.MetaDBMock{}

		img1 := CreateRandomImage()
		img2 := CreateRandomImage()
		multiarch := CreateMultiarchWith().Images([]Image{img1, img2}).Build()

		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr():      img1.AsImageMeta(),
				img2.DigestStr():      img2.AsImageMeta(),
				multiarch.DigestStr(): multiarch.AsImageMeta(),
			}[digest.String()], nil
		}

		metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (types.RepoMeta, error) {
			multiDesc := types.Descriptor{
				Digest:          multiarch.DigestStr(),
				MediaType:       multiarch.Index.MediaType,
				TaggedTimestamp: time.Now(),
			}
			return types.RepoMeta{
				Name: repo,
				Tags: map[types.Tag]types.Descriptor{
					"3.0": multiDesc,
				},
			}, nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		calls := newCallCounter()
		var gate atomic.Pointer[flightGate]
		gate.Store(newFlightGate())

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					calls.Incr(opts.Target)
					gate.Load().Hold()

					return trivyTypes.Report{}, errors.New("fake scan error")
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		runWave := func() {
			g := newFlightGate()
			gate.Store(g)

			results, errs := runCoalescedScanWave(t, 50, g, func() (model.ScanResult, error) {
				return scanner.ScanImage(context.Background(), "repo:3.0")
			})

			for _, scanErr := range errs {
				So(scanErr, ShouldNotBeNil)
			}

			for _, r := range results {
				So(r.Digest, ShouldBeEmpty)
			}
		}

		runWave()

		// Since the first manifest errors out, the scan doesn't continue.
		So(calls.Len(), ShouldEqual, 1)
		scanPath := path.Join(tempDir, "repo@"+img1.DigestStr())
		So(calls.Get(scanPath), ShouldEqual, 1)

		scanner.cache.Purge()
		runWave()

		So(calls.Len(), ShouldEqual, 1)
		So(calls.Get(scanPath), ShouldEqual, 2)
	})

	Convey("Concurrent scans for a manifest with an error should return error for all waiting callers", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		metaDB := mocks.MetaDBMock{}

		img1 := CreateRandomImage()

		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr(): img1.AsImageMeta(),
			}[digest.String()], nil
		}

		metaDB.GetRepoMetaFn = func(ctx context.Context, repo string) (types.RepoMeta, error) {
			imgDesc := types.Descriptor{
				Digest:          img1.DigestStr(),
				MediaType:       img1.Manifest.MediaType,
				TaggedTimestamp: time.Now(),
			}
			return types.RepoMeta{
				Name: repo,
				Tags: map[types.Tag]types.Descriptor{
					"1.0": imgDesc,
				},
			}, nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		calls := newCallCounter()
		var gate atomic.Pointer[flightGate]
		gate.Store(newFlightGate())

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					calls.Incr(opts.Target)
					gate.Load().Hold()

					return trivyTypes.Report{}, errors.New("fake scan error")
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		runWave := func() {
			g := newFlightGate()
			gate.Store(g)

			results, errs := runCoalescedScanWave(t, 50, g, func() (model.ScanResult, error) {
				return scanner.ScanImage(context.Background(), "repo:1.0")
			})

			for _, scanErr := range errs {
				So(scanErr, ShouldNotBeNil)
			}

			for _, r := range results {
				So(r.Digest, ShouldBeEmpty)
			}
		}

		runWave()

		So(calls.Len(), ShouldEqual, 1)
		scanPath := path.Join(tempDir, "repo@"+img1.DigestStr())
		So(calls.Get(scanPath), ShouldEqual, 1)

		scanner.cache.Purge()
		runWave()

		So(calls.Len(), ShouldEqual, 1)
		So(calls.Get(scanPath), ShouldEqual, 2)
	})
}

func TestScanManifestCallerCancellationDoesNotAffectSharedScan(t *testing.T) {
	Convey("A caller whose ctx is canceled while waiting returns promptly "+
		"without canceling or waiting for the shared scan", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		metaDB := mocks.MetaDBMock{}
		img1 := CreateRandomImage()

		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr(): img1.AsImageMeta(),
			}[digest.String()], nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		var scanCalls int32

		scanStarted := make(chan struct{})
		release := make(chan struct{})

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					atomic.AddInt32(&scanCalls, 1)
					close(scanStarted)
					<-release

					return trivyTypes.Report{}, nil
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		leaderDone := make(chan struct{})

		// Leader: enters the flight group and blocks inside the fake runner until released.
		go func() {
			_, _, _ = scanner.scanManifest(context.Background(), "repo", img1.DigestStr())
			close(leaderDone)
		}()

		select {
		case <-scanStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("leader scan did not start")
		}

		// Follower: joins the same singleflight key, then abandons the wait via its
		// own ctx while the leader's scan is still blocked on release.
		followerCtx, cancel := context.WithCancel(context.Background())
		followerDone := make(chan error, 1)

		go func() {
			_, _, scanErr := scanner.scanManifest(followerCtx, "repo", img1.DigestStr())
			followerDone <- scanErr
		}()

		cancel()

		select {
		case scanErr := <-followerDone:
			So(errors.Is(scanErr, context.Canceled), ShouldBeTrue)
		case <-time.After(2 * time.Second):
			t.Fatal("follower did not return promptly after its ctx was canceled")
		}

		// The shared scan must be unaffected by the follower giving up.
		close(release)

		select {
		case <-leaderDone:
		case <-time.After(2 * time.Second):
			t.Fatal("leader scan did not complete after being released")
		}

		So(atomic.LoadInt32(&scanCalls), ShouldEqual, 1)
	})
}

func TestScanIndexCallerCancellationDoesNotAffectSharedScan(t *testing.T) {
	Convey("A follower whose ctx is canceled while waiting returns promptly "+
		"without affecting the shared index scan", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		img1 := CreateRandomImage()
		multiarch := CreateMultiarchWith().Images([]Image{img1}).Build()

		metaDB := mocks.MetaDBMock{}
		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr():      img1.AsImageMeta(),
				multiarch.DigestStr(): multiarch.AsImageMeta(),
			}[digest.String()], nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		var scanCalls int32

		scanStarted := make(chan struct{})
		release := make(chan struct{})

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					atomic.AddInt32(&scanCalls, 1)
					close(scanStarted)
					<-release

					return trivyTypes.Report{}, nil
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		leaderDone := make(chan struct{})

		// Leader: enters the index-level flight group and, via its traversal of the
		// index's single child, blocks inside the fake runner until released.
		go func() {
			_, _, _ = scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
			close(leaderDone)
		}()

		select {
		case <-scanStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("leader scan did not start")
		}

		// Follower: joins the same singleflight key, then abandons the wait via its
		// own ctx while the leader's traversal is still blocked on release.
		followerCtx, cancel := context.WithCancel(context.Background())
		followerDone := make(chan error, 1)

		go func() {
			_, _, scanErr := scanner.scanIndex(followerCtx, "repo", multiarch.DigestStr())
			followerDone <- scanErr
		}()

		cancel()

		select {
		case scanErr := <-followerDone:
			So(errors.Is(scanErr, context.Canceled), ShouldBeTrue)
		case <-time.After(2 * time.Second):
			t.Fatal("follower did not return promptly after its ctx was canceled")
		}

		// The shared scan must be unaffected by the follower giving up.
		close(release)

		select {
		case <-leaderDone:
		case <-time.After(2 * time.Second):
			t.Fatal("leader scan did not complete after being released")
		}

		So(atomic.LoadInt32(&scanCalls), ShouldEqual, 1)
	})

	Convey("The leader's own ctx being canceled must not poison the shared index scan's "+
		"result for other waiters still waiting on the same flight", t, func() {
		tempDir := t.TempDir()
		logger := log.NewTestLogger()

		storeController, err := initMockStoreWithFakeScannerDB(tempDir)
		So(err, ShouldBeNil)

		img1 := CreateRandomImage()
		multiarch := CreateMultiarchWith().Images([]Image{img1}).Build()

		metaDB := mocks.MetaDBMock{}
		metaDB.GetImageMetaFn = func(digest godigest.Digest) (types.ImageMeta, error) {
			return map[string]types.ImageMeta{
				img1.DigestStr():      img1.AsImageMeta(),
				multiarch.DigestStr(): multiarch.AsImageMeta(),
			}[digest.String()], nil
		}

		scanner := NewScanner(storeController, metaDB, &extconf.CVEConfig{
			Trivy: &extconf.TrivyConfig{
				DBRepository: "ghcr.io/project-zot/trivy-db",
			},
		}, logger)

		var scanCalls int32

		scanStarted := make(chan struct{})
		release := make(chan struct{})

		oldNewArtifactRunner := newArtifactRunner
		newArtifactRunner = func(ctx context.Context, opts flag.Options, target artifact.TargetKind,
			runnerOpts ...artifact.RunnerOption,
		) (artifact.Runner, error) {
			return fakeArtifactRunner{
				scanImageFn: func(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
					atomic.AddInt32(&scanCalls, 1)
					close(scanStarted)
					<-release

					return trivyTypes.Report{}, nil
				},
			}, nil
		}
		defer func() {
			newArtifactRunner = oldNewArtifactRunner
		}()

		leaderCtx, cancelLeader := context.WithCancel(context.Background())

		leaderDone := make(chan error, 1)

		// Leader: the first caller for this key, so its ctx is the one captured by the
		// index-level singleflight closure (see scanIndex's use of context.WithoutCancel).
		go func() {
			_, _, scanErr := scanner.scanIndex(leaderCtx, "repo", multiarch.DigestStr())
			leaderDone <- scanErr
		}()

		select {
		case <-scanStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("leader scan did not start")
		}

		// Follower: joins the same flight with its own, never-canceled ctx while the
		// leader's traversal is still blocked on release.
		followerDone := make(chan struct {
			wasCached bool
			err       error
		}, 1)

		go func() {
			_, wasCached, scanErr := scanner.scanIndex(context.Background(), "repo", multiarch.DigestStr())
			followerDone <- struct {
				wasCached bool
				err       error
			}{wasCached, scanErr}
		}()

		// Cancel the LEADER's own ctx (not the follower's) while the shared traversal is
		// still blocked. Without context.WithoutCancel wrapping the traversal, this ctx
		// cancellation would surface as the *shared* flight's result and poison the
		// still-waiting follower with context.Canceled even though its own ctx is fine.
		cancelLeader()

		select {
		case scanErr := <-leaderDone:
			So(errors.Is(scanErr, context.Canceled), ShouldBeTrue)
		case <-time.After(2 * time.Second):
			t.Fatal("leader did not return promptly after its own ctx was canceled")
		}

		// The underlying traversal must be unaffected by the leader's own cancellation.
		close(release)

		select {
		case result := <-followerDone:
			So(result.err, ShouldBeNil)
			So(result.wasCached, ShouldBeFalse)
		case <-time.After(2 * time.Second):
			t.Fatal("follower did not receive the shared scan's successful result")
		}

		So(atomic.LoadInt32(&scanCalls), ShouldEqual, 1)
	})
}

func TestScanIndexConcurrentCyclicRootsDoNotDeadlock(t *testing.T) {
	Convey("Concurrent top-level scans rooted at two indexes that cyclically reference "+
		"each other must not deadlock", t, func() {
		leaf := CreateImageWith().DefaultLayers().PlatformConfig("amd64", "linux").Build()

		digA := godigest.FromString("concurrent-cycle-index-a")
		digB := godigest.FromString("concurrent-cycle-index-b")
		indexA := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageIndex, Digest: digB, Size: 1},
				{MediaType: ispec.MediaTypeImageManifest, Digest: leaf.ManifestDescriptor.Digest, Size: leaf.ManifestDescriptor.Size},
			},
		}
		indexB := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageIndex, Digest: digA, Size: 1},
			},
		}

		scanner := Scanner{
			log: log.NewTestLogger(),
			metaDB: mocks.MetaDBMock{
				GetImageMetaFn: func(digest godigest.Digest) (types.ImageMeta, error) {
					switch digest.String() {
					case digA.String():
						return types.ImageMeta{MediaType: ispec.MediaTypeImageIndex, Digest: digA, Index: &indexA}, nil
					case digB.String():
						return types.ImageMeta{MediaType: ispec.MediaTypeImageIndex, Digest: digB, Index: &indexB}, nil
					case leaf.DigestStr():
						return leaf.AsImageMeta(), nil
					default:
						return types.ImageMeta{}, zerr.ErrRepoMetaNotFound
					}
				},
			},
			storeController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 1, time.Time{}, nil
				},
			}},
			cache:                 cvecache.NewCveCache(cacheSize, log.NewTestLogger()),
			scanSingleFlightGroup: &singleflight.Group{},
		}
		// Pre-cache the leaf manifest so scanManifest short-circuits on its top cache
		// check: this test targets the index-traversal dedup logic, not a real trivy scan.
		scanner.cache.Add(leaf.DigestStr(), map[string]zcommon.CVE{"CVE-1": {ID: "CVE-1"}})

		type scanOutcome struct {
			result    map[string]zcommon.CVE
			wasCached bool
			err       error
		}

		var outcomeA, outcomeB scanOutcome

		done := make(chan struct{})

		go func() {
			var wg sync.WaitGroup

			wg.Add(2)

			go func() {
				defer wg.Done()

				result, wasCached, err := scanner.scanIndex(context.Background(), "repo", digA.String())
				outcomeA = scanOutcome{result, wasCached, err}
			}()

			go func() {
				defer wg.Done()

				result, wasCached, err := scanner.scanIndex(context.Background(), "repo", digB.String())
				outcomeB = scanOutcome{result, wasCached, err}
			}()

			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent scans rooted at cyclically referencing indexes deadlocked")
		}

		So(outcomeA.err, ShouldBeNil)
		So(outcomeB.err, ShouldBeNil)
	})
}
