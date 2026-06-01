//go:build search

package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	cvecache "zotregistry.dev/zot/v2/pkg/extensions/search/cve/cache"
	"zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type fakeArtifactRunner struct {
	reportFn func(ctx context.Context, opts flag.Options, report trivyTypes.Report) error
}

func (f fakeArtifactRunner) ScanImage(ctx context.Context, opts flag.Options) (trivyTypes.Report, error) {
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

func generateTestImage(storeController storage.StoreController, imageName string) {
	repoName, tag := common.GetImageDirAndTag(imageName)

	image := CreateRandomImage()

	err := WriteImageToFileSystem(
		image, repoName, tag, storeController)
	So(err, ShouldBeNil)
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

		store := local.NewImageStore(rootDir, false, false, logger, monitoring.NewMetricsServer(false, logger), nil, nil, nil, nil)
		storeController := storage.StoreController{DefaultStore: store}

		scanner := Scanner{
			log:             logger,
			storeController: storeController,
			sbomOptions: sbomOptions{
				enabled:      true,
				reportFormat: trivyTypes.FormatSPDXJSON,
			},
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
			ImageOptions: flag.ImageOptions{Input: "repo:tag"},
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
		metrics := monitoring.NewMetricsServer(false, log)

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
		cveMap, err := scanner.ScanImage(ctx, img0)

		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image in substore
		cveMap, err = scanner.ScanImage(ctx, img1)
		So(err, ShouldBeNil)
		So(len(cveMap), ShouldEqual, 0)

		// Scanning image which does not exist
		cveMap, err = scanner.ScanImage(ctx, "a/test/image2:tag100")
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
		metrics := monitoring.NewMetricsServer(false, log)

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
		panic(err)
	}

	log := log.NewTestLogger()

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
		panic(err)
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
		panic(err)
	}

	// Continue with initializing the objects the scanner depends on
	metrics := monitoring.NewMetricsServer(false, log)

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
		metrics := monitoring.NewMetricsServer(false, log)

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
		storeController.DefaultStore = &imagestore.ImageStore{}

		metaDB := &boltdb.BoltDB{}
		log := log.NewTestLogger()

		Convey("Find index in cache", func() {
			scanner := Scanner{
				log:             log,
				metaDB:          metaDB,
				storeController: storeController,
				cache:           cvecache.NewCveCache(cacheSize, log),
			}

			scanner.cache.Add("digest", make(map[string]model.CVE))

			found, err := scanner.isIndexScannable("digest")
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
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
				log:             log,
				metaDB:          metaDB,
				storeController: storeController,
				cache:           cvecache.NewCveCache(cacheSize, log),
			}

			ok, err := scanner.isIndexScannable(multiarch.DigestStr())
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})
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

func TestStoreSBOMAsOCIArtifact(t *testing.T) {
	Convey("storeSBOMAsOCIArtifact stores SBOM once as OCI referrer", t, func() {
		rootDir := t.TempDir()

		logger := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, logger)
		defer metrics.Stop()
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
