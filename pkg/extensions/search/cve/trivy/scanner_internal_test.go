//go:build search
// +build search

package trivy

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	"zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/imagestore"
	"zotregistry.dev/zot/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

func generateTestImage(storeController storage.StoreController, imageName string) {
	repoName, tag := common.GetImageDirAndTag(imageName)

	image := CreateRandomImage()

	err := WriteImageToFileSystem(
		image, repoName, tag, storeController)
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

		firstStore := local.NewImageStore(firstRootDir, false, false, log, metrics, nil, nil)

		secondStore := local.NewImageStore(secondRootDir, false, false, log, metrics, nil, nil)

		thirdStore := local.NewImageStore(thirdRootDir, false, false, log, metrics, nil, nil)

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

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)

		// Create ImageStore
		store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil)

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

		// Download DB fails for missing DB url
		scanner := NewScanner(storeController, metaDB, "", "", log)

		ctx := context.Background()

		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		// Try to scan without the DB being downloaded
		opts := scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)
		So(err, ShouldWrap, zerr.ErrCVEDBNotFound)

		// Download DB fails for invalid Java DB
		scanner = NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db",
			"ghcr.io/project-zot/trivy-not-db", log)

		err = scanner.UpdateDB(ctx)
		So(err, ShouldNotBeNil)

		// Download DB passes for valid Trivy DB url, and missing Trivy Java DB url
		// Download DB is necessary since DB download on scan is disabled
		scanner = NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", log)

		// UpdateDB with good ctx
		err = scanner.UpdateDB(ctx)
		So(err, ShouldBeNil)

		// Scanning image with correct options
		opts = scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)

		// Scanning image with incorrect cache options
		// to trigger runner initialization errors
		opts.CacheOptions.CacheBackend = "redis://asdf!$%&!*)("
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)

		// Scanning image with invalid input to trigger a scanner error
		opts = scanner.getTrivyOptions("nilnonexisting_image:0.0.1")
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldNotBeNil)

		// Scanning image with incorrect report options
		// to trigger report filtering errors
		opts = scanner.getTrivyOptions(img)
		opts.ReportOptions.IgnorePolicy = "invalid file path"
		_, err = scanner.runTrivy(ctx, opts)
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

	store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil)

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
		store := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil)

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
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)

		// Scanning image containing a jar file
		img = "zot-cve-java-test:0.0.1"

		opts = scanner.getTrivyOptions(img)
		_, err = scanner.runTrivy(ctx, opts)
		So(err, ShouldBeNil)
	})
}

func TestIsIndexScanable(t *testing.T) {
	Convey("IsIndexScanable", t, func() {
		storeController := storage.StoreController{}
		storeController.DefaultStore = &imagestore.ImageStore{}

		metaDB := &boltdb.BoltDB{}
		log := log.NewLogger("debug", "")

		Convey("Find index in cache", func() {
			scanner := NewScanner(storeController, metaDB, "", "", log)

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
		log := log.NewLogger("debug", "")

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

			scanner := NewScanner(storeController, metaDB, "", "", log)
			ok, err := scanner.isIndexScannable(multiarch.DigestStr())
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})
	})
}

func TestGetCVEReference(t *testing.T) {
	Convey("getCVEReference", t, func() {
		ref := getCVEReference("primary", []string{})
		So(ref, ShouldResemble, "primary")

		ref = getCVEReference("", []string{"secondary"})
		So(ref, ShouldResemble, "secondary")

		ref = getCVEReference("", []string{""})
		So(ref, ShouldResemble, "")

		ref = getCVEReference("", []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-2650"})
		So(ref, ShouldResemble, "https://nvd.nist.gov/vuln/detail/CVE-2023-2650")
	})
}
