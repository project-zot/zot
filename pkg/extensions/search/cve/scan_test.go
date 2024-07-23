//go:build search
// +build search

package cveinfo_test

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	cveinfo "zotregistry.dev/zot/pkg/extensions/search/cve"
	cvecache "zotregistry.dev/zot/pkg/extensions/search/cve/cache"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var (
	ErrBadTest    = errors.New("there is a bug in the test")
	ErrFailedScan = errors.New("scan has failed intentionally")
)

func TestScanGeneratorWithMockedData(t *testing.T) { //nolint: gocyclo
	Convey("Test CVE scanning task scheduler with diverse mocked data", t, func() {
		repo1 := "repo1"
		repoIndex := "repoIndex"

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		logPath := logFile.Name()
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logPath)
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		cfg := config.New()
		cfg.Scheduler = &config.SchedulerConfig{NumWorkers: 3}
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(cfg, metrics, logger)

		params := boltdb.DBParameters{
			RootDir: t.TempDir(),
		}
		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		// Refactor Idea: We can use InitializeTestMetaDB

		// Create metadb data for scannable image with vulnerabilities
		image11 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2008, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "0.1.0", image11.AsImageMeta())
		So(err, ShouldBeNil)

		image12 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2009, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "1.0.0", image12.AsImageMeta())
		So(err, ShouldBeNil)

		image13 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2010, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "1.1.0", image13.AsImageMeta())
		So(err, ShouldBeNil)

		image14 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2011, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo1", "1.0.1", image14.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for scannable image with no vulnerabilities
		image61 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2016, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo6", "1.0.0", image61.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for image not supporting scanning
		image21 := CreateImageWith().Layers([]Layer{{
			MediaType: ispec.MediaTypeImageLayerNonDistributableGzip, //nolint:staticcheck
			Blob:      []byte{10, 10, 10},
			Digest:    godigest.FromBytes([]byte{10, 10, 10}),
		}}).ImageConfig(ispec.Image{Created: DateRef(2009, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo2", "1.0.0", image21.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for invalid images/negative tests
		img := CreateRandomImage()
		digest31 := img.Digest()

		err = metaDB.SetRepoReference(context.Background(), "repo3", "invalid-manifest", img.AsImageMeta())
		So(err, ShouldBeNil)

		image41 := CreateImageWith().DefaultLayers().
			CustomConfigBlob([]byte("invalid config blob"), ispec.MediaTypeImageConfig).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo4", "invalid-config", image41.AsImageMeta())
		So(err, ShouldBeNil)

		image15 := CreateRandomMultiarch()

		digest51 := image15.Digest()
		err = metaDB.SetRepoReference(context.Background(), "repo5", "nonexitent-manifests-for-multiarch",
			image15.AsImageMeta())
		So(err, ShouldBeNil)

		// Create metadb data for scannable image which errors during scan
		image71 := CreateImageWith().DefaultLayers().
			ImageConfig(ispec.Image{Created: DateRef(2000, 1, 1, 12, 0, 0, 0, time.UTC)}).Build()

		err = metaDB.SetRepoReference(context.Background(), "repo7", "1.0.0", image71.AsImageMeta())
		So(err, ShouldBeNil)

		// Create multiarch image with vulnerabilities
		multiarchImage := CreateRandomMultiarch()

		err = metaDB.SetRepoReference(context.Background(), repoIndex, multiarchImage.Images[0].DigestStr(),
			multiarchImage.Images[0].AsImageMeta())
		So(err, ShouldBeNil)
		err = metaDB.SetRepoReference(context.Background(), repoIndex, multiarchImage.Images[1].DigestStr(),
			multiarchImage.Images[1].AsImageMeta())
		So(err, ShouldBeNil)
		err = metaDB.SetRepoReference(context.Background(), repoIndex, multiarchImage.Images[2].DigestStr(),
			multiarchImage.Images[2].AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(context.Background(), repoIndex, "tagIndex", multiarchImage.AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.SetRepoMeta("repo-with-bad-tag-digest", mTypes.RepoMeta{
			Name: "repo-with-bad-tag-digest",
			Tags: map[mTypes.Tag]mTypes.Descriptor{
				"tag":            {MediaType: ispec.MediaTypeImageManifest, Digest: godigest.FromString("1").String()},
				"tag-multi-arch": {MediaType: ispec.MediaTypeImageIndex, Digest: godigest.FromString("2").String()},
			},
		})
		So(err, ShouldBeNil)

		// Keep a record of all the image references / digest pairings
		// This is normally done in MetaDB, but we want to verify
		// the whole flow, including MetaDB
		imageMap := map[string]string{}

		image11Digest := image11.ManifestDescriptor.Digest.String()
		image11Name := "repo1:0.1.0"
		imageMap[image11Name] = image11Digest
		image12Digest := image12.ManifestDescriptor.Digest.String()
		image12Name := "repo1:1.0.0"
		imageMap[image12Name] = image12Digest
		image13Digest := image13.ManifestDescriptor.Digest.String()
		image13Name := "repo1:1.1.0"
		imageMap[image13Name] = image13Digest
		image14Digest := image14.ManifestDescriptor.Digest.String()
		image14Name := "repo1:1.0.1"
		imageMap[image14Name] = image14Digest
		image21Digest := image21.ManifestDescriptor.Digest.String()
		image21Name := "repo2:1.0.0"
		imageMap[image21Name] = image21Digest
		image31Name := "repo3:invalid-manifest"
		imageMap[image31Name] = digest31.String()
		image41Digest := image41.ManifestDescriptor.Digest.String()
		image41Name := "repo4:invalid-config"
		imageMap[image41Name] = image41Digest
		image51Name := "repo5:nonexitent-manifest-for-multiarch"
		imageMap[image51Name] = digest51.String()
		image61Digest := image61.ManifestDescriptor.Digest.String()
		image61Name := "repo6:1.0.0"
		imageMap[image61Name] = image61Digest
		image71Digest := image71.ManifestDescriptor.Digest.String()
		image71Name := "repo7:1.0.0"
		imageMap[image71Name] = image71Digest
		indexDigest := multiarchImage.IndexDescriptor.Digest.String()
		indexName := "repoIndex:tagIndex"
		imageMap[indexName] = indexDigest
		indexM1Digest := multiarchImage.Images[0].ManifestDescriptor.Digest.String()
		indexM1Name := "repoIndex@" + indexM1Digest
		imageMap[indexM1Name] = indexM1Digest
		indexM2Digest := multiarchImage.Images[1].ManifestDescriptor.Digest.String()
		indexM2Name := "repoIndex@" + indexM2Digest
		imageMap[indexM2Name] = indexM2Digest
		indexM3Digest := multiarchImage.Images[2].ManifestDescriptor.Digest.String()
		indexM3Name := "repoIndex@" + indexM3Digest
		imageMap[indexM3Name] = indexM3Digest

		// Initialize a test CVE cache
		cache := cvecache.NewCveCache(20, logger)

		// MetaDB loaded with initial data, now mock the scanner
		// Setup test CVE data in mock scanner
		scanner := mocks.CveScannerMock{
			ScanImageFn: func(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
				result := cache.Get(image)
				// Will not match sending the repo:tag as a parameter, but we don't care
				if result != nil {
					return result, nil
				}

				repo, ref, isTag := zcommon.GetImageDirAndReference(image)
				if isTag {
					foundRef, ok := imageMap[image]
					if !ok {
						return nil, ErrBadTest
					}
					ref = foundRef
				}

				// Images in chronological order
				if repo == repo1 && ref == image11Digest {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				if repo == repo1 && zcommon.Contains([]string{image12Digest, image21Digest}, ref) {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
						"CVE2": {
							ID:          "CVE2",
							Severity:    "HIGH",
							Title:       "Title CVE2",
							Description: "Description CVE2",
						},
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				if repo == repo1 && ref == image13Digest {
					result := map[string]cvemodel.CVE{
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				// As a minor release on 1.0.0 banch
				// does not include all fixes published in 1.1.0
				if repo == repo1 && ref == image14Digest {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
						"CVE3": {
							ID:          "CVE3",
							Severity:    "LOW",
							Title:       "Title CVE3",
							Description: "Description CVE3",
						},
					}

					cache.Add(ref, result)

					return result, nil
				}

				// Unexpected error while scanning
				if repo == "repo7" {
					return map[string]cvemodel.CVE{}, ErrFailedScan
				}

				if (repo == repoIndex && ref == indexDigest) ||
					(repo == repoIndex && ref == indexM1Digest) {
					result := map[string]cvemodel.CVE{
						"CVE1": {
							ID:          "CVE1",
							Severity:    "MEDIUM",
							Title:       "Title CVE1",
							Description: "Description CVE1",
						},
					}

					// Simulate scanning an index results in scanning its manifests
					if ref == indexDigest {
						cache.Add(indexM1Digest, result)
						cache.Add(indexM2Digest, map[string]cvemodel.CVE{})
						cache.Add(indexM3Digest, map[string]cvemodel.CVE{})
					}

					cache.Add(ref, result)

					return result, nil
				}

				// By default the image has no vulnerabilities
				result = map[string]cvemodel.CVE{}
				cache.Add(ref, result)

				return result, nil
			},
			IsImageFormatScannableFn: func(repo string, reference string) (bool, error) {
				if repo == repoIndex {
					return true, nil
				}

				// Almost same logic compared to actual Trivy specific implementation
				imageDir, inputTag := repo, reference

				repoMeta, err := metaDB.GetRepoMeta(context.Background(), imageDir)
				if err != nil {
					return false, err
				}

				manifestDigestStr := reference

				if zcommon.IsTag(reference) {
					var ok bool

					descriptor, ok := repoMeta.Tags[inputTag]
					if !ok {
						return false, zerr.ErrTagMetaNotFound
					}

					manifestDigestStr = descriptor.Digest
				}

				manifestDigest, err := godigest.Parse(manifestDigestStr)
				if err != nil {
					return false, err
				}

				manifestData, err := metaDB.GetImageMeta(manifestDigest)
				if err != nil {
					return false, err
				}

				for _, imageLayer := range manifestData.Manifests[0].Manifest.Layers {
					switch imageLayer.MediaType {
					case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):

						return true, nil
					default:

						return false, zerr.ErrScanNotSupported
					}
				}

				return false, nil
			},
			IsImageMediaScannableFn: func(repo, digest, mediaType string) (bool, error) {
				if repo == "repo2" {
					if digest == image21Digest {
						return false, nil
					}
				}

				return true, nil
			},
			IsResultCachedFn: func(digest string) bool {
				return cache.Contains(digest)
			},
			UpdateDBFn: func(ctx context.Context) error {
				cache.Purge()

				return nil
			},
		}

		// Purge scan, it should not be needed
		So(scanner.UpdateDB(context.Background()), ShouldBeNil)

		// Verify none of the entries are cached to begin with
		t.Log("verify cache is initially empty")

		for image, digestStr := range imageMap {
			t.Log("expecting " + image + " " + digestStr + " to be absent from cache")
			So(scanner.IsResultCached(digestStr), ShouldBeFalse)
		}

		// Start the generator
		generator := cveinfo.NewScanTaskGenerator(metaDB, scanner, logger)

		sch.SubmitGenerator(generator, 10*time.Second, scheduler.MediumPriority)

		sch.RunScheduler()

		defer sch.Shutdown()

		// Make sure the scanner generator has completed despite errors
		found, err := test.ReadLogFileAndSearchString(logPath,
			"finished scanning available images during scheduled cve scan", 40*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		t.Log("verify cache is up to date after scanner generator ran")

		// Verify all of the entries are cached
		for image, digestStr := range imageMap {
			repo, _, _ := zcommon.GetImageDirAndReference(image)

			ok, err := scanner.IsImageFormatScannable(repo, digestStr)
			if ok && err == nil && repo != "repo7" {
				t.Log("expecting " + image + " " + digestStr + " to be present in cache")
				So(scanner.IsResultCached(digestStr), ShouldBeTrue)
			} else {
				// We don't cache results for un-scannable manifests
				t.Log("expecting " + image + " " + digestStr + " to be absent from cache")
				So(scanner.IsResultCached(digestStr), ShouldBeFalse)
			}
		}

		found, err = test.ReadLogFileAndSearchString(logPath,
			"failed to obtain repo metadata during scheduled cve scan", 20*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// Make sure the scanner generator is catching the scanning error for repo7
		found, err = test.ReadLogFileAndSearchString(logPath,
			"failed to perform scheduled cve scan for image", 20*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		// Make sure the scanner generator is triggered at least twice
		found, err = test.ReadLogFileAndCountStringOccurence(logPath,
			"finished scanning available images during scheduled cve scan", 30*time.Second, 2)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)
	})
}

func TestScanGeneratorWithRealData(t *testing.T) {
	Convey("Test CVE scanning task scheduler real data", t, func() {
		rootDir := t.TempDir()

		logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
		logPath := logFile.Name()
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logPath)
		writers := io.MultiWriter(os.Stdout, logFile)
		logger.Logger = logger.Output(writers)

		cfg := config.New()
		cfg.Scheduler = &config.SchedulerConfig{NumWorkers: 3}

		boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: rootDir})
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, logger)
		So(err, ShouldBeNil)

		metrics := monitoring.NewMetricsServer(true, logger)
		imageStore := local.NewImageStore(rootDir, false, false,
			logger, metrics, nil, nil)
		storeController := storage.StoreController{DefaultStore: imageStore}

		image := CreateRandomVulnerableImage()

		err = WriteImageToFileSystem(image, "zot-test", "0.0.1", storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, logger)
		So(err, ShouldBeNil)

		scanner := cveinfo.NewScanner(storeController, metaDB, "ghcr.io/project-zot/trivy-db", "", logger)
		err = scanner.UpdateDB(context.Background())
		So(err, ShouldBeNil)

		So(scanner.IsResultCached(image.DigestStr()), ShouldBeFalse)

		sch := scheduler.NewScheduler(cfg, metrics, logger)

		generator := cveinfo.NewScanTaskGenerator(metaDB, scanner, logger)

		// Start the generator
		sch.SubmitGenerator(generator, 120*time.Second, scheduler.MediumPriority)

		sch.RunScheduler()

		defer sch.Shutdown()

		// Make sure the scanner generator has completed
		found, err := test.ReadLogFileAndSearchString(logPath,
			"finished scanning available images during scheduled cve scan", 120*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logPath,
			image.ManifestDescriptor.Digest.String(), 120*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(logPath,
			"scheduled cve scan completed successfully for image", 120*time.Second)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		So(scanner.IsResultCached(image.DigestStr()), ShouldBeTrue)

		cveMap, err := scanner.ScanImage(context.Background(), "zot-test:0.0.1")
		So(err, ShouldBeNil)
		t.Logf("cveMap: %v", cveMap)
		// As of September 22 2023 there are 5 CVEs:
		// CVE-2023-1255, CVE-2023-2650, CVE-2023-2975, CVE-2023-3817, CVE-2023-3446
		// There may be more discovered in the future
		So(len(cveMap), ShouldBeGreaterThanOrEqualTo, 5)
		So(cveMap, ShouldContainKey, "CVE-2023-1255")
		So(cveMap, ShouldContainKey, "CVE-2023-2650")
		So(cveMap, ShouldContainKey, "CVE-2023-2975")
		So(cveMap, ShouldContainKey, "CVE-2023-3817")
		So(cveMap, ShouldContainKey, "CVE-2023-3446")

		cveInfo := cveinfo.NewCVEInfo(scanner, metaDB, logger)

		// Based on cache population only, no extra scanning
		cveSummary, err := cveInfo.GetCVESummaryForImageMedia(context.Background(), "zot-test", image.DigestStr(),
			image.ManifestDescriptor.MediaType)
		So(err, ShouldBeNil)
		So(cveSummary.Count, ShouldBeGreaterThanOrEqualTo, 5)
		// As of September 22 the max severity is MEDIUM, but new CVEs could appear in the future
		So([]string{"MEDIUM", "HIGH", "CRITICAL"}, ShouldContain, cveSummary.MaxSeverity)
	})
}
