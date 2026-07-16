package gc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/dynamodb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/azurite"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const (
	region        = "us-east-2"
	s3TestName    = "S3APIs"
	localTestName = "LocalAPIs"
	azureTestName = "AzureAPIs"
)

//nolint:gochecknoglobals
var testCases = []struct {
	testCaseName string
	storageType  string
}{
	{
		testCaseName: s3TestName,
		storageType:  storageConstants.S3StorageDriverName,
	},
	{
		testCaseName: localTestName,
		storageType:  storageConstants.LocalStorageDriverName,
	},
	{
		testCaseName: azureTestName,
		storageType:  storageConstants.AzureStorageDriverName,
	},
}

func newTestMetricsServer(t *testing.T, log zlog.Logger) monitoring.MetricServer {
	t.Helper()

	metrics := monitoring.NewMetricsServer(false, log)
	t.Cleanup(metrics.Stop)

	return metrics
}

// The backend subtests run in parallel, but the top-level test stays sequential on
// purpose: parallelising it too would run this and the other retention test's backends
// concurrently, multiplying the load on the runner and the storage emulators.
//
//nolint:tparallel
func TestGarbageCollectAndRetentionMetaDB(t *testing.T) {
	log := zlog.NewTestLogger()
	audit := zlog.NewAuditLogger("debug", "/dev/null")

	metrics := newTestMetricsServer(t, log)

	trueVal := true

	for _, testcase := range testCases {
		t.Run(testcase.testCaseName, func(t *testing.T) {
			// Run the storage backends concurrently. Each subtest builds its own store,
			// cache and metaDB (unique prefixes / temp dirs), so the S3, filesystem and
			// Azure passes are independent and need not run in series.
			t.Parallel()

			var imgStore storageTypes.ImageStore

			var metaDB mTypes.MetaDB
			compat := []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}

			switch testcase.storageType {
			case storageConstants.S3StorageDriverName:
				tskip.SkipDynamo(t)
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				rootDir := path.Join("/oci-repo-test", uuid.String())
				cacheDir := t.TempDir()

				bucket := "zot-storage-test"

				storageDriverParams := map[string]any{
					"rootDir":        rootDir,
					"name":           "s3",
					"region":         region,
					"bucket":         bucket,
					"regionendpoint": os.Getenv("S3MOCK_ENDPOINT"),
					"accesskey":      "minioadmin",
					"secretkey":      "minioadmin",
					"secure":         false,
					"skipverify":     false,
					"forcepathstyle": true,
				}

				storeName := fmt.Sprintf("%v", storageDriverParams["name"])

				store, err := factory.Create(context.Background(), storeName, storageDriverParams)
				if err != nil {
					panic(err)
				}

				defer store.Delete(context.Background(), rootDir) //nolint: errcheck

				// create bucket if it doesn't exists
				_, err = resty.R().Put("http://" + os.Getenv("S3MOCK_ENDPOINT") + "/" + bucket)
				if err != nil {
					panic(err)
				}

				uuid, err = guuid.NewV4()
				if err != nil {
					panic(err)
				}

				params := dynamodb.DBDriverParameters{ //nolint:contextcheck
					Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
					Region:                 region,
					RepoMetaTablename:      "repo" + uuid.String(),
					RepoBlobsInfoTablename: "repoblobsinfo" + uuid.String(),
					ImageMetaTablename:     "imagemeta" + uuid.String(),
					UserDataTablename:      "user" + uuid.String(),
					APIKeyTablename:        "apiKey" + uuid.String(),
					VersionTablename:       "version" + uuid.String(),
				}

				client, err := dynamodb.GetDynamoClient(params)
				if err != nil {
					panic(err)
				}

				metaDB, err = dynamodb.New(client, params, log)
				if err != nil {
					panic(err)
				}

				imgStore = s3.NewImageStore(rootDir, cacheDir, true, false, log, metrics, nil, store, nil, compat, nil)
			case storageConstants.AzureStorageDriverName:
				tskip.SkipAzure(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				rootDir := path.Join("/oci-repo-test", uuid.String())
				cacheDir := t.TempDir()

				driverParams := azurite.DriverParams(rootDir)
				storage.NormalizeRootDirectory(storageConstants.AzureStorageDriverName, driverParams)

				store, err := factory.Create(context.Background(), storageConstants.AzureStorageDriverName, driverParams)
				if err != nil {
					panic(err)
				}

				if err := azurite.EnsureContainer(); err != nil {
					panic(err)
				}

				defer store.Delete(context.Background(), "/") //nolint: errcheck

				// init metaDB on a local boltdb (independent of the blob store)
				boltParams := boltdb.DBParameters{
					RootDir: cacheDir,
				}

				boltDriver, err := boltdb.GetBoltDriver(boltParams)
				if err != nil {
					panic(err)
				}

				metaDB, err = boltdb.New(boltDriver, log)
				if err != nil {
					panic(err)
				}

				imgStore = azure.NewImageStore(storage.RootDir(storageConstants.AzureStorageDriverName, driverParams),
					cacheDir, true, false, log, metrics, nil, store, nil, compat, nil)
			default:
				// Create temporary directory
				rootDir := t.TempDir()

				// Create ImageStore
				imgStore = local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, compat, nil)

				// init metaDB
				params := boltdb.DBParameters{
					RootDir: rootDir,
				}

				boltDriver, err := boltdb.GetBoltDriver(params)
				if err != nil {
					panic(err)
				}

				metaDB, err = boltdb.New(boltDriver, log)
				if err != nil {
					panic(err)
				}
			}

			storeController := storage.StoreController{}
			storeController.DefaultStore = imgStore

			ctx := context.Background()

			Convey("setup gc images", t, func() {
				// for gc testing
				// basic images
				gcTest1 := CreateRandomImage()
				err := WriteImageToFileSystem(gcTest1, "gc-test1", "0.0.1", storeController)
				So(err, ShouldBeNil)

				// also add same image(same digest) with another tag
				err = WriteImageToFileSystem(gcTest1, "gc-test1", "0.0.2", storeController)
				So(err, ShouldBeNil)

				gcTest2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcTest2, "gc-test2", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcTest3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcTest3, "gc-test3", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcTest4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcTest4, "gc-test4", "0.0.1", storeController)
				So(err, ShouldBeNil)

				// referrers
				ref1 := CreateRandomImageWith().Subject(gcTest1.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref1, "gc-test1", ref1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref2 := CreateRandomImageWith().Subject(gcTest2.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref2, "gc-test2", ref2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref3 := CreateRandomImageWith().Subject(gcTest3.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref3, "gc-test3", ref3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref4 := CreateMultiarchWith().RandomImages(3).Subject(gcTest4.DescriptorRef()).Build()
				err = WriteMultiArchImageToFileSystem(ref4, "gc-test4", ref4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// referrers pointing to referrers
				refOfRef1 := CreateRandomImageWith().Subject(ref1.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef1, "gc-test1", refOfRef1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef2 := CreateRandomImageWith().Subject(ref2.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef2, "gc-test2", refOfRef2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef3 := CreateRandomImageWith().Subject(ref3.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef3, "gc-test3", refOfRef3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef4 := CreateMultiarchWith().RandomImages(3).Subject(ref4.DescriptorRef()).Build()
				err = WriteMultiArchImageToFileSystem(refOfRef4, "gc-test4", refOfRef4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// untagged images
				gcUntagged1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged1, "gc-test1", gcUntagged1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged2, "gc-test2", gcUntagged2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged3, "gc-test3", gcUntagged3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcUntagged4, "gc-test4", gcUntagged4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// docker images
				gcDocker1 := CreateRandomImage().AsDockerImage()
				err = WriteImageToFileSystem(gcDocker1, "gc-docker1", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcDocker2 := CreateRandomMultiarch().AsDockerImage()
				err = WriteMultiArchImageToFileSystem(gcDocker2, "gc-docker2", "0.0.1", storeController)
				So(err, ShouldBeNil)

				// for image retention testing
				// old images
				gcOld1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld1, "retention", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcOld2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld2, "retention", "0.0.2", storeController)
				So(err, ShouldBeNil)

				gcOld3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld3, "retention", "0.0.3", storeController)
				So(err, ShouldBeNil)

				gcOld4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcOld4, "retention", "0.0.7", storeController)
				So(err, ShouldBeNil)

				// new images
				gcNew1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew1, "retention", "0.0.4", storeController)
				So(err, ShouldBeNil)

				gcNew2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew2, "retention", "0.0.5", storeController)
				So(err, ShouldBeNil)

				gcNew3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew3, "retention", "0.0.6", storeController)
				So(err, ShouldBeNil)

				gcNew4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcNew4, "retention", "0.0.8", storeController)
				So(err, ShouldBeNil)

				err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
				So(err, ShouldBeNil)

				retentionMeta, err := metaDB.GetRepoMeta(ctx, "retention")
				So(err, ShouldBeNil)

				// update timestamps for image retention
				gcOld1Stats := retentionMeta.Statistics[gcOld1.DigestStr()]
				gcOld1Stats.PushTimestamp = time.Now().Add(-10 * 24 * time.Hour)
				gcOld1Stats.LastPullTimestamp = time.Now().Add(-10 * 24 * time.Hour)

				gcOld2Stats := retentionMeta.Statistics[gcOld2.DigestStr()]
				gcOld2Stats.PushTimestamp = time.Now().Add(-11 * 24 * time.Hour)
				gcOld2Stats.LastPullTimestamp = time.Now().Add(-11 * 24 * time.Hour)

				gcOld3Stats := retentionMeta.Statistics[gcOld3.DigestStr()]
				gcOld3Stats.PushTimestamp = time.Now().Add(-12 * 24 * time.Hour)
				gcOld3Stats.LastPullTimestamp = time.Now().Add(-12 * 24 * time.Hour)

				gcOld4Stats := retentionMeta.Statistics[gcOld4.DigestStr()]
				gcOld4Stats.PushTimestamp = time.Now().Add(-13 * 24 * time.Hour)
				gcOld4Stats.LastPullTimestamp = time.Now().Add(-13 * 24 * time.Hour)

				gcNew1Stats := retentionMeta.Statistics[gcNew1.DigestStr()]
				gcNew1Stats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
				gcNew1Stats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)

				gcNew2Stats := retentionMeta.Statistics[gcNew2.DigestStr()]
				gcNew2Stats.PushTimestamp = time.Now().Add(-2 * 24 * time.Hour)
				gcNew2Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)

				gcNew3Stats := retentionMeta.Statistics[gcNew3.DigestStr()]
				gcNew3Stats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
				gcNew3Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)

				gcNew4Stats := retentionMeta.Statistics[gcNew4.DigestStr()]
				gcNew4Stats.PushTimestamp = time.Now().Add(-4 * 24 * time.Hour)
				gcNew4Stats.LastPullTimestamp = time.Now().Add(-4 * 24 * time.Hour)

				retentionMeta.Statistics[gcOld1.DigestStr()] = gcOld1Stats
				retentionMeta.Statistics[gcOld2.DigestStr()] = gcOld2Stats
				retentionMeta.Statistics[gcOld3.DigestStr()] = gcOld3Stats
				retentionMeta.Statistics[gcOld4.DigestStr()] = gcOld4Stats

				retentionMeta.Statistics[gcNew1.DigestStr()] = gcNew1Stats
				retentionMeta.Statistics[gcNew2.DigestStr()] = gcNew2Stats
				retentionMeta.Statistics[gcNew3.DigestStr()] = gcNew3Stats
				retentionMeta.Statistics[gcNew4.DigestStr()] = gcNew4Stats

				// update repo meta
				err = metaDB.SetRepoMeta("retention", retentionMeta)
				So(err, ShouldBeNil)

				Convey("should not gc anything", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test4")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-docker1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-docker2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcTest2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcUntagged2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", ref2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", refOfRef2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcTest3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcUntagged3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", ref3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", refOfRef3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcTest4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcUntagged4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", ref4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", refOfRef4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker1", gcDocker1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker2", gcDocker2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("gc untagged manifests", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags:        []config.KeepTagsPolicy{},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test4")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-docker1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-docker2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcTest2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcUntagged2.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", ref2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", refOfRef2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcTest3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcUntagged3.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", ref3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", refOfRef3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcTest4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcUntagged4.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", ref4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", refOfRef4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker1", gcDocker1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker2", gcDocker2.DigestStr())
					So(err, ShouldBeNil)
				})

				Convey("gc all tags, untagged, and afterwards referrers", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					// although we have two tags both should be deleted
					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldNotBeNil)

					// now repo should get gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldNotContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "gc-docker1")
					So(repos, ShouldContain, "gc-docker2")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc all tags for docker repo", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-docker*"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-docker1")
					So(err, ShouldBeNil)
					err = gc.CleanRepo(ctx, "gc-docker2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker1", gcDocker1.DigestStr())
					So(err, ShouldNotBeNil)
					_, _, _, err = imgStore.GetImageManifest("gc-docker2", gcDocker2.DigestStr())
					So(err, ShouldNotBeNil)

					// now repo should get gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldNotContain, "gc-docker1")
					So(repos, ShouldNotContain, "gc-docker2")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc all tags, untagged, and afterwards referrers using GetNextRepository()", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1", "gc-test3"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					processedRepos := make(map[string]struct{})
					expectedRepos := []string{"gc-docker1", "gc-docker2", "gc-test1", "gc-test2", "gc-test3", "gc-test4", "retention"}

					for i := range 2 * len(expectedRepos) {
						t.Logf("index %d, processed repos %v", i, processedRepos)

						// we need to check if GetNextRepository returns each repository just once, and empty string afterwards
						repo, err := imgStore.GetNextRepository(processedRepos)
						t.Logf("index %d, repo '%s'", i, repo)
						So(err, ShouldBeNil)

						if i >= len(expectedRepos) {
							So(repo, ShouldEqual, "")

							continue
						} else {
							So(repo, ShouldEqual, expectedRepos[i])
						}

						processedRepos[repo] = struct{}{}

						// run cleanRepo, this should not impact the list of calls necessary for
						// GetNextRepository to iterate through every repo
						err = gc.CleanRepo(ctx, repo)
						So(err, ShouldBeNil)
					}

					// verify one more time the returned values
					So(len(processedRepos), ShouldEqual, len(expectedRepos))

					for _, repo := range expectedRepos {
						So(processedRepos, ShouldContainKey, repo)
					}

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					// now repos should get gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldNotContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldNotContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "gc-docker1")
					So(repos, ShouldContain, "gc-docker2")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc with dry-run all tags, untagged, and afterwards referrers", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay:  1 * time.Millisecond,
							DryRun: true,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					// now repo should not be gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "gc-docker1")
					So(repos, ShouldContain, "gc-docker2")
					So(repos, ShouldContain, "retention")

					tags, err := imgStore.GetImageTags("gc-test1")
					So(err, ShouldBeNil)
					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldContain, "0.0.2")
				})

				Convey("all tags matches for retention", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.*"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain all tags if keeptags is not specified", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-docker2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain new tags", func() {
					sevenDays := 7 * 24 * time.Hour

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns:     []string{".*"},
											PulledWithin: &sevenDays,
											PushedWithin: &sevenDays,
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)

					So(tags, ShouldContain, "0.0.4")
					So(tags, ShouldContain, "0.0.5")
					So(tags, ShouldContain, "0.0.6")
					So(tags, ShouldContain, "0.0.8")

					So(tags, ShouldNotContain, "0.0.1")
					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.7")
				})

				Convey("retain 3 most recently pushed images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns:                []string{".*"},
											MostRecentlyPushedCount: 3,
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)

					So(tags, ShouldContain, "0.0.4")
					So(tags, ShouldContain, "0.0.5")
					So(tags, ShouldContain, "0.0.6")

					So(tags, ShouldNotContain, "0.0.1")
					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
				})

				Convey("retain 3 most recently pulled images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns:                []string{".*"},
											MostRecentlyPulledCount: 3,
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)

					So(tags, ShouldContain, "0.0.4")
					So(tags, ShouldContain, "0.0.5")
					So(tags, ShouldContain, "0.0.6")

					So(tags, ShouldNotContain, "0.0.1")
					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
				})

				Convey("retain 3 most recently pulled OR 4 most recently pushed images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns:                []string{".*"},
											MostRecentlyPulledCount: 3,
											MostRecentlyPushedCount: 4,
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)

					So(tags, ShouldContain, "0.0.4")
					So(tags, ShouldContain, "0.0.5")
					So(tags, ShouldContain, "0.0.6")
					So(tags, ShouldContain, "0.0.8")

					So(tags, ShouldNotContain, "0.0.1")
					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.7")
				})

				Convey("test if first match rule logic works", func() {
					twoDays := 2 * 24 * time.Hour
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.1"},
										},
										{
											Patterns: []string{"0.0.2"},
										},
										{
											Patterns:     []string{".*"},
											PulledWithin: &twoDays,
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)
					t.Log(tags)
					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldContain, "0.0.2")
					So(tags, ShouldContain, "0.0.4")

					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.5")
					So(tags, ShouldNotContain, "0.0.6")
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
				})

				Convey("gc - do not match any repo", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"no-match"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-docker1")
					So(repos, ShouldContain, "gc-docker2")
					So(repos, ShouldContain, "retention")
				})

				Convey("remove one tag because it didn't match, preserve tags without statistics in metaDB", func() {
					// add new tag in retention repo which can not be found in metaDB, should be always retained
					err = WriteImageToFileSystem(CreateRandomImage(), "retention", "0.0.9", storeController)
					So(err, ShouldBeNil)

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.[1-5]", "0.0.7"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.9")
					So(err, ShouldBeNil)
				})

				Convey("gc with context done", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.*"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					ctx, cancel := context.WithCancel(ctx)
					cancel()

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldNotBeNil)
				})

				Convey("should gc only stale blob uploads", func() {
					repoName := "gc-test1"

					// Drive staleness through the GC delay rather than wall-clock time: a long
					// delay keeps a recent upload, a zero delay treats it as stale. This keeps the
					// test deterministic regardless of how long the backend takes to respond.
					newGC := func(delay time.Duration) gc.GarbageCollect {
						return gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
							Delay: delay,
							ImageRetention: config.ImageRetention{
								Delay: storageConstants.DefaultGCDelay,
								Policies: []config.RetentionPolicy{
									{
										Repositories:    []string{"**"},
										DeleteReferrers: true,
										DeleteUntagged:  &trueVal,
										KeepTags: []config.KeepTagsPolicy{
											{},
										},
									},
								},
							},
						}, audit, log, metrics)
					}

					blobUploadID, err := imgStore.NewBlobUpload(context.Background(), repoName)
					So(err, ShouldBeNil)

					content := []byte("test-data3")
					buf := bytes.NewBuffer(content)
					_, err = imgStore.PutBlobChunkStreamed(context.Background(), repoName, blobUploadID, buf)
					So(err, ShouldBeNil)

					// Blob upload should be there
					uploads, err := imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err := imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					// A long GC delay keeps the recent upload.
					err = newGC(1*time.Hour).CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob upload is recent it should still be there
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					// A zero GC delay treats the upload as stale, so it is collected.
					err = newGC(0).CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob uploads should be GCed
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)
					So(uploads, ShouldBeEmpty)

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)
					So(err, ShouldNotBeNil)
					So(isPresent, ShouldBeFalse)
				})
			})
		})
	}
}

func TestGarbageCollectDeletion(t *testing.T) {
	Convey("setup store", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")

		metrics := newTestMetricsServer(t, log)

		trueVal := true
		falseVal := false

		// Create temporary directory
		rootDir := t.TempDir()

		// Create ImageStore
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		// init metaDB
		params := boltdb.DBParameters{
			RootDir: rootDir,
		}

		boltDriver, err := boltdb.GetBoltDriver(params)
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()

		repoName := "multiarch"
		blobsDir := path.Join(rootDir, repoName, "blobs")

		Convey("Create test data", func() {
			image1 := CreateRandomImage()
			image2 := CreateRandomImage()
			image3 := CreateRandomImage()
			bottomIndex1 := CreateMultiarchWith().Images([]Image{image1, image2}).Build()
			bottomIndex2 := CreateMultiarchWith().Images([]Image{image3}).Build()

			err = WriteImageToFileSystem(image2, repoName, "manifest2", storeController)
			So(err, ShouldBeNil)

			err = WriteMultiArchImageToFileSystem(bottomIndex1, repoName, bottomIndex1.Digest().String(), storeController)
			So(err, ShouldBeNil)

			err = WriteMultiArchImageToFileSystem(bottomIndex2, repoName, "bottomIndex2", storeController)
			So(err, ShouldBeNil)

			topIndex := ispec.Index{
				Versioned: specs.Versioned{SchemaVersion: 2},
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						Digest:    bottomIndex1.IndexDescriptor.Digest,
						Size:      bottomIndex1.IndexDescriptor.Size,
						MediaType: ispec.MediaTypeImageIndex,
					},
					{
						Digest:    bottomIndex2.IndexDescriptor.Digest,
						Size:      bottomIndex2.IndexDescriptor.Size,
						MediaType: ispec.MediaTypeImageIndex,
					},
				},
			}

			topIndexBlob, err := json.Marshal(topIndex)
			So(err, ShouldBeNil)

			rootIndexDigest, _, err := imgStore.PutImageManifest(context.Background(),
				repoName, "topindex", ispec.MediaTypeImageIndex, topIndexBlob, nil)
			So(err, ShouldBeNil)

			bottomIndex1Digest := bottomIndex1.IndexDescriptor.Digest
			bottomIndex2Digest := bottomIndex2.IndexDescriptor.Digest
			manifest1Digest := image1.Digest()
			manifest2Digest := image2.Digest()
			manifest3Digest := image3.Digest()

			err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
			So(err, ShouldBeNil)

			Convey("gc untagged manifests should not do anything, as all images refer to one another", func() {
				gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
					Delay: 1 * time.Millisecond,
					ImageRetention: config.ImageRetention{
						Delay: 1 * time.Millisecond,
						Policies: []config.RetentionPolicy{
							{
								Repositories:    []string{"**"},
								DeleteReferrers: true,
								DeleteUntagged:  &trueVal,
								KeepTags:        []config.KeepTagsPolicy{},
							},
						},
					},
				}, audit, log, metrics)

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldBeNil)

				// All indexes and manifests refer to one another, so none should be missing
				tags, err := readTagsFromStorage(rootDir, repoName, manifest1Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest1Digest.Algorithm().String(), manifest1Digest.Encoded()))
				So(err, ShouldBeNil)

				tags, err = readTagsFromStorage(rootDir, repoName, manifest2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "manifest2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest2Digest.Algorithm().String(), manifest2Digest.Encoded()))
				So(err, ShouldBeNil)

				tags, err = readTagsFromStorage(rootDir, repoName, manifest3Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest3Digest.Algorithm().String(), manifest3Digest.Encoded()))
				So(err, ShouldBeNil)

				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex1Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex1Digest.Algorithm().String(), bottomIndex1Digest.Encoded()))
				So(err, ShouldBeNil)

				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "bottomIndex2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex2Digest.Algorithm().String(), bottomIndex2Digest.Encoded()))
				So(err, ShouldBeNil)

				tags, err = readTagsFromStorage(rootDir, repoName, rootIndexDigest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "topindex")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, rootIndexDigest.Algorithm().String(), rootIndexDigest.Encoded()))
				So(err, ShouldBeNil)
			})

			Convey("gc untagged manifests after deleting the tag of the top index", func() {
				gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
					Delay: 1 * time.Millisecond,
					ImageRetention: config.ImageRetention{
						Delay: 1 * time.Millisecond,
						Policies: []config.RetentionPolicy{
							{
								Repositories:    []string{"**"},
								DeleteReferrers: true,
								DeleteUntagged:  &trueVal,
								KeepTags:        []config.KeepTagsPolicy{},
							},
						},
					},
				}, audit, log, metrics)

				err = deleteTagInStorage(rootDir, repoName, "topindex")

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldBeNil)

				// manifest1, bottomIndex1 and topIndex are untagged, so manifest1 should be deleted
				tags, err := readTagsFromStorage(rootDir, repoName, manifest1Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, manifest1Digest.Algorithm().String(), manifest1Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// manifest2 is has a tag, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, manifest2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "manifest2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest2Digest.Algorithm().String(), manifest2Digest.Encoded()))
				So(err, ShouldBeNil)

				// manifest3 is referenced by tagged bottomIndex2, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, manifest3Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest3Digest.Algorithm().String(), manifest3Digest.Encoded()))
				So(err, ShouldBeNil)

				// bottomIndex1 and topIndex are untagged, so bottomIndex1 should be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex1Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex1Digest.Algorithm().String(), bottomIndex1Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// bottomIndex2 is has a tag, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "bottomIndex2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex2Digest.Algorithm().String(), bottomIndex2Digest.Encoded()))
				So(err, ShouldBeNil)

				// topIndex is untagged, so it should be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, rootIndexDigest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, rootIndexDigest.Algorithm().String(), rootIndexDigest.Encoded()))
				So(err, ShouldNotBeNil)
			})

			Convey("do not gc untagged manifests after deleting the tag of the top index", func() {
				gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
					Delay: 1 * time.Millisecond,
					ImageRetention: config.ImageRetention{
						Delay: 1 * time.Millisecond,
						Policies: []config.RetentionPolicy{
							{
								Repositories:    []string{"**"},
								DeleteReferrers: true,
								DeleteUntagged:  &falseVal,
								KeepTags:        []config.KeepTagsPolicy{},
							},
						},
					},
				}, audit, log, metrics)

				err = deleteTagInStorage(rootDir, repoName, "topindex")

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldBeNil)

				// manifest1, bottomIndex1 and topIndex are untagged, so manifest1 should not be deleted
				tags, err := readTagsFromStorage(rootDir, repoName, manifest1Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest1Digest.Algorithm().String(), manifest1Digest.Encoded()))
				So(err, ShouldBeNil)

				// manifest2 is has a tag, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, manifest2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "manifest2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest2Digest.Algorithm().String(), manifest2Digest.Encoded()))
				So(err, ShouldBeNil)

				// manifest3 is referenced by tagged bottomIndex2, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, manifest3Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest3Digest.Algorithm().String(), manifest3Digest.Encoded()))
				So(err, ShouldBeNil)

				// bottomIndex1 and topIndex are untagged, so bottomIndex1 should not be deleted
				_, err = readTagsFromStorage(rootDir, repoName, bottomIndex1Digest)
				So(err, ShouldBeNil)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex1Digest.Algorithm().String(), bottomIndex1Digest.Encoded()))
				So(err, ShouldBeNil)

				// bottomIndex2 is has a tag, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "bottomIndex2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex2Digest.Algorithm().String(), bottomIndex2Digest.Encoded()))
				So(err, ShouldBeNil)

				// topIndex is untagged, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, rootIndexDigest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, rootIndexDigest.Algorithm().String(), rootIndexDigest.Encoded()))
				So(err, ShouldBeNil)
			})

			Convey("gc unmatching tags", func() {
				gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
					Delay: 1 * time.Millisecond,
					ImageRetention: config.ImageRetention{
						Delay: 1 * time.Millisecond,
						Policies: []config.RetentionPolicy{
							{
								Repositories:    []string{"**"},
								DeleteReferrers: true,
								DeleteUntagged:  &trueVal,
								KeepTags: []config.KeepTagsPolicy{
									{
										Patterns: []string{"manifest2"},
									},
								},
							},
						},
					},
				}, audit, log, metrics)

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldBeNil)

				// manifest1, bottomIndex1 and topIndex are untagged or don't have matching tags
				tags, err := readTagsFromStorage(rootDir, repoName, manifest1Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, manifest1Digest.Algorithm().String(), manifest1Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// manifest2 has a matching tag, so it should not be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, manifest2Digest)
				So(err, ShouldBeNil)
				So(tags, ShouldContain, "manifest2")
				So(len(tags), ShouldEqual, 1)

				_, err = os.Stat(path.Join(blobsDir, manifest2Digest.Algorithm().String(), manifest2Digest.Encoded()))
				So(err, ShouldBeNil)

				// manifest3, bottomIndex2 and topIndex are untagged or don't have matching tags
				tags, err = readTagsFromStorage(rootDir, repoName, manifest3Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, manifest3Digest.Algorithm().String(), manifest3Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// bottomIndex1 and topIndex are untagged, so bottomIndex1 should be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex1Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex1Digest.Algorithm().String(), bottomIndex1Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// bottomIndex2 and topIndex are untagged, so bottomIndex1 should be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, bottomIndex2Digest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, bottomIndex2Digest.Algorithm().String(), bottomIndex2Digest.Encoded()))
				So(err, ShouldNotBeNil)

				// topIndex is untagged, so it should be deleted
				tags, err = readTagsFromStorage(rootDir, repoName, rootIndexDigest)
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 0)

				_, err = os.Stat(path.Join(blobsDir, rootIndexDigest.Algorithm().String(), rootIndexDigest.Encoded()))
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func deleteTagInStorage(rootDir, repoName, tag string) error {
	indexJSONBuf, err := os.ReadFile(path.Join(rootDir, repoName, "index.json"))
	if err != nil {
		return err
	}

	var indexJSON ispec.Index

	err = json.Unmarshal(indexJSONBuf, &indexJSON)
	if err != nil {
		return err
	}

	for _, desc := range indexJSON.Manifests {
		if desc.Annotations[ispec.AnnotationRefName] == tag {
			delete(desc.Annotations, ispec.AnnotationRefName)
		}
	}

	indexJSONBuf, err = json.Marshal(indexJSON)
	if err != nil {
		return err
	}

	err = os.WriteFile(path.Join(rootDir, repoName, "index.json"), indexJSONBuf, 0o600)
	if err != nil {
		return err
	}

	return nil
}

func readTagsFromStorage(rootDir, repoName string, digest godigest.Digest) ([]string, error) {
	result := []string{}

	indexJSONBuf, err := os.ReadFile(path.Join(rootDir, repoName, "index.json"))
	if err != nil {
		return result, err
	}

	var indexJSON ispec.Index

	err = json.Unmarshal(indexJSONBuf, &indexJSON)
	if err != nil {
		return result, err
	}

	for _, desc := range indexJSON.Manifests {
		if desc.Digest != digest {
			continue
		}

		name := desc.Annotations[ispec.AnnotationRefName]
		// There is a special case where there is an entry in
		// the index.json without tags, in this case name is an empty string
		// Also we should not have duplicates
		// Do these checks in the actual test cases, not here
		result = append(result, name)
	}

	return result, nil
}

// The backend subtests run in parallel, but the top-level test stays sequential on
// purpose: parallelising it too would run this and the other retention test's backends
// concurrently, multiplying the load on the runner and the storage emulators.
//
//nolint:tparallel
func TestGarbageCollectAndRetentionNoMetaDB(t *testing.T) {
	log := zlog.NewTestLogger()
	audit := zlog.NewAuditLogger("debug", "/dev/null")

	metrics := newTestMetricsServer(t, log)

	trueVal := true

	for _, testcase := range testCases {
		t.Run(testcase.testCaseName, func(t *testing.T) {
			// Run the storage backends concurrently. Each subtest builds its own store,
			// cache and metaDB (unique prefixes / temp dirs), so the S3, filesystem and
			// Azure passes are independent and need not run in series.
			t.Parallel()

			var imgStore storageTypes.ImageStore

			var metaDB mTypes.MetaDB
			metaDB = nil

			switch testcase.storageType {
			case storageConstants.S3StorageDriverName:
				tskip.SkipDynamo(t)
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				rootDir := path.Join("/oci-repo-test", uuid.String())
				cacheDir := t.TempDir()

				bucket := "zot-storage-test"

				storageDriverParams := map[string]any{
					"rootDir":        rootDir,
					"name":           "s3",
					"region":         region,
					"bucket":         bucket,
					"regionendpoint": os.Getenv("S3MOCK_ENDPOINT"),
					"accesskey":      "minioadmin",
					"secretkey":      "minioadmin",
					"secure":         false,
					"skipverify":     false,
					"forcepathstyle": true,
				}

				storeName := fmt.Sprintf("%v", storageDriverParams["name"])

				store, err := factory.Create(context.Background(), storeName, storageDriverParams)
				if err != nil {
					panic(err)
				}

				defer store.Delete(context.Background(), rootDir) //nolint: errcheck

				// create bucket if it doesn't exists
				_, err = resty.R().Put("http://" + os.Getenv("S3MOCK_ENDPOINT") + "/" + bucket)
				if err != nil {
					panic(err)
				}

				imgStore = s3.NewImageStore(rootDir, cacheDir, true, false, log, metrics, nil, store, nil, nil, nil)
			case storageConstants.AzureStorageDriverName:
				tskip.SkipAzure(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				rootDir := path.Join("/oci-repo-test", uuid.String())
				cacheDir := t.TempDir()

				driverParams := azurite.DriverParams(rootDir)
				storage.NormalizeRootDirectory(storageConstants.AzureStorageDriverName, driverParams)

				store, err := factory.Create(context.Background(), storageConstants.AzureStorageDriverName, driverParams)
				if err != nil {
					panic(err)
				}

				if err := azurite.EnsureContainer(); err != nil {
					panic(err)
				}

				defer store.Delete(context.Background(), "/") //nolint: errcheck

				imgStore = azure.NewImageStore(storage.RootDir(storageConstants.AzureStorageDriverName, driverParams),
					cacheDir, true, false, log, metrics, nil, store, nil, nil, nil)
			default:
				// Create temporary directory
				rootDir := t.TempDir()

				// Create ImageStore
				imgStore = local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)
			}

			storeController := storage.StoreController{}
			storeController.DefaultStore = imgStore

			ctx := context.Background()

			Convey("setup gc images", t, func() {
				// for gc testing
				// basic images
				gcTest1 := CreateRandomImage()
				err := WriteImageToFileSystem(gcTest1, "gc-test1", "0.0.1", storeController)
				So(err, ShouldBeNil)

				// also add same image(same digest) with another tag
				err = WriteImageToFileSystem(gcTest1, "gc-test1", "0.0.2", storeController)
				So(err, ShouldBeNil)

				gcTest2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcTest2, "gc-test2", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcTest3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcTest3, "gc-test3", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcTest4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcTest4, "gc-test4", "0.0.1", storeController)
				So(err, ShouldBeNil)

				// referrers
				ref1 := CreateRandomImageWith().Subject(gcTest1.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref1, "gc-test1", ref1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref2 := CreateRandomImageWith().Subject(gcTest2.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref2, "gc-test2", ref2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref3 := CreateRandomImageWith().Subject(gcTest3.DescriptorRef()).Build()
				err = WriteImageToFileSystem(ref3, "gc-test3", ref3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				ref4 := CreateMultiarchWith().RandomImages(3).Subject(gcTest4.DescriptorRef()).Build()
				err = WriteMultiArchImageToFileSystem(ref4, "gc-test4", ref4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// referrers pointing to referrers
				refOfRef1 := CreateRandomImageWith().Subject(ref1.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef1, "gc-test1", refOfRef1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef2 := CreateRandomImageWith().Subject(ref2.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef2, "gc-test2", refOfRef2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef3 := CreateRandomImageWith().Subject(ref3.DescriptorRef()).Build()
				err = WriteImageToFileSystem(refOfRef3, "gc-test3", refOfRef3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				refOfRef4 := CreateMultiarchWith().RandomImages(3).Subject(ref4.DescriptorRef()).Build()
				err = WriteMultiArchImageToFileSystem(refOfRef4, "gc-test4", refOfRef4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// untagged images
				gcUntagged1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged1, "gc-test1", gcUntagged1.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged2, "gc-test2", gcUntagged2.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcUntagged3, "gc-test3", gcUntagged3.DigestStr(), storeController)
				So(err, ShouldBeNil)

				gcUntagged4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcUntagged4, "gc-test4", gcUntagged4.DigestStr(), storeController)
				So(err, ShouldBeNil)

				// for image retention testing
				// old images
				gcOld1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld1, "retention", "0.0.1", storeController)
				So(err, ShouldBeNil)

				gcOld2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld2, "retention", "0.0.2", storeController)
				So(err, ShouldBeNil)

				gcOld3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcOld3, "retention", "0.0.3", storeController)
				So(err, ShouldBeNil)

				gcOld4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcOld4, "retention", "0.0.7", storeController)
				So(err, ShouldBeNil)

				// new images
				gcNew1 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew1, "retention", "0.0.4", storeController)
				So(err, ShouldBeNil)

				gcNew2 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew2, "retention", "0.0.5", storeController)
				So(err, ShouldBeNil)

				gcNew3 := CreateRandomImage()
				err = WriteImageToFileSystem(gcNew3, "retention", "0.0.6", storeController)
				So(err, ShouldBeNil)

				gcNew4 := CreateRandomMultiarch()
				err = WriteMultiArchImageToFileSystem(gcNew4, "retention", "0.0.8", storeController)
				So(err, ShouldBeNil)

				Convey("should not gc anything", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test4")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcTest2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcUntagged2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", ref2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", refOfRef2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcTest3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcUntagged3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", ref3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", refOfRef3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcTest4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcUntagged4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", ref4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", refOfRef4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("gc untagged manifests", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags:        []config.KeepTagsPolicy{},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test4")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcTest2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", gcUntagged2.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", ref2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", refOfRef2.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcTest3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", gcUntagged3.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", ref3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", refOfRef3.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcTest4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", gcUntagged4.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", ref4.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test4", refOfRef4.DigestStr())
					So(err, ShouldBeNil)
				})

				Convey("gc all tags, untagged, and afterwards referrers", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					// although we have two tags both should be deleted
					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcTest1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldNotBeNil)

					// now repo should get gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldNotContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc all tags, untagged, and afterwards referrers using GetNextRepository()", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1", "gc-test3"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					processedRepos := make(map[string]struct{})
					expectedRepos := []string{"gc-test1", "gc-test2", "gc-test3", "gc-test4", "retention"}

					for i := range 10 {
						t.Logf("index %d, processed repos %v", i, processedRepos)

						// we need to check if GetNextRepository returns each repository just once, and empty string afterwards
						repo, err := imgStore.GetNextRepository(processedRepos)
						t.Logf("index %d, repo '%s'", i, repo)
						So(err, ShouldBeNil)

						if i >= len(expectedRepos) {
							So(repo, ShouldEqual, "")

							continue
						}
						So(repo, ShouldEqual, expectedRepos[i]) //nolint:gosec // guarded by i < len(expectedRepos)

						processedRepos[repo] = struct{}{}

						// run cleanRepo, this should not impact the list of calls necessary for
						// GetNextRepository to iterate through every repo
						err = gc.CleanRepo(ctx, repo)
						So(err, ShouldBeNil)
					}

					// verify one more time the returned values
					So(len(processedRepos), ShouldEqual, len(expectedRepos))

					for _, repo := range expectedRepos {
						So(processedRepos, ShouldContainKey, repo)
					}

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					// now repos should get gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldNotContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldNotContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc with dry-run all tags, untagged, and afterwards referrers", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay:  1 * time.Millisecond,
							DryRun: true,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"gc-test1"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"v1"}, // should not match any tag
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					// now repo should not be gc'ed
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "gc-test4")
					So(repos, ShouldContain, "retention")

					tags, err := imgStore.GetImageTags("gc-test1")
					So(err, ShouldBeNil)
					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldContain, "0.0.2")
				})

				Convey("all tags matches for retention", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.*"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain all tags if keeptags is not specified", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test2", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test3", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.2")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.3")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.4")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.5")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.6")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain a subset of all tags based on patterns only", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.1"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)
					t.Log(tags)

					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.4")
					So(tags, ShouldNotContain, "0.0.5")
					So(tags, ShouldNotContain, "0.0.6")
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
				})

				Convey("retain a subset of all tags based on patterns only using multiple rules", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultGCDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.1"},
										},
										{
											Patterns: []string{"0.0.2"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)
					t.Log(tags)

					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
					So(tags, ShouldNotContain, "0.0.4")
					So(tags, ShouldNotContain, "0.0.5")
					So(tags, ShouldNotContain, "0.0.6")
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
				})

				Convey("gc - do not match any repo", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: 1 * time.Millisecond,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"no-match"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log, metrics)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", ref1.DigestStr())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", refOfRef1.DigestStr())
					So(err, ShouldBeNil)

					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldContain, "gc-test1")
					So(repos, ShouldContain, "gc-test2")
					So(repos, ShouldContain, "gc-test3")
					So(repos, ShouldContain, "retention")
				})

				Convey("gc with context done", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: 1 * time.Millisecond,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.*"},
										},
									},
								},
							},
						},
					}, audit, log, metrics)

					ctx, cancel := context.WithCancel(ctx)
					cancel()

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldNotBeNil)
				})

				Convey("should gc only stale blob uploads", func() {
					repoName := "gc-test1"

					// Drive staleness through the GC delay rather than wall-clock time: a long
					// delay keeps a recent upload, a zero delay treats it as stale. This keeps the
					// test deterministic regardless of how long the backend takes to respond.
					newGC := func(delay time.Duration) gc.GarbageCollect {
						return gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
							Delay: delay,
							ImageRetention: config.ImageRetention{
								Delay: storageConstants.DefaultGCDelay,
								Policies: []config.RetentionPolicy{
									{
										Repositories:    []string{"**"},
										DeleteReferrers: true,
										DeleteUntagged:  &trueVal,
										KeepTags: []config.KeepTagsPolicy{
											{},
										},
									},
								},
							},
						}, audit, log, metrics)
					}

					blobUploadID, err := imgStore.NewBlobUpload(context.Background(), repoName)
					So(err, ShouldBeNil)

					content := []byte("test-data3")
					buf := bytes.NewBuffer(content)
					_, err = imgStore.PutBlobChunkStreamed(context.Background(), repoName, blobUploadID, buf)
					So(err, ShouldBeNil)

					// Blob upload should be there
					uploads, err := imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err := imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					// A long GC delay keeps the recent upload.
					err = newGC(1*time.Hour).CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob upload is recent it should still be there
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote storage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					// A zero GC delay treats the upload as stale, so it is collected.
					err = newGC(0).CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob uploads should be GCed
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)
					So(uploads, ShouldBeEmpty)

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)
					So(err, ShouldNotBeNil)
					So(isPresent, ShouldBeFalse)
				})
			})
		})
	}
}

// TestGCMultiArchIndexKeepsNestedConfigAndLayers is the S2 guard (AC-1): platform manifests that are
// reachable ONLY through a tagged image index - i.e. they are never their own index.json entry - must
// keep their config/layer blobs across blob-GC. This requires the referenced-blobs collector to recurse
// into the index rather than only reading the top-level index.json entries (the old
// addImageIndexBlobsToReferences behavior recorded the nested manifest digests but not their
// config/layers).
func TestGCMultiArchIndexKeepsNestedConfigAndLayers(t *testing.T) {
	Convey("tagged image index whose platform manifests are nested-only", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		ctx := context.Background()
		repoName := "gc-nested-multiarch"

		err := imgStore.InitRepo(ctx, repoName)
		So(err, ShouldBeNil)

		platform1 := CreateRandomImage()
		platform2 := CreateRandomImage()

		blobExists := func(digest godigest.Digest) bool {
			_, statErr := os.Stat(path.Join(rootDir, repoName, "blobs", digest.Algorithm().String(), digest.Encoded()))

			return statErr == nil
		}

		// write each platform manifest's config, layers and manifest content as plain blobs -
		// deliberately NOT via PutImageManifest, so they never become their own index.json entry.
		writeNestedOnly := func(img Image) {
			for _, layerBlob := range img.Layers {
				layerDigest := godigest.FromBytes(layerBlob)
				_, _, err := imgStore.FullBlobUpload(ctx, repoName, bytes.NewReader(layerBlob), layerDigest)
				So(err, ShouldBeNil)
			}

			configBlob, err := json.Marshal(img.Config)
			So(err, ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, repoName, bytes.NewReader(configBlob), img.Manifest.Config.Digest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, repoName,
				bytes.NewReader(img.ManifestDescriptor.Data), img.ManifestDescriptor.Digest)
			So(err, ShouldBeNil)
		}

		writeNestedOnly(platform1)
		writeNestedOnly(platform2)

		topIndex := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					Digest:    platform1.ManifestDescriptor.Digest,
					Size:      platform1.ManifestDescriptor.Size,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    platform2.ManifestDescriptor.Digest,
					Size:      platform2.ManifestDescriptor.Size,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		topIndexBlob, err := json.Marshal(topIndex)
		So(err, ShouldBeNil)

		topIndexDigest, _, err := imgStore.PutImageManifest(ctx, repoName, "top", ispec.MediaTypeImageIndex, topIndexBlob, nil)
		So(err, ShouldBeNil)

		// sanity check: index.json only carries the tagged top index, the platform manifests are
		// reachable exclusively through recursion into that index's own descriptor list.
		indexContent, err := imgStore.GetIndexContent(repoName)
		So(err, ShouldBeNil)

		var indexJSON ispec.Index

		err = json.Unmarshal(indexContent, &indexJSON)
		So(err, ShouldBeNil)
		So(len(indexJSON.Manifests), ShouldEqual, 1)
		So(indexJSON.Manifests[0].Digest, ShouldEqual, topIndexDigest)

		// sleep past the delay so the nested config/layer blobs are genuinely GC-eligible
		// (exercises the real orphan-age filter instead of relying on an inert near-zero delay).
		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		So(blobExists(topIndexDigest), ShouldBeTrue)

		for _, platform := range []Image{platform1, platform2} {
			So(blobExists(platform.ManifestDescriptor.Digest), ShouldBeTrue)
			So(blobExists(platform.Manifest.Config.Digest), ShouldBeTrue)

			for _, layer := range platform.Manifest.Layers {
				So(blobExists(layer.Digest), ShouldBeTrue)
			}
		}
	})
}

// TestGCDockerSchema2ListNotOverDeleted is the S1 guard (AC-2): a tagged docker manifest-list image
// must keep every nested docker schema2 manifest's config/layer blobs after blob-GC. Docker media types
// used to fall into the collector's own-digest-only default arm, so their config/layers were treated as
// unreferenced and deleted regardless of nesting.
func TestGCDockerSchema2ListNotOverDeleted(t *testing.T) {
	Convey("tagged docker manifest-list image", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		compatMediaTypes := []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, compatMediaTypes, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-docker-schema2-list"

		dockerList := CreateRandomMultiarch().AsDockerImage()

		err := WriteMultiArchImageToFileSystem(dockerList, repoName, "0.0.1", storeController)
		So(err, ShouldBeNil)

		blobExists := func(digest godigest.Digest) bool {
			_, statErr := os.Stat(path.Join(rootDir, repoName, "blobs", digest.Algorithm().String(), digest.Encoded()))

			return statErr == nil
		}

		// sleep past the delay so the nested config/layer blobs are genuinely GC-eligible
		// (exercises the real orphan-age filter instead of relying on an inert near-zero delay).
		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		So(blobExists(dockerList.IndexDescriptor.Digest), ShouldBeTrue)

		for _, image := range dockerList.Images {
			So(blobExists(image.ManifestDescriptor.Digest), ShouldBeTrue)
			So(blobExists(image.Manifest.Config.Digest), ShouldBeTrue)

			for _, layer := range image.Manifest.Layers {
				So(blobExists(layer.Digest), ShouldBeTrue)
			}
		}
	})
}

// TestGCUnknownMediaTypeManifestPruned guards the corruption found during fix-loop verification:
// common.GetReferencedBlobs marks every index.json descriptor's own digest as referenced regardless of
// media type (mirroring IsBlobReferencedInImageIndex), so a tagged index entry with an
// unsupported/unknown manifest media type would otherwise never become an orphan - while its config/layer
// blobs still fall out as real orphans and get deleted, leaving a dangling index.json entry. GC must
// force-prune such entries itself so the manifest and its blobs are cleaned together, and a healthy
// tagged image must be left untouched.
func TestGCUnknownMediaTypeManifestPruned(t *testing.T) {
	Convey("index.json entry with unsupported manifest media type", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-unknown-media-type"

		unsupportedMediaType := "application/vnd.oci.artifact.manifest.v1+json"

		healthy := CreateRandomImage()
		err := WriteImageToFileSystem(healthy, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		unknown := CreateRandomImage()
		err = WriteImageToFileSystem(unknown, repoName, "unknown", storeController)
		So(err, ShouldBeNil)

		// rewrite the unknown image's manifest with an unsupported media type, re-hash it, write the
		// new blob, and re-point/re-type its index.json descriptor - exactly mirroring how
		// TestGarbageCollectImageUnknownManifest (pkg/storage/local/local_test.go) builds the fixture.
		unknownBuf, err := os.ReadFile(path.Join(rootDir, repoName, "blobs",
			unknown.ManifestDescriptor.Digest.Algorithm().String(), unknown.ManifestDescriptor.Digest.Encoded()))
		So(err, ShouldBeNil)

		var unknownManifest ispec.Manifest

		err = json.Unmarshal(unknownBuf, &unknownManifest)
		So(err, ShouldBeNil)

		unknownManifest.MediaType = unsupportedMediaType

		unknownBuf, err = json.Marshal(unknownManifest)
		So(err, ShouldBeNil)

		unknownDigest := godigest.FromBytes(unknownBuf)

		err = os.WriteFile(path.Join(rootDir, repoName, "blobs", unknownDigest.Algorithm().String(), unknownDigest.Encoded()),
			unknownBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		indexJSONBuf, err := os.ReadFile(path.Join(rootDir, repoName, "index.json"))
		So(err, ShouldBeNil)

		var indexJSON ispec.Index

		err = json.Unmarshal(indexJSONBuf, &indexJSON)
		So(err, ShouldBeNil)

		for idx, desc := range indexJSON.Manifests {
			if desc.Digest == unknown.ManifestDescriptor.Digest {
				indexJSON.Manifests[idx].Digest = unknownDigest
				indexJSON.Manifests[idx].MediaType = unsupportedMediaType
			}
		}

		indexJSONBuf, err = json.Marshal(indexJSON)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(rootDir, repoName, "index.json"), indexJSONBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		blobExists := func(digest godigest.Digest) bool {
			_, statErr := os.Stat(path.Join(rootDir, repoName, "blobs", digest.Algorithm().String(), digest.Encoded()))

			return statErr == nil
		}

		// sleep so the unknown manifest's config/layers pass the GC delay's age gate once orphaned
		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		// (a) the unknown manifest entry is removed from index.json
		prunedIndexBuf, err := imgStore.GetIndexContent(repoName)
		So(err, ShouldBeNil)

		var prunedIndex ispec.Index

		err = json.Unmarshal(prunedIndexBuf, &prunedIndex)
		So(err, ShouldBeNil)

		for _, desc := range prunedIndex.Manifests {
			So(desc.Digest, ShouldNotEqual, unknownDigest)
		}

		// (b) the unknown manifest's config/layer blobs are gone
		So(blobExists(unknownDigest), ShouldBeFalse)
		So(blobExists(unknown.Manifest.Config.Digest), ShouldBeFalse)

		for _, layer := range unknown.Manifest.Layers {
			So(blobExists(layer.Digest), ShouldBeFalse)
		}

		// (c) the healthy tagged image's blobs survive
		So(blobExists(healthy.ManifestDescriptor.Digest), ShouldBeTrue)
		So(blobExists(healthy.Manifest.Config.Digest), ShouldBeTrue)

		for _, layer := range healthy.Manifest.Layers {
			So(blobExists(layer.Digest), ShouldBeTrue)
		}
	})
}

// TestGCDryRunDeletesNothing guards DryRun's non-destructive-simulation contract: index.json pruning is
// already DryRun-gated, but blob GC re-reads the on-disk index.json independently and used to run
// unconditionally, so it could delete orphan blobs for real - including the config/layers of an
// unknown-media-type entry whose index.json descriptor DryRun leaves untouched, corrupting the repo. Blob
// GC (and upload GC) must be gated by DryRun exactly like the index-prune passes and metrics.
func TestGCDryRunDeletesNothing(t *testing.T) {
	Convey("DryRun with a true orphan blob and an unknown media type entry", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-dry-run"

		unsupportedMediaType := "application/vnd.oci.artifact.manifest.v1+json"

		healthy := CreateRandomImage()
		err := WriteImageToFileSystem(healthy, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		unknown := CreateRandomImage()
		err = WriteImageToFileSystem(unknown, repoName, "unknown", storeController)
		So(err, ShouldBeNil)

		unknownBuf, err := os.ReadFile(path.Join(rootDir, repoName, "blobs",
			unknown.ManifestDescriptor.Digest.Algorithm().String(), unknown.ManifestDescriptor.Digest.Encoded()))
		So(err, ShouldBeNil)

		var unknownManifest ispec.Manifest

		err = json.Unmarshal(unknownBuf, &unknownManifest)
		So(err, ShouldBeNil)

		unknownManifest.MediaType = unsupportedMediaType

		unknownBuf, err = json.Marshal(unknownManifest)
		So(err, ShouldBeNil)

		unknownDigest := godigest.FromBytes(unknownBuf)

		err = os.WriteFile(path.Join(rootDir, repoName, "blobs", unknownDigest.Algorithm().String(), unknownDigest.Encoded()),
			unknownBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		indexJSONBuf, err := os.ReadFile(path.Join(rootDir, repoName, "index.json"))
		So(err, ShouldBeNil)

		var indexJSON ispec.Index

		err = json.Unmarshal(indexJSONBuf, &indexJSON)
		So(err, ShouldBeNil)

		for idx, desc := range indexJSON.Manifests {
			if desc.Digest == unknown.ManifestDescriptor.Digest {
				indexJSON.Manifests[idx].Digest = unknownDigest
				indexJSON.Manifests[idx].MediaType = unsupportedMediaType
			}
		}

		indexJSONBuf, err = json.Marshal(indexJSON)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(rootDir, repoName, "index.json"), indexJSONBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		// a true orphan blob: content-addressed, never referenced by any manifest
		orphanContent := []byte("i am a true orphan blob")
		orphanDigest := godigest.FromBytes(orphanContent)

		_, _, err = imgStore.FullBlobUpload(ctx, repoName, bytes.NewReader(orphanContent), orphanDigest)
		So(err, ShouldBeNil)

		blobExists := func(digest godigest.Digest) bool {
			_, statErr := os.Stat(path.Join(rootDir, repoName, "blobs", digest.Algorithm().String(), digest.Encoded()))

			return statErr == nil
		}

		// snapshot index.json bytes before GC, so we can assert it is byte-identical afterwards
		indexBefore, err := imgStore.GetIndexContent(repoName)
		So(err, ShouldBeNil)

		// sleep so the orphan / unknown-media-type blobs would pass the GC delay's age gate
		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay:  1 * time.Second,
				DryRun: true,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		indexAfter, err := imgStore.GetIndexContent(repoName)
		So(err, ShouldBeNil)
		So(string(indexAfter), ShouldEqual, string(indexBefore))

		So(blobExists(orphanDigest), ShouldBeTrue)

		So(blobExists(unknownDigest), ShouldBeTrue)
		So(blobExists(unknown.Manifest.Config.Digest), ShouldBeTrue)

		for _, layer := range unknown.Manifest.Layers {
			So(blobExists(layer.Digest), ShouldBeTrue)
		}

		So(blobExists(healthy.ManifestDescriptor.Digest), ShouldBeTrue)
		So(blobExists(healthy.Manifest.Config.Digest), ShouldBeTrue)

		for _, layer := range healthy.Manifest.Layers {
			So(blobExists(layer.Digest), ShouldBeTrue)
		}
	})
}

// TestGCRemoveRepoAfterAllBlobsGCed covers the CleanupRepo tail (imagestore.go): once GC reaps every
// blob in a repo (removeRepo == len(gcBlobs) == len(allBlobs)) and there is no in-progress blob upload,
// the whole repo directory is removed; but if a blob upload is in progress, the guard must keep the
// repo directory even though every blob was reaped.
func TestGCRemoveRepoAfterAllBlobsGCed(t *testing.T) {
	Convey("repo directory is removed once every blob is GCed and no upload is in progress", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-remove-repo"

		img := CreateRandomImage()
		err := WriteImageToFileSystem(img, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		// drop the only manifest entry, so index.json is empty and every on-disk blob becomes an orphan
		err = imgStore.DeleteImageManifest(ctx, repoName, "v1", true)
		So(err, ShouldBeNil)

		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldNotContain, repoName)
	})

	Convey("repo directory is kept when a blob upload is in progress even though every blob was GCed", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-remove-repo-upload-guard"

		img := CreateRandomImage()
		err := WriteImageToFileSystem(img, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		err = imgStore.DeleteImageManifest(ctx, repoName, "v1", true)
		So(err, ShouldBeNil)

		// start (and leave open) a blob upload, so ListBlobUploads is non-empty when CleanupRepo runs
		_, err = imgStore.NewBlobUpload(ctx, repoName)
		So(err, ShouldBeNil)

		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldContain, repoName)
	})
}

// TestGCUnknownMediaTypeManifestPrunedSharedBlobKept guards that pruning an unknown-media-type entry
// and then collecting orphans still respects cross-references: a config blob shared between the pruned
// unknown-media-type manifest and a healthy tagged image must survive (the healthy image still
// references it), while a blob referenced ONLY by the unknown manifest must be deleted.
func TestGCUnknownMediaTypeManifestPrunedSharedBlobKept(t *testing.T) {
	Convey("unknown media type manifest sharing a config blob with a healthy image", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "/dev/null")
		metrics := newTestMetricsServer(t, log)

		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore

		ctx := context.Background()
		repoName := "gc-unknown-media-type-shared-blob"

		unsupportedMediaType := "application/vnd.oci.artifact.manifest.v1+json"

		healthy := CreateRandomImage()
		err := WriteImageToFileSystem(healthy, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		// a blob referenced ONLY by the unknown-media-type manifest - must be deleted once pruned
		exclusiveLayerContent := []byte("exclusive to the unknown-media-type manifest")
		exclusiveLayerDigest := godigest.FromBytes(exclusiveLayerContent)

		_, _, err = imgStore.FullBlobUpload(ctx, repoName, bytes.NewReader(exclusiveLayerContent), exclusiveLayerDigest)
		So(err, ShouldBeNil)

		// the unknown manifest reuses the healthy image's config digest - this blob must survive
		unknownManifest := ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: unsupportedMediaType,
			Config:    healthy.Manifest.Config,
			Layers:    []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer, Digest: exclusiveLayerDigest, Size: int64(len(exclusiveLayerContent))}},
		}

		unknownBuf, err := json.Marshal(unknownManifest)
		So(err, ShouldBeNil)

		unknownDigest := godigest.FromBytes(unknownBuf)

		_, _, err = imgStore.FullBlobUpload(ctx, repoName, bytes.NewReader(unknownBuf), unknownDigest)
		So(err, ShouldBeNil)

		indexJSONBuf, err := os.ReadFile(path.Join(rootDir, repoName, "index.json"))
		So(err, ShouldBeNil)

		var indexJSON ispec.Index

		err = json.Unmarshal(indexJSONBuf, &indexJSON)
		So(err, ShouldBeNil)

		indexJSON.Manifests = append(indexJSON.Manifests, ispec.Descriptor{
			MediaType: unsupportedMediaType,
			Digest:    unknownDigest,
			Size:      int64(len(unknownBuf)),
			Annotations: map[string]string{
				ispec.AnnotationRefName: "unknown",
			},
		})

		indexJSONBuf, err = json.Marshal(indexJSON)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(rootDir, repoName, "index.json"), indexJSONBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		blobExists := func(digest godigest.Digest) bool {
			_, statErr := os.Stat(path.Join(rootDir, repoName, "blobs", digest.Algorithm().String(), digest.Encoded()))

			return statErr == nil
		}

		time.Sleep(1 * time.Second)

		gcInstance := gc.NewGarbageCollect(imgStore, nil, gc.Options{
			Delay: 1 * time.Second,
			ImageRetention: config.ImageRetention{
				Delay: 1 * time.Second,
			},
		}, audit, log, metrics)

		err = gcInstance.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		// the unknown entry is pruned from index.json
		prunedIndexBuf, err := imgStore.GetIndexContent(repoName)
		So(err, ShouldBeNil)

		var prunedIndex ispec.Index

		err = json.Unmarshal(prunedIndexBuf, &prunedIndex)
		So(err, ShouldBeNil)

		for _, desc := range prunedIndex.Manifests {
			So(desc.Digest, ShouldNotEqual, unknownDigest)
		}

		// the unknown manifest blob itself and its exclusive layer are gone
		So(blobExists(unknownDigest), ShouldBeFalse)
		So(blobExists(exclusiveLayerDigest), ShouldBeFalse)

		// the shared config blob survives - still referenced by the healthy image
		So(blobExists(healthy.Manifest.Config.Digest), ShouldBeTrue)

		// the healthy image's own manifest/layers survive too
		So(blobExists(healthy.ManifestDescriptor.Digest), ShouldBeTrue)

		for _, layer := range healthy.Manifest.Layers {
			So(blobExists(layer.Digest), ShouldBeTrue)
		}
	})
}
