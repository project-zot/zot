package gc_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/docker/distribution/registry/storage/driver/factory"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	"zotregistry.dev/zot/pkg/meta/dynamodb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/gc"
	"zotregistry.dev/zot/pkg/storage/local"
	"zotregistry.dev/zot/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

const (
	region = "us-east-2"
)

//nolint:gochecknoglobals
var testCases = []struct {
	testCaseName string
	storageType  string
}{
	{
		testCaseName: "S3APIs",
		storageType:  storageConstants.S3StorageDriverName,
	},
	{
		testCaseName: "LocalAPIs",
		storageType:  storageConstants.LocalStorageDriverName,
	},
}

func TestGarbageCollectAndRetention(t *testing.T) {
	log := zlog.NewLogger("info", "/dev/null")
	audit := zlog.NewAuditLogger("debug", "/dev/null")

	metrics := monitoring.NewMetricsServer(false, log)

	trueVal := true

	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore

			var metaDB mTypes.MetaDB

			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipDynamo(t)
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				rootDir := path.Join("/oci-repo-test", uuid.String())
				cacheDir := t.TempDir()

				bucket := "zot-storage-test"

				storageDriverParams := map[string]interface{}{
					"rootDir":        rootDir,
					"name":           "s3",
					"region":         region,
					"bucket":         bucket,
					"regionendpoint": os.Getenv("S3MOCK_ENDPOINT"),
					"accesskey":      "minioadmin",
					"secretkey":      "minioadmin",
					"secure":         false,
					"skipverify":     false,
				}

				storeName := fmt.Sprintf("%v", storageDriverParams["name"])

				store, err := factory.Create(storeName, storageDriverParams)
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

				imgStore = s3.NewImageStore(rootDir, cacheDir, true, false, log, metrics, nil, store, nil)
			} else {
				// Create temporary directory
				rootDir := t.TempDir()

				// Create ImageStore
				imgStore = local.NewImageStore(rootDir, false, false, log, metrics, nil, nil)

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

				gcNew1Stats := retentionMeta.Statistics[gcNew1.DigestStr()]
				gcNew1Stats.PushTimestamp = time.Now().Add(-1 * 24 * time.Hour)
				gcNew1Stats.LastPullTimestamp = time.Now().Add(-1 * 24 * time.Hour)

				gcNew2Stats := retentionMeta.Statistics[gcNew2.DigestStr()]
				gcNew2Stats.PushTimestamp = time.Now().Add(-2 * 24 * time.Hour)
				gcNew2Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)

				gcNew3Stats := retentionMeta.Statistics[gcNew3.DigestStr()]
				gcNew3Stats.PushTimestamp = time.Now().Add(-3 * 24 * time.Hour)
				gcNew3Stats.LastPullTimestamp = time.Now().Add(-2 * 24 * time.Hour)

				retentionMeta.Statistics[gcOld1.DigestStr()] = gcOld1Stats
				retentionMeta.Statistics[gcOld2.DigestStr()] = gcOld2Stats
				retentionMeta.Statistics[gcOld3.DigestStr()] = gcOld3Stats

				retentionMeta.Statistics[gcNew1.DigestStr()] = gcNew1Stats
				retentionMeta.Statistics[gcNew2.DigestStr()] = gcNew2Stats
				retentionMeta.Statistics[gcNew3.DigestStr()] = gcNew3Stats

				// update repo meta
				err = metaDB.SetRepoMeta("retention", retentionMeta)
				So(err, ShouldBeNil)

				Convey("should not gc anything", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
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
					}, audit, log)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test2")
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, "gc-test3")
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
					}, audit, log)

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
					}, audit, log)

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
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

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
				})

				Convey("retain new tags", func() {
					sevenDays := 7 * 24 * time.Hour

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

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
				})

				Convey("retain 3 most recently pushed images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

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
				})

				Convey("retain 3 most recently pulled images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

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
				})

				Convey("retain 3 most recently pulled OR 4 most recently pushed images", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

					err = gc.CleanRepo(ctx, "retention")
					So(err, ShouldBeNil)

					tags, err := imgStore.GetImageTags("retention")
					So(err, ShouldBeNil)

					So(tags, ShouldContain, "0.0.1")
					So(tags, ShouldContain, "0.0.4")
					So(tags, ShouldContain, "0.0.5")
					So(tags, ShouldContain, "0.0.6")

					So(tags, ShouldNotContain, "0.0.2")
					So(tags, ShouldNotContain, "0.0.3")
				})

				Convey("test if first match rule logic works", func() {
					twoDays := 2 * 24 * time.Hour
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

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
					}, audit, log)

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("gc-test1", gcUntagged1.DigestStr())
					So(err, ShouldBeNil)

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

				Convey("remove one tag because it didn't match, preserve tags without statistics in metaDB", func() {
					// add new tag in retention repo which can not be found in metaDB, should be always retained
					err = WriteImageToFileSystem(CreateRandomImage(), "retention", "0.0.7", storeController)
					So(err, ShouldBeNil)

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
									KeepTags: []config.KeepTagsPolicy{
										{
											Patterns: []string{"0.0.[1-5]"},
										},
									},
								},
							},
						},
					}, audit, log)

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
					}, audit, log)

					ctx, cancel := context.WithCancel(ctx)
					cancel()

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldNotBeNil)
				})
			})
		})
	}
}
