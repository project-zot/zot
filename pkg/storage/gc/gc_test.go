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

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/compat"
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
	region        = "us-east-2"
	s3TestName    = "S3APIs"
	localTestName = "LocalAPIs"
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
}

func TestGarbageCollectAndRetentionMetaDB(t *testing.T) {
	log := zlog.NewTestLogger()
	audit := zlog.NewAuditLogger("debug", "/dev/null")

	metrics := monitoring.NewMetricsServer(false, log)

	trueVal := true

	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore

			var metaDB mTypes.MetaDB
			compat := []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}

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
			} else {
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
					}, audit, log)

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
					}, audit, log)

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
					}, audit, log)

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
							Delay: storageConstants.DefaultRetentionDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
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
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
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
					So(tags, ShouldNotContain, "0.0.7")
					So(tags, ShouldNotContain, "0.0.8")
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
					}, audit, log)

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
							Delay: storageConstants.DefaultRetentionDelay,
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
					}, audit, log)

					ctx, cancel := context.WithCancel(ctx)
					cancel()

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldNotBeNil)
				})

				Convey("should gc only stale blob uploads", func() {
					gcDelay := 1 * time.Second
					repoName := "gc-test1"

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: gcDelay,
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

					blobUploadID, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)

					content := []byte("test-data3")
					buf := bytes.NewBuffer(content)
					_, err = imgStore.PutBlobChunkStreamed(repoName, blobUploadID, buf)
					So(err, ShouldBeNil)

					// Blob upload should be there
					uploads, err := imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err := imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob upload is recent it should still be there
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					time.Sleep(gcDelay + 1*time.Second)

					err = gc.CleanRepo(ctx, repoName)
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

		metrics := monitoring.NewMetricsServer(false, log)

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

			rootIndexDigest, _, err := imgStore.PutImageManifest(repoName, "topindex", ispec.MediaTypeImageIndex,
				topIndexBlob)
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
				}, audit, log)

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
				}, audit, log)

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
				}, audit, log)

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
				}, audit, log)

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

func TestGarbageCollectAndRetentionNoMetaDB(t *testing.T) {
	log := zlog.NewTestLogger()
	audit := zlog.NewAuditLogger("debug", "/dev/null")

	metrics := monitoring.NewMetricsServer(false, log)

	trueVal := true

	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore

			var metaDB mTypes.MetaDB
			metaDB = nil

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
			} else {
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
					}, audit, log)

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
					}, audit, log)

					processedRepos := make(map[string]struct{})
					expectedRepos := []string{"gc-test1", "gc-test2", "gc-test3", "gc-test4", "retention"}

					for i := range 10 {
						t.Logf("index %d, processed repos %v", i, processedRepos)

						// we need to check if GetNextRepository returns each repository just once, and empty string afterwards
						repo, err := imgStore.GetNextRepository(processedRepos)
						t.Logf("index %d, repo '%s'", i, repo)
						So(err, ShouldBeNil)

						if i >= 5 {
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

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain all tags if keeptags is not specified", func() {
					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
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

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.7")
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("retention", "0.0.8")
					So(err, ShouldBeNil)
				})

				Convey("retain a subset of all tags based on patterns only", func() {
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
					}, audit, log)

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
					}, audit, log)

					ctx, cancel := context.WithCancel(ctx)
					cancel()

					err := gc.CleanRepo(ctx, "gc-test1")
					So(err, ShouldNotBeNil)
				})

				Convey("should gc only stale blob uploads", func() {
					gcDelay := 1 * time.Second
					repoName := "gc-test1"

					gc := gc.NewGarbageCollect(imgStore, metaDB, gc.Options{
						Delay: gcDelay,
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

					blobUploadID, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)

					content := []byte("test-data3")
					buf := bytes.NewBuffer(content)
					_, err = imgStore.PutBlobChunkStreamed(repoName, blobUploadID, buf)
					So(err, ShouldBeNil)

					// Blob upload should be there
					uploads, err := imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err := imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// Blob upload is recent it should still be there
					uploads, err = imgStore.ListBlobUploads(repoName)
					So(err, ShouldBeNil)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(uploads, ShouldEqual, []string{})
					} else {
						// Local storage is used right away
						So(uploads, ShouldEqual, []string{blobUploadID})
					}

					isPresent, _, _, err = imgStore.StatBlobUpload(repoName, blobUploadID)

					if testcase.testCaseName == s3TestName {
						// Remote sorage is written to only after the blob upload is finished,
						// there should be no space used by blob uploads
						So(err, ShouldNotBeNil)
						So(isPresent, ShouldBeFalse)
					} else {
						// Local storage is used right away
						So(err, ShouldBeNil)
						So(isPresent, ShouldBeTrue)
					}

					time.Sleep(gcDelay + 1*time.Second)

					err = gc.CleanRepo(ctx, repoName)
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
