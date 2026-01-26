package s3_test

import (
	"bytes"
	"context"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/inject"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

//nolint:gochecknoglobals
var (
	testImage      = "test"
	errorText      = "new s3 error"
	errS3          = errors.New(errorText)
	errCache       = errors.New("new cache error")
	zotStorageTest = "zot-storage-test"
	s3Region       = "us-east-2"
)

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func createMockStorage(rootDir string, cacheDir string, dedupe bool, store driver.StorageDriver,
) storageTypes.ImageStore {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(true, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	if _, err := os.Stat(path.Join(cacheDir,
		storageConstants.BoltdbName+storageConstants.DBExtensionName)); dedupe || (!dedupe && err == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	il := s3.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return il
}

func createMockStorageWithMockCache(rootDir string, dedupe bool, store driver.StorageDriver,
	cacheDriver storageTypes.Cache,
) storageTypes.ImageStore {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	il := s3.NewImageStore(rootDir, "", dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return il
}

func createStoreDriver(rootDir string) driver.StorageDriver {
	bucket := zotStorageTest
	endpoint := os.Getenv("S3MOCK_ENDPOINT")
	storageDriverParams := map[string]any{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         s3Region,
		"bucket":         bucket,
		"regionendpoint": endpoint,
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

	// create bucket if it doesn't exists
	_, err = resty.R().Put("http://" + endpoint + "/" + bucket)
	if err != nil {
		panic(err)
	}

	return store
}

func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	store := createStoreDriver(rootDir)

	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	s3CacheDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

	var err error

	if _, err = os.Stat(s3CacheDBPath); dedupe || (!dedupe && err == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	il := s3.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, err
}

func createObjectsStoreDynamo(rootDir string, cacheDir string, dedupe bool, tableName string) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	store := createStoreDriver(rootDir)

	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	tableName = strings.ReplaceAll(tableName, "/", "")

	cacheDriver, _ = storage.Create("dynamodb", cache.DynamoDBDriverParameters{
		Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
		Region:    s3Region,
		TableName: tableName,
	}, log)

	//nolint:errcheck
	cacheDriverDynamo, _ := cacheDriver.(*cache.DynamoDBDriver)

	err := cacheDriverDynamo.NewTable(tableName)
	if err != nil {
		panic(err)
	}

	il := s3.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, err
}

func runAndGetScheduler() *scheduler.Scheduler {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)
	taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
	taskScheduler.RateLimit = 50 * time.Millisecond

	taskScheduler.RunScheduler()

	return taskScheduler
}

func TestStorageDriverStatFunction(t *testing.T) {
	tskip.SkipS3(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
	defer cleanupStorage(storeDriver, testDir)

	/* There is an issue with storageDriver.Stat() that returns a storageDriver.FileInfo()
	which falsely reports isDir() as true for paths under certain circumstances
	for example:
	1) create a file, eg: repo/testImageA/file
	2) run storageDriver.Stat() on a partial path, eg: storageDriver.Stat("repo/testImage") - without 'A' char
	3) the returned storageDriver.FileInfo will report that isDir() is true.
	*/
	Convey("Validate storageDriver.Stat() and isDir() functions with zot storage API", t, func(c C) {
		repo1 := "repo/testimagea"
		repo2 := "repo/testimage"

		So(imgStore, ShouldNotBeNil)

		err = imgStore.InitRepo(repo1)
		So(err, ShouldBeNil)

		isValid, err := imgStore.ValidateRepo(repo1)
		So(err, ShouldBeNil)
		So(isValid, ShouldBeTrue)

		err = imgStore.InitRepo(repo2)
		So(err, ShouldBeNil)

		isValid, err = imgStore.ValidateRepo(repo2)
		So(err, ShouldBeNil)
		So(isValid, ShouldBeTrue)
	})

	Convey("Validate storageDriver.Stat() and isDir() functions with storageDriver API", t, func(c C) {
		testFile := "/ab/cd/file"

		shouldBeDirectoryPath1 := "/ab/cd"
		shouldBeDirectoryPath2 := "/ab"

		shouldNotBeDirectoryPath1 := "/ab/c"
		shouldNotBeDirectoryPath2 := "/a"

		err := storeDriver.PutContent(context.Background(), testFile, []byte("file contents"))
		So(err, ShouldBeNil)

		fileInfo, err := storeDriver.Stat(context.Background(), testFile)
		So(err, ShouldBeNil)

		So(fileInfo.IsDir(), ShouldBeFalse)

		fileInfo, err = storeDriver.Stat(context.Background(), shouldBeDirectoryPath1)
		So(err, ShouldBeNil)
		So(fileInfo.IsDir(), ShouldBeTrue)

		fileInfo, err = storeDriver.Stat(context.Background(), shouldBeDirectoryPath2)
		So(err, ShouldBeNil)
		So(fileInfo.IsDir(), ShouldBeTrue)

		fileInfo, err = storeDriver.Stat(context.Background(), shouldNotBeDirectoryPath1)
		// err should actually be storageDriver.PathNotFoundError but it's nil
		So(err, ShouldBeNil)
		// should be false instead
		So(fileInfo.IsDir(), ShouldBeTrue)

		fileInfo, err = storeDriver.Stat(context.Background(), shouldNotBeDirectoryPath2)
		// err should actually be storageDriver.PathNotFoundError but it's nils
		So(err, ShouldBeNil)
		// should be false instead
		So(fileInfo.IsDir(), ShouldBeTrue)
	})
}

func TestGetOCIReferrers(t *testing.T) {
	tskip.SkipS3(t)

	repo := "zot-test"

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	tdir := t.TempDir()
	testDir := path.Join("/oci-repo-test", uuid.String())

	_, imgStore, _ := createObjectsStore(testDir, tdir, true)

	Convey("Upload test image", t, func(c C) {
		image := CreateDefaultImage()

		manifest := image.Manifest
		cfg := image.Config
		layers := image.Layers

		for _, content := range layers {
			upload, err := imgStore.NewBlobUpload(repo)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)

			blob, err := imgStore.PutBlobChunkStreamed(repo, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			blobDigest1 := digest
			So(blobDigest1, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload(repo, upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)
		}

		// upload config blob
		cblob, err := json.Marshal(cfg)
		So(err, ShouldBeNil)

		buf := bytes.NewBuffer(cblob)
		buflen := buf.Len()
		digest := godigest.FromBytes(cblob)

		_, clen, err := imgStore.FullBlobUpload(repo, buf, digest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, buflen)

		// upload manifest
		mblob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		mbuf := bytes.NewBuffer(mblob)
		mbuflen := mbuf.Len()
		mdigest := godigest.FromBytes(mblob)

		d, _, err := imgStore.PutImageManifest(repo, "1.0", ispec.MediaTypeImageManifest, mbuf.Bytes())
		So(d, ShouldEqual, mdigest)
		So(err, ShouldBeNil)

		body := []byte("this is an artifact")
		digest = godigest.FromBytes(body)
		buf = bytes.NewBuffer(body)
		buflen = buf.Len()

		_, n, err := imgStore.FullBlobUpload(repo, buf, digest)
		So(err, ShouldBeNil)
		So(n, ShouldEqual, buflen)

		Convey("Get OCI Referrers - application/vnd.oci.image.manifest.v1+json", func(c C) {
			artifactType := "application/vnd.example.icecream.v1"
			// push artifact config blob
			configBody := []byte("{}")
			configDigest := godigest.FromBytes(configBody)
			configBuf := bytes.NewBuffer(configBody)
			configBufLen := configBuf.Len()

			_, n, err := imgStore.FullBlobUpload(repo, configBuf, configDigest)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, configBufLen)

			artifactManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config: ispec.Descriptor{
					MediaType: artifactType,
					Size:      int64(configBufLen),
					Digest:    configDigest,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/octet-stream",
						Size:      int64(buflen),
						Digest:    digest,
					},
				},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Size:      int64(mbuflen),
					Digest:    mdigest,
				},
			}

			artifactManifest.SchemaVersion = 2

			manBuf, err := json.Marshal(artifactManifest)
			So(err, ShouldBeNil)

			manBufLen := len(manBuf)
			manDigest := godigest.FromBytes(manBuf)

			_, _, err = imgStore.PutImageManifest(repo, manDigest.Encoded(), ispec.MediaTypeImageManifest, manBuf)
			So(err, ShouldBeNil)

			index, err := imgStore.GetReferrers(repo, mdigest, []string{artifactType})
			So(err, ShouldBeNil)
			So(index, ShouldNotBeEmpty)
			So(index.Manifests[0].ArtifactType, ShouldEqual, artifactType)
			So(index.Manifests[0].MediaType, ShouldEqual, ispec.MediaTypeImageManifest)
			So(index.Manifests[0].Size, ShouldEqual, manBufLen)
			So(index.Manifests[0].Digest, ShouldEqual, manDigest)
		})
	})
}

func TestNegativeCasesObjectsStorage(t *testing.T) {
	tskip.SkipS3(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	tdir := t.TempDir()
	testDir := path.Join("/oci-repo-test", uuid.String())

	Convey("With dedupe", t, func(c C) {
		storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
		defer cleanupStorage(storeDriver, testDir)

		Convey("Invalid repo name", func(c C) {
			// Validate repo should fail if repo name does not match spec
			_, err := imgStore.ValidateRepo(".")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			_, err = imgStore.ValidateRepo("..")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			_, err = imgStore.ValidateRepo("_test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			_, err = imgStore.ValidateRepo(".test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			_, err = imgStore.ValidateRepo("-test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			// Init repo should fail if repo name does not match spec
			err = imgStore.InitRepo(".")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			err = imgStore.InitRepo("..")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			err = imgStore.InitRepo("_test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			err = imgStore.InitRepo(".test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

			err = imgStore.InitRepo("-test-dir")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		})

		Convey("Invalid validate repo", func(c C) {
			So(imgStore.InitRepo(testImage), ShouldBeNil)
			objects, err := storeDriver.List(context.Background(), path.Join(imgStore.RootDir(), testImage))
			So(err, ShouldBeNil)

			for _, object := range objects {
				t.Logf("Removing object: %s", object)
				err := storeDriver.Delete(context.Background(), object)
				So(err, ShouldBeNil)
			}

			_, err = imgStore.ValidateRepo(testImage)
			So(err, ShouldNotBeNil)
			_, err = imgStore.GetRepositories()
			So(err, ShouldBeNil)
		})

		Convey("Unable to create subpath cache db", func(c C) {
			bucket := zotStorageTest
			endpoint := os.Getenv("S3MOCK_ENDPOINT")

			storageDriverParams := config.GlobalStorageConfig{
				StorageConfig: config.StorageConfig{
					Dedupe:        true,
					RootDirectory: t.TempDir(),
					RemoteCache:   false,
				},
				SubPaths: map[string]config.StorageConfig{
					"/a": {
						Dedupe:        true,
						RootDirectory: t.TempDir(),
						StorageDriver: map[string]any{
							"rootDir":        "/a",
							"name":           "s3",
							"region":         s3Region,
							"bucket":         bucket,
							"regionendpoint": endpoint,
							"accesskey":      "minioadmin",
							"secretkey":      "minioadmin",
							"secure":         false,
							"skipverify":     false,
						},
						RemoteCache: false,
					},
				},
			}
			conf := config.New()
			conf.Storage = storageDriverParams
			controller := api.NewController(conf)
			So(controller, ShouldNotBeNil)

			err = controller.InitImageStore()
			So(err, ShouldBeNil)
		})

		Convey("Invalid get image tags", func(c C) {
			So(imgStore.InitRepo(testImage), ShouldBeNil)

			So(storeDriver.Move(context.Background(), path.Join(testDir, testImage, "index.json"),
				path.Join(testDir, testImage, "blobs")), ShouldBeNil)

			ok, _ := imgStore.ValidateRepo(testImage)
			So(ok, ShouldBeFalse)

			_, err = imgStore.GetImageTags(testImage)
			So(err, ShouldNotBeNil)

			So(storeDriver.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)

			So(imgStore.InitRepo(testImage), ShouldBeNil)
			So(storeDriver.PutContent(context.Background(), path.Join(testDir, testImage, "index.json"), []byte{}), ShouldBeNil)
			_, err = imgStore.GetImageTags(testImage)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Without dedupe", t, func(c C) {
		tdir := t.TempDir()

		storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, false)
		defer cleanupStorage(storeDriver, testDir)

		Convey("Invalid get image manifest", func(c C) {
			So(imgStore.InitRepo(testImage), ShouldBeNil)
			So(storeDriver.Delete(context.Background(), path.Join(testDir, testImage, "index.json")), ShouldBeNil)
			_, _, _, err = imgStore.GetImageManifest(testImage, "")
			So(err, ShouldNotBeNil)
			So(storeDriver.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)
			So(imgStore.InitRepo(testImage), ShouldBeNil)
			So(storeDriver.PutContent(context.Background(), path.Join(testDir, testImage, "index.json"), []byte{}), ShouldBeNil)
			_, _, _, err = imgStore.GetImageManifest(testImage, "")
			So(err, ShouldNotBeNil)
		})

		Convey("Invalid validate repo", func(c C) {
			So(imgStore, ShouldNotBeNil)

			So(imgStore.InitRepo(testImage), ShouldBeNil)
			So(storeDriver.Delete(context.Background(), path.Join(testDir, testImage, "index.json")), ShouldBeNil)
			_, err = imgStore.ValidateRepo(testImage)
			So(err, ShouldNotBeNil)
			So(storeDriver.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)
			So(imgStore.InitRepo(testImage), ShouldBeNil)
			So(storeDriver.Move(context.Background(), path.Join(testDir, testImage, "index.json"),
				path.Join(testDir, testImage, "_index.json")), ShouldBeNil)

			ok, err := imgStore.ValidateRepo(testImage)
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("Invalid finish blob upload", func(c C) {
			So(imgStore, ShouldNotBeNil)

			So(imgStore.InitRepo(testImage), ShouldBeNil)
			upload, err := imgStore.NewBlobUpload(testImage)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)

			blob, err := imgStore.PutBlobChunk(testImage, upload, 0, int64(buflen), buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			src := imgStore.BlobUploadPath(testImage, upload)
			stwr, err := storeDriver.Writer(context.Background(), src, true)
			So(err, ShouldBeNil)

			_, err = stwr.Write([]byte("another-chunk-of-data"))
			So(err, ShouldBeNil)

			err = stwr.Close()
			So(err, ShouldBeNil)

			err = imgStore.FinishBlobUpload(testImage, upload, buf, digest)
			So(err, ShouldNotBeNil)
		})

		Convey("Test storage driver errors", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				ListFn: func(ctx context.Context, path string) ([]string, error) {
					return []string{testImage}, errS3
				},
				MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
					return errS3
				},
				GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
					return []byte{}, errS3
				},
				PutContentFn: func(ctx context.Context, path string, content []byte) error {
					return errS3
				},
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, errS3
				},
				ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("")), errS3
				},
				WalkFn: func(ctx context.Context, path string, f driver.WalkFn, options ...func(*driver.WalkOptions)) error {
					return errS3
				},
				StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{}, errS3
				},
				DeleteFn: func(ctx context.Context, path string) error {
					return errS3
				},
			})
			So(imgStore, ShouldNotBeNil)

			So(imgStore.InitRepo(testImage), ShouldNotBeNil)
			_, err := imgStore.ValidateRepo(testImage)
			So(err, ShouldNotBeNil)

			upload, err := imgStore.NewBlobUpload(testImage)
			So(err, ShouldNotBeNil)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)

			_, err = imgStore.PutBlobChunk(testImage, upload, 0, int64(buflen), buf)
			So(err, ShouldNotBeNil)

			err = imgStore.FinishBlobUpload(testImage, upload, buf, digest)
			So(err, ShouldNotBeNil)

			err = imgStore.DeleteBlob(testImage, digest)
			So(err, ShouldNotBeNil)

			err = imgStore.DeleteBlobUpload(testImage, upload)
			So(err, ShouldNotBeNil)

			err = imgStore.DeleteImageManifest(testImage, "1.0", false)
			So(err, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(testImage, "1.0", "application/json", []byte{})
			So(err, ShouldNotBeNil)

			_, err = imgStore.PutBlobChunkStreamed(testImage, upload, bytes.NewBufferString(testImage))
			So(err, ShouldNotBeNil)

			_, _, err = imgStore.FullBlobUpload(testImage, bytes.NewBuffer([]byte{}), "inexistent")
			So(err, ShouldNotBeNil)

			_, _, err = imgStore.CheckBlob(testImage, digest)
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.StatBlob(testImage, digest)
			So(err, ShouldNotBeNil)
		})

		Convey("Test ValidateRepo", func(c C) {
			tdir := t.TempDir()

			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				ListFn: func(ctx context.Context, path string) ([]string, error) {
					return []string{testImage, testImage}, errS3
				},
			})

			_, err := imgStore.ValidateRepo(testImage)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetRepositories", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WalkFn: func(ctx context.Context, path string, f driver.WalkFn, options ...func(*driver.WalkOptions)) error {
					return f(new(mocks.FileInfoMock))
				},
			})
			repos, err := imgStore.GetRepositories()
			So(repos, ShouldBeEmpty)
			So(err, ShouldBeNil)
		})

		Convey("Test DeleteImageManifest", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
					return []byte{}, errS3
				},
			})
			err := imgStore.DeleteImageManifest(testImage, "1.0", false)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetIndexContent", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
					return []byte{}, driver.PathNotFoundError{}
				},
			})
			_, err := imgStore.GetIndexContent(testImage)
			So(err, ShouldNotBeNil)
		})

		Convey("Test DeleteImageManifest2", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{})
			err := imgStore.DeleteImageManifest(testImage, "1.0", false)
			So(err, ShouldNotBeNil)
		})

		Convey("Test NewBlobUpload", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errS3
				},
			})
			_, err := imgStore.NewBlobUpload(testImage)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetBlobUpload", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errS3
				},
			})
			_, err := imgStore.GetBlobUpload(testImage, "uuid")
			So(err, ShouldNotBeNil)
		})

		Convey("Test BlobUploadInfo", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errS3
				},
			})
			_, err := imgStore.BlobUploadInfo(testImage, "uuid")
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunkStreamed", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, errS3
				},
			})
			_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunkStreamed2", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{WriteFn: func(b []byte) (int, error) {
						return 0, errS3
					}}, errS3
				},
			})
			_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunk", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, errS3
				},
			})
			_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunk2", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(b []byte) (int, error) {
							return 0, errS3
						},
						CancelFn: func() error {
							return errS3
						},
					}, nil
				},
			})
			_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunk3", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(b []byte) (int, error) {
							return 0, errS3
						},
					}, errS3
				},
			})
			_, err := imgStore.PutBlobChunk(testImage, "uuid", 12, 100, io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test PutBlobChunk4", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, driver.PathNotFoundError{}
				},
			})
			_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, io.NopCloser(strings.NewReader("")))
			So(err, ShouldNotBeNil)
		})

		Convey("Test FinishBlobUpload", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						CommitFn: func() error {
							return errS3
						},
					}, nil
				},
			})
			d := godigest.FromBytes([]byte("test"))
			err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FinishBlobUpload2", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						CloseFn: func() error {
							return errS3
						},
					}, nil
				},
			})
			d := godigest.FromBytes([]byte("test"))
			err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FinishBlobUpload3", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return nil, errS3
				},
			})
			d := godigest.FromBytes([]byte("test"))
			err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FinishBlobUpload4", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
					return errS3
				},
			})
			d := godigest.FromBytes([]byte(""))
			err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FullBlobUpload", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, errS3
				},
			})
			d := godigest.FromBytes([]byte(""))
			_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FullBlobUpload2", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{})
			d := godigest.FromBytes([]byte(" "))
			_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test FullBlobUpload3", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
					return errS3
				},
			})
			d := godigest.FromBytes([]byte(""))
			_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetBlob", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("")), errS3
				},
			})
			d := godigest.FromBytes([]byte(""))
			_, _, err := imgStore.GetBlob(testImage, d, "")
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetBlobContent", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
					return []byte{}, errS3
				},
			})

			d := godigest.FromBytes([]byte(""))
			_, err := imgStore.GetBlobContent(testImage, d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test DeleteBlob", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
				DeleteFn: func(ctx context.Context, path string) error {
					return errS3
				},
			})
			d := godigest.FromBytes([]byte(""))
			err := imgStore.DeleteBlob(testImage, d)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GetReferrers", func(c C) {
			imgStore = createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{})
			d := godigest.FromBytes([]byte(""))
			_, err := imgStore.GetReferrers(testImage, d, []string{"application/image"})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrRepoBadVersion)
		})
	})
}

func TestS3Dedupe(t *testing.T) {
	tskip.SkipS3(t)
	tskip.SkipDynamo(t)
	Convey("Dedupe", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
		defer cleanupStorage(storeDriver, testDir)

		// manifest1
		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := digest
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize1, err := imgStore.CheckBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize1, _, err = imgStore.StatBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize1, err := imgStore.GetBlob("dedupe1", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe1", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", manifestDigest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest2 := digest
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest)
		So(err, ShouldBeNil)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)

		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		blobContent, err := imgStore.GetBlobContent("dedupe2", digest)
		So(err, ShouldBeNil)
		So(len(blobContent), ShouldBeGreaterThan, 0)
		So(checkBlobSize1, ShouldEqual, len(blobContent))
		So(getBlobSize1, ShouldEqual, len(blobContent))

		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest = ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}
		manifest.SchemaVersion = 2
		manifestBuf, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest2 := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest,
			manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", manifestDigest2.String())
		So(err, ShouldBeNil)

		fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
			blobDigest1.Encoded()))
		So(err, ShouldBeNil)

		fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
			blobDigest2.Encoded()))
		So(err, ShouldBeNil)

		// original blob should have the real content of blob
		So(fi1.Size(), ShouldNotEqual, fi2.Size())
		So(fi1.Size(), ShouldBeGreaterThan, 0)
		// deduped blob should be of size 0
		So(fi2.Size(), ShouldEqual, 0)

		Convey("delete blobs from storage/cache should work when dedupe is true", func() {
			So(blobDigest1, ShouldEqual, blobDigest2)

			// to not trigger BlobInUse err, delete manifest first
			err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
			So(err, ShouldBeNil)

			// delete tag, but not manifest
			err = imgStore.DeleteImageManifest("dedupe2", "1.0", false)
			So(err, ShouldBeNil)

			// delete should succeed as the manifest was deleted
			err = imgStore.DeleteBlob("dedupe1", blobDigest1)
			So(err, ShouldBeNil)

			// delete should fail, as the blob is referenced by an untagged manifest
			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldEqual, zerr.ErrBlobReferenced)

			err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldBeNil)
		})

		Convey("Check that delete blobs moves the real content to the next contenders", func() {
			// to not trigger BlobInUse err, delete manifest first
			err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
			So(err, ShouldBeNil)

			// if we delete blob1, the content should be moved to blob2
			err = imgStore.DeleteBlob("dedupe1", blobDigest1)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
				blobDigest1.Encoded()))
			So(err, ShouldNotBeNil)

			fi2, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)

			So(fi2.Size(), ShouldBeGreaterThan, 0)
			// the second blob should now be equal to the deleted blob.
			So(fi2.Size(), ShouldEqual, fi1.Size())

			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldNotBeNil)
		})

		Convey("Check backward compatibility - switch dedupe to false", func() {
			/* copy cache to the new storage with dedupe false (doing this because we
			already have a cache object holding the lock on cache db file) */
			input, err := os.ReadFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName))
			So(err, ShouldBeNil)

			tdir = t.TempDir()

			err = os.WriteFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName), input, 0o600)
			So(err, ShouldBeNil)

			storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, false)
			defer cleanupStorage(storeDriver, testDir)

			// manifest3 without dedupe
			upload, err = imgStore.NewBlobUpload("dedupe3")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content = []byte("test-data3")
			buf = bytes.NewBuffer(content)
			buflen = buf.Len()
			digest = godigest.FromBytes(content)

			blob, err = imgStore.PutBlobChunkStreamed("dedupe3", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			blobDigest2 := digest
			So(blobDigest2, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("dedupe3", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			_, _, err = imgStore.CheckBlob("dedupe3", digest)
			So(err, ShouldBeNil)

			// check that we retrieve the real dedupe2/blob (which is deduped earlier - 0 size) when switching to dedupe false
			blobReadCloser, getBlobSize2, err = imgStore.GetBlob("dedupe2", digest,
				"application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			So(getBlobSize1, ShouldEqual, getBlobSize2)

			err = blobReadCloser.Close()
			So(err, ShouldBeNil)

			_, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest)
			So(err, ShouldBeNil)
			So(checkBlobSize2, ShouldBeGreaterThan, 0)
			So(checkBlobSize2, ShouldEqual, getBlobSize2)

			_, getBlobSize3, err := imgStore.GetBlob("dedupe3", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			So(getBlobSize1, ShouldEqual, getBlobSize3)

			blobContent, err := imgStore.GetBlobContent("dedupe3", digest)
			So(err, ShouldBeNil)
			So(getBlobSize1, ShouldEqual, len(blobContent))

			_, checkBlobSize3, err := imgStore.CheckBlob("dedupe3", digest)
			So(err, ShouldBeNil)
			So(checkBlobSize3, ShouldBeGreaterThan, 0)
			So(checkBlobSize3, ShouldEqual, getBlobSize3)

			cblob, cdigest = GetRandomImageConfig()
			_, clen, err = imgStore.FullBlobUpload("dedupe3", bytes.NewReader(cblob), cdigest)
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))

			hasBlob, _, err = imgStore.CheckBlob("dedupe3", cdigest)
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

			manifest = ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: "application/vnd.oci.image.config.v1+json",
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(buflen),
					},
				},
			}
			manifest.SchemaVersion = 2
			manifestBuf, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			manifestDigest3 := godigest.FromBytes(manifestBuf)
			_, _, err = imgStore.PutImageManifest("dedupe3", "1.0", ispec.MediaTypeImageManifest,
				manifestBuf)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest("dedupe3", manifestDigest3.String())
			So(err, ShouldBeNil)

			fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
				blobDigest1.Encoded()))
			So(err, ShouldBeNil)

			fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest1.Encoded()))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldEqual, 0)

			fi3, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe3", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)

			// the new blob with dedupe false should be equal with the origin blob from dedupe1
			So(fi1.Size(), ShouldEqual, fi3.Size())

			Convey("delete blobs from storage/cache should work when dedupe is false", func() {
				So(blobDigest1, ShouldEqual, blobDigest2)
				// to not trigger BlobInUse err, delete manifest first
				err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteImageManifest("dedupe3", manifestDigest3.String(), false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe1", blobDigest1)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe2", blobDigest2)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe3", blobDigest2)
				So(err, ShouldBeNil)
			})

			Convey("rebuild s3 dedupe index from true to false", func() { //nolint: dupl
				taskScheduler := runAndGetScheduler()
				defer taskScheduler.Shutdown()

				storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), false)
				defer cleanupStorage(storeDriver, testDir)

				// rebuild with dedupe false, should have all blobs with content
				imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
				// wait until rebuild finishes

				time.Sleep(10 * time.Second)

				taskScheduler.Shutdown()

				fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
					blobDigest1.Encoded()))
				So(fi1.Size(), ShouldBeGreaterThan, 0)
				So(err, ShouldBeNil)

				fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
					blobDigest2.Encoded()))
				So(err, ShouldBeNil)
				So(fi2.Size(), ShouldEqual, fi1.Size())

				blobContent, err := imgStore.GetBlobContent("dedupe2", blobDigest2)
				So(err, ShouldBeNil)
				So(len(blobContent), ShouldEqual, fi1.Size())

				Convey("rebuild s3 dedupe index from false to true", func() {
					taskScheduler := runAndGetScheduler()
					defer taskScheduler.Shutdown()

					storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
					defer cleanupStorage(storeDriver, testDir)

					// rebuild with dedupe false, should have all blobs with content
					imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
					// wait until rebuild finishes

					time.Sleep(10 * time.Second)

					taskScheduler.Shutdown()

					fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
						blobDigest2.Encoded()))
					So(err, ShouldBeNil)
					So(fi2.Size(), ShouldEqual, 0)

					blobContent, err := imgStore.GetBlobContent("dedupe2", blobDigest2)
					So(err, ShouldBeNil)
					So(len(blobContent), ShouldBeGreaterThan, 0)
				})
			})
		})
	})

	Convey("Dedupe with dynamodb", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, _ := createObjectsStoreDynamo(testDir, tdir, true, tdir)
		defer cleanupStorage(storeDriver, testDir)

		// manifest1
		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := digest
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, checkBlobSize1, err := imgStore.CheckBlob("dedupe1", digest)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize1, err := imgStore.GetBlob("dedupe1", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe1", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", manifestDigest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest2 := digest
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest)
		So(err, ShouldBeNil)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)

		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest = ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}
		manifest.SchemaVersion = 2
		manifestBuf, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest2 := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest,
			manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", manifestDigest2.String())
		So(err, ShouldBeNil)

		fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
			blobDigest1.Encoded()))
		So(err, ShouldBeNil)

		fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
			blobDigest2.Encoded()))
		So(err, ShouldBeNil)

		// original blob should have the real content of blob
		So(fi1.Size(), ShouldNotEqual, fi2.Size())
		So(fi1.Size(), ShouldBeGreaterThan, 0)
		// deduped blob should be of size 0
		So(fi2.Size(), ShouldEqual, 0)

		Convey("delete blobs from storage/cache should work when dedupe is true", func() {
			So(blobDigest1, ShouldEqual, blobDigest2)

			// to not trigger BlobInUse err, delete manifest first
			err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
			So(err, ShouldBeNil)

			// delete tag, but not manifest
			err = imgStore.DeleteImageManifest("dedupe2", "1.0", false)
			So(err, ShouldBeNil)

			// Delete should succeed as the manifest was deleted
			err = imgStore.DeleteBlob("dedupe1", blobDigest1)
			So(err, ShouldBeNil)

			// Delete should fail, as the blob is referenced by an untagged manifest
			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldEqual, zerr.ErrBlobReferenced)

			err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldBeNil)
		})

		Convey("rebuild s3 dedupe index from true to false", func() { //nolint: dupl
			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), false)
			defer cleanupStorage(storeDriver, testDir)

			// rebuild with dedupe false, should have all blobs with content
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
			// wait until rebuild finishes

			time.Sleep(10 * time.Second)

			taskScheduler.Shutdown()

			fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
				blobDigest1.Encoded()))
			So(fi1.Size(), ShouldBeGreaterThan, 0)
			So(err, ShouldBeNil)

			fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldEqual, fi1.Size())

			blobContent, err := imgStore.GetBlobContent("dedupe2", blobDigest2)
			So(err, ShouldBeNil)
			So(len(blobContent), ShouldEqual, fi1.Size())

			Convey("delete blobs from storage/cache should work when dedupe is false", func() {
				So(blobDigest1, ShouldEqual, blobDigest2)

				// to not trigger BlobInUse err, delete manifest first
				err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
				So(err, ShouldBeNil)

				// delete tag, but not manifest
				err = imgStore.DeleteImageManifest("dedupe2", "1.0", false)
				So(err, ShouldBeNil)

				// delete should succeed as the manifest was deleted
				err = imgStore.DeleteBlob("dedupe1", blobDigest1)
				So(err, ShouldBeNil)

				// delete should fail, as the blob is referenced by an untagged manifest
				err = imgStore.DeleteBlob("dedupe2", blobDigest2)
				So(err, ShouldEqual, zerr.ErrBlobReferenced)

				err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe2", blobDigest2)
				So(err, ShouldBeNil)
			})

			Convey("rebuild s3 dedupe index from false to true", func() {
				taskScheduler := runAndGetScheduler()
				defer taskScheduler.Shutdown()

				storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
				defer cleanupStorage(storeDriver, testDir)

				// rebuild with dedupe false, should have all blobs with content
				imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
				// wait until rebuild finishes

				time.Sleep(10 * time.Second)

				taskScheduler.Shutdown()

				fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
					blobDigest2.Encoded()))
				So(err, ShouldBeNil)
				So(fi2.Size(), ShouldEqual, 0)

				blobContent, err := imgStore.GetBlobContent("dedupe2", blobDigest2)
				So(err, ShouldBeNil)
				So(len(blobContent), ShouldBeGreaterThan, 0)
			})
		})

		Convey("Check that delete blobs moves the real content to the next contenders", func() {
			// if we delete blob1, the content should be moved to blob2
			// to not trigger BlobInUse err, delete manifest first
			err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest("dedupe2", manifestDigest2.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlob("dedupe1", blobDigest1)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
				blobDigest1.Encoded()))
			So(err, ShouldNotBeNil)

			fi2, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)

			So(fi2.Size(), ShouldBeGreaterThan, 0)
			// the second blob should now be equal to the deleted blob.
			So(fi2.Size(), ShouldEqual, fi1.Size())

			err = imgStore.DeleteBlob("dedupe2", blobDigest2)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldNotBeNil)
		})
	})
}

func TestRebuildDedupeIndex(t *testing.T) {
	tskip.SkipS3(t)

	Convey("Push images with dedupe true", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
		defer cleanupStorage(storeDriver, testDir)

		// push image1
		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)

		blobDigest1 := digest

		_, blen, err := imgStore.FullBlobUpload("dedupe1", buf, digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, buflen)

		hasBlob, blen1, err := imgStore.CheckBlob("dedupe1", digest)
		So(blen1, ShouldEqual, buflen)
		So(hasBlob, ShouldEqual, true)
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, clen, err = imgStore.CheckBlob("dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)
		So(clen, ShouldEqual, len(cblob))

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest = godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe1", digest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", digest.String())
		So(err, ShouldBeNil)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blobDigest2 := digest

		_, blen, err = imgStore.FullBlobUpload("dedupe2", buf, digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, buflen)

		hasBlob, blen1, err = imgStore.CheckBlob("dedupe2", digest)
		So(blen1, ShouldEqual, buflen)
		So(hasBlob, ShouldEqual, true)
		So(err, ShouldBeNil)

		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, clen, err = imgStore.CheckBlob("dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)
		So(clen, ShouldEqual, len(cblob))

		digest = godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe2", digest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", digest.String())
		So(err, ShouldBeNil)

		configFi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
			cdigest.Encoded()))
		So(err, ShouldBeNil)

		configFi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
			cdigest.Encoded()))
		So(err, ShouldBeNil)

		fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256",
			blobDigest1.Encoded()))
		So(err, ShouldBeNil)

		fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
			blobDigest2.Encoded()))
		So(err, ShouldBeNil)

		// original blob should have the real content of blob
		So(fi1.Size(), ShouldNotEqual, fi2.Size())
		So(fi1.Size(), ShouldBeGreaterThan, 0)
		// deduped blob should be of size 0
		So(fi2.Size(), ShouldEqual, 0)

		So(configFi1.Size(), ShouldNotEqual, configFi2.Size())
		So(configFi1.Size(), ShouldBeGreaterThan, 0)
		// deduped blob should be of size 0
		So(configFi2.Size(), ShouldEqual, 0)

		Convey("Intrerrupt rebuilding and restart, checking idempotency", func() {
			for i := range 10 {
				log := log.NewTestLogger()
				metrics := monitoring.NewMetricsServer(false, log)
				taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
				taskScheduler.RateLimit = 1 * time.Millisecond

				taskScheduler.RunScheduler()
				defer taskScheduler.Shutdown()

				storeDriver, imgStore, _ = createObjectsStore(testDir, t.TempDir(), false)
				defer cleanupStorage(storeDriver, testDir)

				// rebuild with dedupe false, should have all blobs with content
				imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

				sleepValue := i * 5
				time.Sleep(time.Duration(sleepValue) * time.Millisecond)

				taskScheduler.Shutdown()
			}

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(10 * time.Second)

			taskScheduler.Shutdown()

			fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldEqual, fi1.Size())

			configFi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				cdigest.Encoded()))
			So(err, ShouldBeNil)
			So(configFi2.Size(), ShouldEqual, configFi1.Size())

			// now from dedupe false to true
			for i := range 10 {
				log := log.NewTestLogger()
				metrics := monitoring.NewMetricsServer(false, log)
				taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
				taskScheduler.RateLimit = 1 * time.Millisecond

				taskScheduler.RunScheduler()
				defer taskScheduler.Shutdown()

				storeDriver, imgStore, _ = createObjectsStore(testDir, t.TempDir(), true)
				defer cleanupStorage(storeDriver, testDir)

				// rebuild with dedupe false, should have all blobs with content
				imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

				sleepValue := i * 5
				time.Sleep(time.Duration(sleepValue) * time.Millisecond)

				taskScheduler.Shutdown()
			}

			taskScheduler = runAndGetScheduler()
			defer taskScheduler.Shutdown()

			// rebuild with dedupe false, should have all blobs with content
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(10 * time.Second)

			taskScheduler.Shutdown()

			fi2, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldNotEqual, fi1.Size())
			So(fi2.Size(), ShouldEqual, 0)

			configFi2, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				cdigest.Encoded()))
			So(err, ShouldBeNil)
			So(configFi2.Size(), ShouldNotEqual, configFi1.Size())
			So(configFi2.Size(), ShouldEqual, 0)
		})

		Convey("Trigger ErrDedupeRebuild because cache is nil", func() {
			storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
			defer cleanupStorage(storeDriver, testDir)

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(3 * time.Second)
		})

		Convey("Rebuild dedupe index already rebuilt", func() {
			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
			defer cleanupStorage(storeDriver, testDir)

			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(5 * time.Second)
		})

		Convey("Trigger Stat error while getting original blob", func() {
			tdir := t.TempDir()

			storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, false)
			defer cleanupStorage(storeDriver, testDir)

			// remove original blob
			err := storeDriver.PutContent(context.Background(), fi1.Path(), []byte{})
			So(err, ShouldBeNil)

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(5 * time.Second)
		})

		Convey("Trigger ErrDedupeRebuild while statting original blob", func() {
			// remove original blob
			err := storeDriver.Delete(context.Background(), fi1.Path())
			So(err, ShouldBeNil)

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
			defer cleanupStorage(storeDriver, testDir)

			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(5 * time.Second)
		})

		Convey("Trigger ErrDedupeRebuild when original blob has 0 size", func() {
			// remove original blob
			err := storeDriver.PutContent(context.Background(), fi1.Path(), []byte{})
			So(err, ShouldBeNil)

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
			defer cleanupStorage(storeDriver, testDir)

			// rebuild with dedupe false, should have all blobs with content
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(5 * time.Second)
		})

		Convey("Trigger GetNextDigestWithBlobPaths path not found err", func() {
			tdir := t.TempDir()

			storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
			defer cleanupStorage(storeDriver, testDir)

			// remove rootDir
			err := storeDriver.Delete(context.Background(), imgStore.RootDir())
			So(err, ShouldBeNil)

			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			// rebuild with dedupe false, should have all blobs with content
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(5 * time.Second)
		})

		Convey("Rebuild from true to false", func() {
			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), false)
			defer cleanupStorage(storeDriver, testDir)

			// rebuild with dedupe false, should have all blobs with content
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

			// wait until rebuild finishes
			time.Sleep(10 * time.Second)

			taskScheduler.Shutdown()

			fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256",
				blobDigest2.Encoded()))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldEqual, fi1.Size())
		})
	})
}

func TestNextRepositoryMockStoreDriver(t *testing.T) {
	testDir := t.TempDir()
	tdir := t.TempDir()

	// some s3 implementations (eg, digitalocean spaces) will return pathnotfounderror for walk but not list
	// This code cannot be reliably covered by end to end tests
	Convey("Trigger PathNotFound error when Walk() is called in GetNextRepository()", t, func() {
		imgStore := createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				return driver.PathNotFoundError{}
			},
		})

		processedRepos := make(map[string]struct{}, 0)
		processedRepos["testRepo"] = struct{}{}
		nextRepository, err := imgStore.GetNextRepository(processedRepos)
		So(err, ShouldBeNil)
		So(nextRepository, ShouldEqual, "")
	})
}

func TestRebuildDedupeMockStoreDriver(t *testing.T) {
	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	tdir := t.TempDir()

	validDigest := godigest.FromString("digest")

	// Helper function to generate standard OCI blob path
	blobPath := func(repo string, digest godigest.Digest) string {
		return fmt.Sprintf("%s/%s/%s/%s", repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
	}

	Convey("Trigger Stat error in getOriginalBlobFromDisk()", t, func() {
		imgStore := createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{}, errS3
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				return walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, false, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger GetContent error in restoreDedupedBlobs()", t, func() {
		imgStore := createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(0)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
			GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, false, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger GetContent error in restoreDedupedBlobs()", t, func() {
		imgStore := createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(0)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &mocks.FileWriterMock{}, errS3
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, false, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger Stat() error in restoreDedupedBlobs()", t, func() {
		imgStore := createMockStorage(testDir, tdir, false, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(10)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, errS3
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, false, duplicateBlobs)
		So(err, ShouldNotBeNil)

		Convey("Trigger Stat() error in dedupeBlobs()", func() {
			imgStore := createMockStorage(testDir, t.TempDir(), true, &mocks.StorageDriverMock{
				StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
					if path == blobPath("path/to", validDigest) {
						return &mocks.FileInfoMock{
							SizeFn: func() int64 {
								return int64(10)
							},
						}, nil
					}

					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(10)
						},
					}, errS3
				},
				WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
					_ = walkFn(&mocks.FileInfoMock{
						IsDirFn: func() bool {
							return false
						},
						PathFn: func() string {
							return blobPath("path/to", validDigest)
						},
					})
					_ = walkFn(&mocks.FileInfoMock{
						IsDirFn: func() bool {
							return false
						},
						PathFn: func() string {
							return blobPath("path/to/second", validDigest)
						},
					})

					return nil
				},
			})

			digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
			So(err, ShouldBeNil)

			err = imgStore.RunDedupeForDigest(context.TODO(), digest, false, duplicateBlobs)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Trigger PutContent() error in dedupeBlobs()", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(0)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("Trigger getOriginalBlob() error in dedupeBlobs()", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(0)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(0)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	//nolint: dupl
	Convey("Trigger Stat() error in dedupeBlobs()", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(10)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, errS3
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)

		err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger getNextDigestWithBlobPaths err", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			WalkFn: func(ctx context.Context, path string, f driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				return errS3
			},
		})

		_, _, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldNotBeNil)
	})

	Convey("Skip files with invalid algorithm directory", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				// File in blobs directory but with invalid algorithm name
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return fmt.Sprintf("path/to/%s/invalid-algo/digest-hash", ispec.ImageBlobsDir)
					},
				})

				return nil
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)
		// Should return empty digest because invalid algorithm directory is skipped
		So(digest.String(), ShouldEqual, "")
		So(duplicateBlobs, ShouldBeEmpty)
	})

	Convey("Skip files with invalid digest hash", t, func() {
		tdir := t.TempDir()
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				// File with valid algorithm but invalid hash format
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return fmt.Sprintf("path/to/%s/sha256/invalid-hash-format", ispec.ImageBlobsDir)
					},
				})

				return nil
			},
		})

		digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
		So(err, ShouldBeNil)
		// Should return empty digest because invalid hash format is skipped
		So(digest.String(), ShouldEqual, "")
		So(duplicateBlobs, ShouldBeEmpty)
	})

	Convey("Trigger cache errors", t, func() {
		storageDriverMockIfBranch := &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(0)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
		}

		storageDriverMockElseBranch := &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == blobPath("path/to", validDigest) {
					return &mocks.FileInfoMock{
						SizeFn: func() int64 {
							return int64(10)
						},
					}, nil
				}

				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return int64(10)
					},
				}, nil
			},
			WalkFn: func(ctx context.Context, path string, walkFn driver.WalkFn, options ...func(*driver.WalkOptions)) error {
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to", validDigest)
					},
				})
				_ = walkFn(&mocks.FileInfoMock{
					IsDirFn: func() bool {
						return false
					},
					PathFn: func() string {
						return blobPath("path/to/second", validDigest)
					},
				})

				return nil
			},
		}

		Convey("on original blob", func() {
			imgStore := createMockStorageWithMockCache(testDir, true, storageDriverMockIfBranch,
				&mocks.CacheMock{
					HasBlobFn: func(digest godigest.Digest, path string) bool {
						return false
					},
					PutBlobFn: func(digest godigest.Digest, path string) error {
						return errCache
					},
				})

			digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
			So(err, ShouldBeNil)

			err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
			So(err, ShouldNotBeNil)
		})

		Convey("on dedupe blob", func() {
			imgStore := createMockStorageWithMockCache(testDir, true, storageDriverMockIfBranch,
				&mocks.CacheMock{
					HasBlobFn: func(digest godigest.Digest, path string) bool {
						return false
					},
					PutBlobFn: func(digest godigest.Digest, path string) error {
						if path == blobPath("path/to", validDigest) {
							return errCache
						}

						return nil
					},
				})

			digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
			So(err, ShouldBeNil)

			err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
			So(err, ShouldNotBeNil)
		})

		Convey("on else branch", func() {
			imgStore := createMockStorageWithMockCache(testDir, true, storageDriverMockElseBranch,
				&mocks.CacheMock{
					HasBlobFn: func(digest godigest.Digest, path string) bool {
						return false
					},
					PutBlobFn: func(digest godigest.Digest, path string) error {
						return errCache
					},
				})

			digest, duplicateBlobs, err := imgStore.GetNextDigestWithBlobPaths([]string{"path/to"}, []godigest.Digest{})
			So(err, ShouldBeNil)

			err = imgStore.RunDedupeForDigest(context.TODO(), digest, true, duplicateBlobs)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestS3PullRange(t *testing.T) {
	tskip.SkipS3(t)

	Convey("Test against s3 image store", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
		defer cleanupStorage(storeDriver, testDir)

		// create a blob/layer
		upload, err := imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("0123456789")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		blob, err := imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("index", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		Convey("Without Dedupe", func() {
			reader, _, _, err := imgStore.GetBlobPartial("index", digest, "*/*", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "application/octet-stream", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 0, 100)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 0, 10)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 0, 0)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:1])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 0, 1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:2])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 2, 3)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[2:4])
			reader.Close()
		})

		Convey("With Dedupe", func() {
			// create a blob/layer with same content
			upload, err := imgStore.NewBlobUpload("dupindex")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			dupcontent := []byte("0123456789")
			buf := bytes.NewBuffer(dupcontent)
			buflen := buf.Len()
			digest := godigest.FromBytes(dupcontent)
			So(digest, ShouldNotBeNil)

			blob, err := imgStore.PutBlobChunkStreamed("dupindex", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("dupindex", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			reader, _, _, err := imgStore.GetBlobPartial("dupindex", digest, "*/*", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "application/octet-stream", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 0, 100)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 0, 10)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 0, 0)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:1])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 0, 1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:2])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 2, 3)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[2:4])
			reader.Close()

			// delete original blob
			err = imgStore.DeleteBlob("index", digest)
			So(err, ShouldBeNil)

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest, "*/*", 2, 3)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[2:4])
			reader.Close()
		})

		Convey("Negative cases", func() {
			_, _, _, err := imgStore.GetBlobPartial("index", "deadBEEF", "*/*", 0, -1)
			So(err, ShouldNotBeNil)

			content := []byte("invalid content")
			digest := godigest.FromBytes(content)

			_, _, _, err = imgStore.GetBlobPartial("index", digest, "*/*", 0, -1)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestS3ManifestImageIndex(t *testing.T) {
	tskip.SkipS3(t)

	Convey("Test against s3 image store", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
		defer cleanupStorage(storeDriver, testDir)

		// create a blob/layer
		upload, err := imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("this is a blob1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		blob, err := imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		bdgst1 := digest
		bsize1 := len(content)

		err = imgStore.FinishBlobUpload("index", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// upload image config blob
		upload, err = imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest := GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()
		blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("index", upload, buf, cdigest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// create a manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    bdgst1,
					Size:      int64(bsize1),
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest = godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		m1content := content
		_, _, err = imgStore.PutImageManifest("index", "test:1.0", ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		// create another manifest but upload using its sha256 reference

		// upload image config blob
		upload, err = imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest = GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()
		blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("index", upload, buf, cdigest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// create a manifest
		manifest = ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    bdgst1,
					Size:      int64(bsize1),
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest = godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		m2dgst := digest
		m2size := len(content)
		_, _, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		Convey("Image index", func() {
			// upload image config blob
			upload, err = imgStore.NewBlobUpload("index")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest = GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("index", upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			_, _, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			var index ispec.Index
			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    digest,
					Size:      int64(len(content)),
				},
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    m2dgst,
					Size:      int64(m2size),
				},
			}

			content, err = json.Marshal(index)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			index1dgst := digest
			_, _, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageIndex, content)
			So(err, ShouldBeNil)
			_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
			So(err, ShouldBeNil)

			// upload another image config blob
			upload, err = imgStore.NewBlobUpload("index")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest = GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("index", upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create another manifest
			manifest = ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			m4dgst := digest
			m4size := len(content)
			_, _, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    digest,
					Size:      int64(len(content)),
				},
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    m2dgst,
					Size:      int64(m2size),
				},
			}

			content, err = json.Marshal(index)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest("index", "test:index2", ispec.MediaTypeImageIndex, content)
			So(err, ShouldBeNil)
			_, _, _, err = imgStore.GetImageManifest("index", "test:index2")
			So(err, ShouldBeNil)

			Convey("List tags", func() {
				tags, err := imgStore.GetImageTags("index")
				So(err, ShouldBeNil)
				So(len(tags), ShouldEqual, 3)
				So(tags, ShouldContain, "test:1.0")
				So(tags, ShouldContain, "test:index1")
				So(tags, ShouldContain, "test:index2")
			})

			Convey("Another index with same manifest", func() {
				var index ispec.Index
				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    m4dgst,
						Size:      int64(m4size),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)

				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)

				_, _, err = imgStore.PutImageManifest("index", "test:index3", ispec.MediaTypeImageIndex, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index3")
				So(err, ShouldBeNil)
			})

			Convey("Another index using digest with same manifest", func() {
				var index ispec.Index
				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    m4dgst,
						Size:      int64(m4size),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)

				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				_, _, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageIndex, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", digest.String())
				So(err, ShouldBeNil)
			})

			Convey("Deleting an image index", func() {
				// delete manifest by tag should pass
				err := imgStore.DeleteImageManifest("index", "test:index3", false)
				So(err, ShouldNotBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)

				err = imgStore.DeleteImageManifest("index", "test:index1", false)
				So(err, ShouldBeNil)

				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldNotBeNil)

				_, _, _, err = imgStore.GetImageManifest("index", "test:index2")
				So(err, ShouldBeNil)
			})

			Convey("Deleting an image index by digest", func() {
				// delete manifest by tag should pass
				err := imgStore.DeleteImageManifest("index", "test:index3", false)
				So(err, ShouldNotBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)

				err = imgStore.DeleteImageManifest("index", index1dgst.String(), false)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldNotBeNil)

				_, _, _, err = imgStore.GetImageManifest("index", "test:index2")
				So(err, ShouldBeNil)
			})

			Convey("Update an index tag with different manifest", func() {
				// create a blob/layer
				upload, err := imgStore.NewBlobUpload("index")
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				content := []byte("this is another blob")
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)

				blob, err := imgStore.PutBlobChunkStreamed("index", upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload("index", upload, buf, digest)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				// create a manifest with same blob but a different tag
				manifest = ispec.Manifest{
					Config: ispec.Descriptor{
						MediaType: ispec.MediaTypeImageConfig,
						Digest:    cdigest,
						Size:      int64(len(cblob)),
					},
					Layers: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageLayer,
							Digest:    digest,
							Size:      int64(len(content)),
						},
					},
				}
				manifest.SchemaVersion = 2
				content, err = json.Marshal(manifest)
				So(err, ShouldBeNil)

				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				_, _, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", digest.String())
				So(err, ShouldBeNil)

				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    digest,
						Size:      int64(len(content)),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)

				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)

				_, _, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageIndex, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldBeNil)

				err = imgStore.DeleteImageManifest("index", "test:index1", false)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldNotBeNil)
			})

			Convey("Negative test cases", func() {
				Convey("Delete index", func() {
					cleanupStorage(storeDriver, path.Join(testDir, "index", "blobs",
						index1dgst.Algorithm().String(), index1dgst.Encoded()))

					err = imgStore.DeleteImageManifest("index", index1dgst.String(), false)
					So(err, ShouldNotBeNil)
					_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
					So(err, ShouldNotBeNil)
				})

				Convey("Corrupt index", func() {
					wrtr, err := storeDriver.Writer(context.Background(),
						path.Join(testDir, "index", "blobs",
							index1dgst.Algorithm().String(), index1dgst.Encoded()),
						false)
					So(err, ShouldBeNil)
					_, err = wrtr.Write([]byte("deadbeef"))
					So(err, ShouldBeNil)
					wrtr.Close()

					err = imgStore.DeleteImageManifest("index", index1dgst.String(), false)
					So(err, ShouldBeNil)
					_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
					So(err, ShouldNotBeNil)
				})

				Convey("Change media-type", func() {
					// previously a manifest, try writing an image index
					var index ispec.Index
					index.SchemaVersion = 2
					index.Manifests = []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    m4dgst,
							Size:      int64(m4size),
						},
					}

					content, err = json.Marshal(index)
					So(err, ShouldBeNil)

					digest = godigest.FromBytes(content)
					So(digest, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("index", "test:1.0", ispec.MediaTypeImageIndex, content)
					So(err, ShouldBeNil)

					// previously an image index, try writing a manifest
					_, _, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageManifest, m1content)
					So(err, ShouldBeNil)
				})
			})
		})
	})

	Convey("Test image index as artifact with subject against s3 image store", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		storeDriver, imgStore, _ := createObjectsStore(testDir, t.TempDir(), true)
		defer cleanupStorage(storeDriver, testDir)

		// create and upload a blob/layer
		// create and upload 2 configs
		// create and upload 2 manifests
		// index creation/testing is handled in the other conveys

		// layer blob
		content := []byte("this is a blob1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		bdigest := godigest.FromBytes(content)
		bsize := len(content)

		So(bdigest, ShouldNotBeNil)

		_, clen, err := imgStore.FullBlobUpload("index", buf, bdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, buflen)

		// first config
		cblob, cdigest := GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()

		_, clen, err = imgStore.FullBlobUpload("index", buf, cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, buflen)

		// first manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    bdigest,
					Size:      int64(bsize),
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		m1digest := godigest.FromBytes(content)
		So(m1digest, ShouldNotBeNil)

		m1size := len(content)

		_, _, err = imgStore.PutImageManifest("index", "test:1.0", ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		// second config
		cblob, cdigest = GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()

		_, clen, err = imgStore.FullBlobUpload("index", buf, cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, buflen)

		// second manifest
		manifest = ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    bdigest,
					Size:      int64(bsize),
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		m2digest := godigest.FromBytes(content)
		So(m2digest, ShouldNotBeNil)

		m2size := len(content)
		_, _, err = imgStore.PutImageManifest("index", m2digest.String(), ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		Convey("Put image index with valid subject", func() {
			// create an image index containing the 2nd manifest, having the 1st manifest as subject
			var index ispec.Index
			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    m2digest,
					Size:      int64(m2size),
				},
			}
			index.Subject = &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    m1digest,
				Size:      int64(m1size),
			}

			content, err := json.Marshal(index)
			So(err, ShouldBeNil)

			idigest := godigest.FromBytes(content)
			So(idigest, ShouldNotBeNil)

			digest1, digest2, err := imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageIndex, content)
			So(err, ShouldBeNil)
			So(digest1.String(), ShouldEqual, idigest.String())
			So(digest2.String(), ShouldEqual, m1digest.String())

			_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
			So(err, ShouldBeNil)
		})
	})
}

func TestS3DedupeErr(t *testing.T) {
	tskip.SkipS3(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	tdir := t.TempDir()

	storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
	defer cleanupStorage(storeDriver, testDir)

	Convey("Test DedupeBlob", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{})

		err = os.Remove(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName))
		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")

		// trigger unable to insert blob record
		err := imgStore.DedupeBlob("", digest, "", "")
		So(err, ShouldNotBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath string, destPath string) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		// trigger unable to rename blob
		err = imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldNotBeNil)

		// trigger retry
		err = imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on second store.Stat()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == "dst2" {
					return driver.FileInfoInternal{}, errS3
				}

				return driver.FileInfoInternal{}, nil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldBeNil)

		// error will be triggered in driver.SameFile()
		err = imgStore.DedupeBlob("", digest, "", "dst2")
		So(err, ShouldBeNil)
	})

	Convey("Test DedupeBlob - error on store.PutContent()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil //nolint:nilnil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "", "dst2")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on cache.PutBlob()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil //nolint:nilnil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on store.Delete()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			DeleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil //nolint:nilnil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "", "dst")
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on initRepo()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &mocks.FileWriterMock{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "", "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest)
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on store.PutContent()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "", "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest)
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on store.Stat()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "", "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on second store.Stat()", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("/src/dst", digest, "", "/repo1/dst1")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("/src/dst", digest, "", "/repo2/dst2")
		So(err, ShouldBeNil)

		// copy cache db to the new imagestore
		input, err := os.ReadFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName))
		So(err, ShouldBeNil)

		tdir = t.TempDir()

		err = os.WriteFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName), input, 0o600)
		So(err, ShouldBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if strings.Contains(path, "repo1/dst1") {
					return driver.FileInfoInternal{}, driver.PathNotFoundError{}
				}

				return driver.FileInfoInternal{}, nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		// now it should move content from /repo1/dst1 to /repo2/dst2
		_, err = imgStore.GetBlobContent("repo2", digest)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.StatBlob("repo2", digest)
		So(err, ShouldBeNil)

		// it errors out because of bad range, as mock store returns a driver.FileInfo with 0 size
		_, _, _, err = imgStore.GetBlobPartial("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on store.Reader()", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("/src/dst", digest, "", "/repo1/dst1")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("/src/dst", digest, "", "/repo2/dst2")
		So(err, ShouldBeNil)

		// copy cache db to the new imagestore
		input, err := os.ReadFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName))
		So(err, ShouldBeNil)

		tdir = t.TempDir()

		err = os.WriteFile(path.Join(tdir, storageConstants.BoltdbName+storageConstants.DBExtensionName), input, 0o600)
		So(err, ShouldBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return 0
					},
					PathFn: func() string {
						return "repo1/dst1"
					},
				}, nil
			},
			ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				if strings.Contains(path, "repo1/dst1") {
					return io.NopCloser(strings.NewReader("")), errS3
				}

				return io.NopCloser(strings.NewReader("")), nil
			},

			GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
				if strings.Contains(path, "repo1/dst1") {
					return []byte{}, errS3
				}

				return []byte{}, nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		_, err = imgStore.GetBlobContent("repo2", digest)
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.GetBlobPartial("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on checkCacheBlob()", t, func(c C) {
		tdir := t.TempDir()

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{
					SizeFn: func() int64 {
						return 0
					},
				}, nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		_, err = imgStore.GetBlobContent("repo2", digest)
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.StatBlob("repo2", digest)
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.GetBlobPartial("repo2", digest, "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteBlob() - error on store.Move()", t, func(c C) {
		tdir := t.TempDir()
		hash := "7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc" // #nosec G101

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, hash)

		blobPath := path.Join(testDir, "repo/blobs/sha256", hash)

		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				if destPath == blobPath {
					return nil
				}

				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path != blobPath {
					return nil, errS3
				}

				return &mocks.FileInfoMock{}, nil
			},
		})

		err := imgStore.DedupeBlob("repo", digest, "", blobPath)
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo2", digest)
		So(err, ShouldBeNil)

		err = imgStore.DeleteBlob("repo", digest)
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d)
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d)
		So(err, ShouldNotBeNil)
	})
}

func TestInjectDedupe(t *testing.T) {
	tdir := t.TempDir()

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	Convey("Inject errors in DedupeBlob function", t, func() {
		imgStore := createMockStorage(testDir, tdir, true, &mocks.StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{}, errS3
			},
		})
		err := imgStore.DedupeBlob("blob", "digest", "", "newblob")
		So(err, ShouldBeNil)

		injected := inject.InjectFailure(0)
		err = imgStore.DedupeBlob("blob", "digest", "", "newblob")

		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}

		injected = inject.InjectFailure(1)
		err = imgStore.DedupeBlob("blob", "digest", "", "newblob")

		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}
	})
}
