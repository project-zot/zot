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

	"github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/s3"
	"zotregistry.io/zot/pkg/test"
)

// nolint: gochecknoglobals
var (
	testImage      = "test"
	fileWriterSize = 12
	fileInfoSize   = 10
	errorText      = "new s3 error"
	errS3          = errors.New(errorText)
)

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func skipIt(t *testing.T) {
	t.Helper()

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func createMockStorage(rootDir string, cacheDir string, dedupe bool, store driver.StorageDriver) storage.ImageStore {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	il := s3.NewImageStore(rootDir, cacheDir, false, storConstants.DefaultGCDelay,
		dedupe, false, log, metrics, nil, store,
	)

	return il
}

func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storage.ImageStore,
	error,
) {
	bucket := "zot-storage-test"
	endpoint := os.Getenv("S3MOCK_ENDPOINT")
	storageDriverParams := map[string]interface{}{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         "us-east-2",
		"bucket":         bucket,
		"regionendpoint": endpoint,
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

	// create bucket if it doesn't exists
	_, err = resty.R().Put("http://" + endpoint + "/" + bucket)
	if err != nil {
		panic(err)
	}

	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	il := s3.NewImageStore(rootDir, cacheDir, false, storConstants.DefaultGCDelay,
		dedupe, false, log, metrics, nil, store)

	return store, il, err
}

type FileInfoMock struct {
	IsDirFn func() bool
	SizeFn  func() int64
}

func (f *FileInfoMock) Path() string {
	return ""
}

func (f *FileInfoMock) Size() int64 {
	if f != nil && f.SizeFn != nil {
		return f.SizeFn()
	}

	return int64(fileInfoSize)
}

func (f *FileInfoMock) ModTime() time.Time {
	return time.Now()
}

func (f *FileInfoMock) IsDir() bool {
	if f != nil && f.IsDirFn != nil {
		return f.IsDirFn()
	}

	return true
}

type FileWriterMock struct {
	WriteFn  func([]byte) (int, error)
	CancelFn func() error
	CommitFn func() error
	CloseFn  func() error
}

func (f *FileWriterMock) Size() int64 {
	return int64(fileWriterSize)
}

func (f *FileWriterMock) Cancel() error {
	if f != nil && f.CancelFn != nil {
		return f.CancelFn()
	}

	return nil
}

func (f *FileWriterMock) Commit() error {
	if f != nil && f.CommitFn != nil {
		return f.CommitFn()
	}

	return nil
}

func (f *FileWriterMock) Write(p []byte) (int, error) {
	if f != nil && f.WriteFn != nil {
		return f.WriteFn(p)
	}

	return 10, nil
}

func (f *FileWriterMock) Close() error {
	if f != nil && f.CloseFn != nil {
		return f.CloseFn()
	}

	return nil
}

type StorageDriverMock struct {
	NameFn       func() string
	GetContentFn func(ctx context.Context, path string) ([]byte, error)
	PutContentFn func(ctx context.Context, path string, content []byte) error
	ReaderFn     func(ctx context.Context, path string, offset int64) (io.ReadCloser, error)
	WriterFn     func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error)
	StatFn       func(ctx context.Context, path string) (driver.FileInfo, error)
	ListFn       func(ctx context.Context, path string) ([]string, error)
	MoveFn       func(ctx context.Context, sourcePath, destPath string) error
	DeleteFn     func(ctx context.Context, path string) error
	WalkFn       func(ctx context.Context, path string, f driver.WalkFn) error
}

func (s *StorageDriverMock) Name() string {
	if s != nil && s.NameFn != nil {
		return s.NameFn()
	}

	return ""
}

func (s *StorageDriverMock) GetContent(ctx context.Context, path string) ([]byte, error) {
	if s != nil && s.GetContentFn != nil {
		return s.GetContentFn(ctx, path)
	}

	return []byte{}, nil
}

func (s *StorageDriverMock) PutContent(ctx context.Context, path string, content []byte) error {
	if s != nil && s.PutContentFn != nil {
		return s.PutContentFn(ctx, path, content)
	}

	return nil
}

func (s *StorageDriverMock) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	if s != nil && s.ReaderFn != nil {
		return s.ReaderFn(ctx, path, offset)
	}

	return io.NopCloser(strings.NewReader("")), nil
}

func (s *StorageDriverMock) Writer(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
	if s != nil && s.WriterFn != nil {
		return s.WriterFn(ctx, path, isAppend)
	}

	return &FileWriterMock{}, nil
}

func (s *StorageDriverMock) Stat(ctx context.Context, path string) (driver.FileInfo, error) {
	if s != nil && s.StatFn != nil {
		return s.StatFn(ctx, path)
	}

	return &FileInfoMock{}, nil
}

func (s *StorageDriverMock) List(ctx context.Context, path string) ([]string, error) {
	if s != nil && s.ListFn != nil {
		return s.ListFn(ctx, path)
	}

	return []string{"a"}, nil
}

func (s *StorageDriverMock) Move(ctx context.Context, sourcePath, destPath string) error {
	if s != nil && s.MoveFn != nil {
		return s.MoveFn(ctx, sourcePath, destPath)
	}

	return nil
}

func (s *StorageDriverMock) Delete(ctx context.Context, path string) error {
	if s != nil && s.DeleteFn != nil {
		return s.DeleteFn(ctx, path)
	}

	return nil
}

func (s *StorageDriverMock) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	return "", nil
}

func (s *StorageDriverMock) Walk(ctx context.Context, path string, f driver.WalkFn) error {
	if s != nil && s.WalkFn != nil {
		return s.WalkFn(ctx, path, f)
	}

	return nil
}

func TestStorageDriverStatFunction(t *testing.T) {
	skipIt(t)

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
		repo1 := "repo/testImageA"
		repo2 := "repo/testImage"

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

func TestNegativeCasesObjectsStorage(t *testing.T) {
	skipIt(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	tdir := t.TempDir()

	storeDriver, imgStore, _ := createObjectsStore(testDir, tdir, true)
	defer cleanupStorage(storeDriver, testDir)

	Convey("Invalid validate repo", t, func(c C) {
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

	Convey("Invalid get image tags", t, func(c C) {
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

	Convey("Invalid get image manifest", t, func(c C) {
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

	Convey("Invalid validate repo", t, func(c C) {
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

	Convey("Invalid finish blob upload", t, func(c C) {
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

		err = imgStore.FinishBlobUpload(testImage, upload, buf, digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test storage driver errors", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
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
				return &FileWriterMock{}, errS3
			},
			ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("")), errS3
			},
			WalkFn: func(ctx context.Context, path string, f driver.WalkFn) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, errS3
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

		err = imgStore.FinishBlobUpload(testImage, upload, buf, digest.String())
		So(err, ShouldNotBeNil)

		err = imgStore.DeleteBlob(testImage, digest.String())
		So(err, ShouldNotBeNil)

		err = imgStore.DeleteBlobUpload(testImage, upload)
		So(err, ShouldNotBeNil)

		err = imgStore.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)

		_, err = imgStore.PutImageManifest(testImage, "1.0", "application/json", []byte{})
		So(err, ShouldNotBeNil)

		_, err = imgStore.PutBlobChunkStreamed(testImage, upload, bytes.NewBuffer([]byte(testImage)))
		So(err, ShouldNotBeNil)

		_, _, err = imgStore.FullBlobUpload(testImage, bytes.NewBuffer([]byte{}), "inexistent")
		So(err, ShouldNotBeNil)

		_, _, err = imgStore.CheckBlob(testImage, digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{testImage, testImage}, errS3
			},
		})

		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)

		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{testImage, testImage}, nil
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, errS3
			},
		})

		_, err = imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo3", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo4", t, func(c C) {
		ociLayout := []byte(`{"imageLayoutVersion": "9.9.9"}`)
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ListFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return ociLayout, nil
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetRepositories", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WalkFn: func(ctx context.Context, path string, f driver.WalkFn) error {
				return f(new(FileInfoMock))
			},
		})
		repos, err := imgStore.GetRepositories()
		So(repos, ShouldBeEmpty)
		So(err, ShouldBeNil)
	})

	Convey("Test DeleteImageManifest", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			GetContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		err := imgStore.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteImageManifest2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{})
		err := imgStore.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test NewBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
		})
		_, err := imgStore.NewBlobUpload(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
		})
		_, err := imgStore.GetBlobUpload(testImage, "uuid")
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", io.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{WriteFn: func(b []byte) (int, error) {
					return 0, errS3
				}}, nil
			},
		})
		_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", io.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, io.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
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

	Convey("Test PutBlobChunk3", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					WriteFn: func(b []byte) (int, error) {
						return 0, errS3
					},
				}, nil
			},
		})
		_, err := imgStore.PutBlobChunk(testImage, "uuid", 12, 100, io.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					CommitFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					CloseFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload3", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, errS3
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload4", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload2", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{})
		d := godigest.FromBytes([]byte(" "))
		_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload3", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader("")), errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.GetBlob(testImage, d.String(), "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteBlob", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			DeleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.DeleteBlob(testImage, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetReferrers", t, func(c C) {
		imgStore = createMockStorage(testDir, tdir, false, &StorageDriverMock{
			DeleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, err := imgStore.GetReferrers(testImage, d.String(), "application/image")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrMethodNotSupported)
	})
}

func TestS3Dedupe(t *testing.T) {
	skipIt(t)
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
		blobDigest1 := strings.Split(digest.String(), ":")[1]
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, checkBlobSize1, err := imgStore.CheckBlob("dedupe1", digest.String())
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize1, err := imgStore.GetBlob("dedupe1", digest.String(),
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest := test.GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest.String())
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))
		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest.String())
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
		digest = godigest.FromBytes(manifestBuf)
		_, err = imgStore.PutImageManifest("dedupe1", digest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", digest.String())
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
		blobDigest2 := strings.Split(digest.String(), ":")[1]
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest.String())
		So(err, ShouldBeNil)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest.String(),
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = test.GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest.String())
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))
		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest.String())
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
		digest = godigest.FromBytes(manifestBuf)
		_, err = imgStore.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest,
			manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", digest.String())
		So(err, ShouldBeNil)

		fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256", blobDigest1))
		So(err, ShouldBeNil)

		fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256", blobDigest2))
		So(err, ShouldBeNil)

		// original blob should have the real content of blob
		So(fi1.Size(), ShouldNotEqual, fi2.Size())
		So(fi1.Size(), ShouldBeGreaterThan, 0)
		// deduped blob should be of size 0
		So(fi2.Size(), ShouldEqual, 0)

		Convey("Check that delete blobs moves the real content to the next contenders", func() {
			// if we delete blob1, the content should be moved to blob2
			err = imgStore.DeleteBlob("dedupe1", "sha256:"+blobDigest1)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256", blobDigest1))
			So(err, ShouldNotBeNil)

			fi2, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256", blobDigest2))
			So(err, ShouldBeNil)

			So(fi2.Size(), ShouldBeGreaterThan, 0)
			// the second blob should now be equal to the deleted blob.
			So(fi2.Size(), ShouldEqual, fi1.Size())

			err = imgStore.DeleteBlob("dedupe2", "sha256:"+blobDigest2)
			So(err, ShouldBeNil)

			_, err = storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256", blobDigest2))
			So(err, ShouldNotBeNil)
		})

		Convey("Check backward compatibility - switch dedupe to false", func() {
			/* copy cache to the new storage with dedupe false (doing this because we
			already have a cache object holding the lock on cache db file) */
			input, err := os.ReadFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName))
			So(err, ShouldBeNil)

			tdir = t.TempDir()

			err = os.WriteFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName), input, 0o600)
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
			blobDigest2 := strings.Split(digest.String(), ":")[1]
			So(blobDigest2, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("dedupe3", upload, buf, digest.String())
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			_, _, err = imgStore.CheckBlob("dedupe3", digest.String())
			So(err, ShouldBeNil)

			// check that we retrieve the real dedupe2/blob (which is deduped earlier - 0 size) when switching to dedupe false
			blobReadCloser, getBlobSize2, err = imgStore.GetBlob("dedupe2", digest.String(),
				"application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			So(getBlobSize1, ShouldEqual, getBlobSize2)
			err = blobReadCloser.Close()
			So(err, ShouldBeNil)

			_, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest.String())
			So(err, ShouldBeNil)
			So(checkBlobSize2, ShouldBeGreaterThan, 0)
			So(checkBlobSize2, ShouldEqual, getBlobSize2)

			_, getBlobSize3, err := imgStore.GetBlob("dedupe3", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			So(getBlobSize1, ShouldEqual, getBlobSize3)

			_, checkBlobSize3, err := imgStore.CheckBlob("dedupe3", digest.String())
			So(err, ShouldBeNil)
			So(checkBlobSize3, ShouldBeGreaterThan, 0)
			So(checkBlobSize3, ShouldEqual, getBlobSize3)

			cblob, cdigest = test.GetRandomImageConfig()
			_, clen, err = imgStore.FullBlobUpload("dedupe3", bytes.NewReader(cblob), cdigest.String())
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))
			hasBlob, _, err = imgStore.CheckBlob("dedupe3", cdigest.String())
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
			digest = godigest.FromBytes(manifestBuf)
			_, err = imgStore.PutImageManifest("dedupe3", "1.0", ispec.MediaTypeImageManifest,
				manifestBuf)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest("dedupe3", digest.String())
			So(err, ShouldBeNil)

			fi1, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe1", "blobs", "sha256", blobDigest1))
			So(err, ShouldBeNil)

			fi2, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe2", "blobs", "sha256", blobDigest1))
			So(err, ShouldBeNil)
			So(fi2.Size(), ShouldEqual, 0)

			fi3, err := storeDriver.Stat(context.Background(), path.Join(testDir, "dedupe3", "blobs", "sha256", blobDigest2))
			So(err, ShouldBeNil)

			// the new blob with dedupe false should be equal with the origin blob from dedupe1
			So(fi1.Size(), ShouldEqual, fi3.Size())
		})
	})
}

func TestS3PullRange(t *testing.T) {
	skipIt(t)

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

		err = imgStore.FinishBlobUpload("index", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		Convey("Without Dedupe", func() {
			reader, _, _, err := imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "application/octet-stream", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, 100)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, 10)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, 0)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:1])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, 1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:2])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 2, 3)
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

			err = imgStore.FinishBlobUpload("dupindex", upload, buf, digest.String())
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			reader, _, _, err := imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "application/octet-stream", 0, -1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 0, 100)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 0, 10)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content)
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 0, 0)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:1])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 0, 1)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[0:2])
			reader.Close()

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 2, 3)
			So(err, ShouldBeNil)
			rdbuf, err = io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(rdbuf, ShouldResemble, content[2:4])
			reader.Close()

			// delete original blob
			err = imgStore.DeleteBlob("index", digest.String())
			So(err, ShouldBeNil)

			reader, _, _, err = imgStore.GetBlobPartial("dupindex", digest.String(), "*/*", 2, 3)
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

			_, _, _, err = imgStore.GetBlobPartial("index", digest.String(), "*/*", 0, -1)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestS3ManifestImageIndex(t *testing.T) {
	skipIt(t)

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

		err = imgStore.FinishBlobUpload("index", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// upload image config blob
		upload, err = imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest := test.GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()
		blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("index", upload, buf, cdigest.String())
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
		_, err = imgStore.PutImageManifest("index", "test:1.0", ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		// create another manifest but upload using its sha256 reference

		// upload image config blob
		upload, err = imgStore.NewBlobUpload("index")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest = test.GetRandomImageConfig()
		buf = bytes.NewBuffer(cblob)
		buflen = buf.Len()
		blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("index", upload, buf, cdigest.String())
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
		_, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		Convey("Image index", func() {
			// upload image config blob
			upload, err = imgStore.NewBlobUpload("index")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest = test.GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("index", upload, buf, cdigest.String())
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
			_, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
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
			_, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageIndex, content)
			So(err, ShouldBeNil)
			_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
			So(err, ShouldBeNil)

			// upload another image config blob
			upload, err = imgStore.NewBlobUpload("index")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest = test.GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed("index", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("index", upload, buf, cdigest.String())
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
			_, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
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
			_, err = imgStore.PutImageManifest("index", "test:index2", ispec.MediaTypeImageIndex, content)
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
				_, err = imgStore.PutImageManifest("index", "test:index3", ispec.MediaTypeImageIndex, content)
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
				_, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageIndex, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", digest.String())
				So(err, ShouldBeNil)
			})

			Convey("Deleting an image index", func() {
				// delete manifest by tag should pass
				err := imgStore.DeleteImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)

				err = imgStore.DeleteImageManifest("index", "test:index1")
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldNotBeNil)

				_, _, _, err = imgStore.GetImageManifest("index", "test:index2")
				So(err, ShouldBeNil)
			})

			Convey("Deleting an image index by digest", func() {
				// delete manifest by tag should pass
				err := imgStore.DeleteImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index3")
				So(err, ShouldNotBeNil)

				err = imgStore.DeleteImageManifest("index", index1dgst.String())
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

				err = imgStore.FinishBlobUpload("index", upload, buf, digest.String())
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
				_, err = imgStore.PutImageManifest("index", digest.String(), ispec.MediaTypeImageManifest, content)
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
				_, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageIndex, content)
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldBeNil)

				err = imgStore.DeleteImageManifest("index", "test:index1")
				So(err, ShouldBeNil)
				_, _, _, err = imgStore.GetImageManifest("index", "test:index1")
				So(err, ShouldNotBeNil)
			})

			Convey("Negative test cases", func() {
				Convey("Delete index", func() {
					cleanupStorage(storeDriver, path.Join(testDir, "index", "blobs",
						index1dgst.Algorithm().String(), index1dgst.Encoded()))

					err = imgStore.DeleteImageManifest("index", index1dgst.String())
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
					err = imgStore.DeleteImageManifest("index", index1dgst.String())
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
					_, err = imgStore.PutImageManifest("index", "test:1.0", ispec.MediaTypeImageIndex, content)
					So(err, ShouldNotBeNil)

					// previously an image index, try writing a manifest
					_, err = imgStore.PutImageManifest("index", "test:index1", ispec.MediaTypeImageManifest, m1content)
					So(err, ShouldNotBeNil)
				})
			})
		})
	})
}

func TestS3DedupeErr(t *testing.T) {
	skipIt(t)

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

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{})

		err = os.Remove(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName))
		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")

		// trigger unable to insert blob record
		err := imgStore.DedupeBlob("", digest, "")
		So(err, ShouldNotBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath string, destPath string) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		// trigger unable to rename blob
		err = imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldNotBeNil)

		// trigger retry
		err = imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on second store.Stat()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if path == "dst2" {
					return driver.FileInfoInternal{}, errS3
				}

				return driver.FileInfoInternal{}, nil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "dst2")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on store.PutContent()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "dst2")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on cache.PutBlob()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DedupeBlob - error on store.Delete()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			DeleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return nil, nil
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, "digest")
		err := imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("", digest, "dst")
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on initRepo()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
			WriterFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on store.PutContent()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test copyBlob() - error on store.Stat()", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return driver.FileInfoInternal{}, errS3
			},
		})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("repo", digest, "dst")
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo", digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on second store.Stat()", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("/src/dst", digest, "/repo1/dst1")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("/src/dst", digest, "/repo2/dst2")
		So(err, ShouldBeNil)

		// copy cache db to the new imagestore
		input, err := os.ReadFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName))
		So(err, ShouldBeNil)

		tdir = t.TempDir()

		err = os.WriteFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName), input, 0o600)
		So(err, ShouldBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				if strings.Contains(path, "repo1/dst1") {
					return driver.FileInfoInternal{}, driver.PathNotFoundError{}
				}

				return driver.FileInfoInternal{}, nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.GetBlobPartial("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on store.Reader()", t, func(c C) {
		tdir := t.TempDir()

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{})

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		err := imgStore.DedupeBlob("/src/dst", digest, "/repo1/dst1")
		So(err, ShouldBeNil)

		err = imgStore.DedupeBlob("/src/dst", digest, "/repo2/dst2")
		So(err, ShouldBeNil)

		// copy cache db to the new imagestore
		input, err := os.ReadFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName))
		So(err, ShouldBeNil)

		tdir = t.TempDir()

		err = os.WriteFile(path.Join(tdir, s3.CacheDBName+storage.DBExtensionName), input, 0o600)
		So(err, ShouldBeNil)

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{
					SizeFn: func() int64 {
						return 0
					},
				}, nil
			},
			ReaderFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				if strings.Contains(path, "repo1/dst1") {
					return io.NopCloser(strings.NewReader("")), errS3
				}

				return io.NopCloser(strings.NewReader("")), nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.GetBlobPartial("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob() - error on checkCacheBlob()", t, func(c C) {
		tdir := t.TempDir()

		digest := godigest.NewDigestFromEncoded(godigest.SHA256,
			"7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc")

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{
					SizeFn: func() int64 {
						return 0
					},
				}, nil
			},
		})

		_, _, err = imgStore.GetBlob("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldNotBeNil)

		_, _, _, err = imgStore.GetBlobPartial("repo2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip", 0, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteBlob() - error on store.Move()", t, func(c C) {
		tdir := t.TempDir()
		hash := "7173b809ca12ec5dee4506cd86be934c4596dd234ee82c0662eac04a8c2c71dc"

		digest := godigest.NewDigestFromEncoded(godigest.SHA256, hash)

		blobPath := path.Join(testDir, "repo/blobs/sha256", hash)

		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
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

				return &FileInfoMock{}, nil
			},
		})

		err := imgStore.DedupeBlob("repo", digest, blobPath)
		So(err, ShouldBeNil)

		_, _, err = imgStore.CheckBlob("repo2", digest.String())
		So(err, ShouldBeNil)

		err = imgStore.DeleteBlob("repo", digest.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, io.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload", t, func(c C) {
		tdir := t.TempDir()
		imgStore = createMockStorage(testDir, tdir, true, &StorageDriverMock{
			MoveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.FinishBlobUpload(testImage, "uuid", io.NopCloser(strings.NewReader("")), d.String())
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
		imgStore := createMockStorage(testDir, tdir, true, &StorageDriverMock{
			StatFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
		})
		err := imgStore.DedupeBlob("blob", "digest", "newblob")
		So(err, ShouldBeNil)

		injected := test.InjectFailure(0)
		err = imgStore.DedupeBlob("blob", "digest", "newblob")
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}

		injected = test.InjectFailure(1)
		err = imgStore.DedupeBlob("blob", "digest", "newblob")
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}
	})
}
