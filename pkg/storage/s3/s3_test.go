package s3_test

import (
	"bytes"
	"context"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/s3"
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

func createMockStorage(rootDir string, store driver.StorageDriver) storage.ImageStore {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	il := s3.NewImageStore(rootDir, false, storage.DefaultGCDelay, false, false, log, metrics, store)

	return il
}

func createObjectsStore(rootDir string) (driver.StorageDriver, storage.ImageStore, error) {
	bucket := "zot-storage-test"
	endpoint := os.Getenv("S3MOCK_ENDPOINT")
	storageDriverParams := map[string]interface{}{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         "us-east-2",
		"bucket":         bucket,
		"regionendpoint": endpoint,
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
	il := s3.NewImageStore(rootDir, false, storage.DefaultGCDelay, false, false, log, metrics, store)

	return store, il, err
}

type FileInfoMock struct {
	isDirFn func() bool
}

func (f *FileInfoMock) Path() string {
	return ""
}

func (f *FileInfoMock) Size() int64 {
	return int64(fileInfoSize)
}

func (f *FileInfoMock) ModTime() time.Time {
	return time.Now()
}

func (f *FileInfoMock) IsDir() bool {
	if f != nil && f.isDirFn != nil {
		return f.isDirFn()
	}

	return true
}

type FileWriterMock struct {
	writeFn  func([]byte) (int, error)
	cancelFn func() error
	commitFn func() error
	closeFn  func() error
}

func (f *FileWriterMock) Size() int64 {
	return int64(fileWriterSize)
}

func (f *FileWriterMock) Cancel() error {
	if f != nil && f.cancelFn != nil {
		return f.cancelFn()
	}

	return nil
}

func (f *FileWriterMock) Commit() error {
	if f != nil && f.commitFn != nil {
		return f.commitFn()
	}

	return nil
}

func (f *FileWriterMock) Write(p []byte) (int, error) {
	if f != nil && f.writeFn != nil {
		return f.writeFn(p)
	}

	return 10, nil
}

func (f *FileWriterMock) Close() error {
	if f != nil && f.closeFn != nil {
		return f.closeFn()
	}

	return nil
}

type StorageDriverMock struct {
	nameFn       func() string
	getContentFn func(ctx context.Context, path string) ([]byte, error)
	putContentFn func(ctx context.Context, path string, content []byte) error
	readerFn     func(ctx context.Context, path string, offset int64) (io.ReadCloser, error)
	writerFn     func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error)
	statFn       func(ctx context.Context, path string) (driver.FileInfo, error)
	listFn       func(ctx context.Context, path string) ([]string, error)
	moveFn       func(ctx context.Context, sourcePath string, destPath string) error
	deleteFn     func(ctx context.Context, path string) error
	walkFn       func(ctx context.Context, path string, f driver.WalkFn) error
}

func (s *StorageDriverMock) Name() string {
	if s != nil && s.nameFn != nil {
		return s.nameFn()
	}

	return ""
}

func (s *StorageDriverMock) GetContent(ctx context.Context, path string) ([]byte, error) {
	if s != nil && s.getContentFn != nil {
		return s.getContentFn(ctx, path)
	}

	return []byte{}, nil
}

func (s *StorageDriverMock) PutContent(ctx context.Context, path string, content []byte) error {
	if s != nil && s.putContentFn != nil {
		return s.putContentFn(ctx, path, content)
	}

	return nil
}

func (s *StorageDriverMock) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	if s != nil && s.readerFn != nil {
		return s.readerFn(ctx, path, offset)
	}

	return ioutil.NopCloser(strings.NewReader("")), nil
}

func (s *StorageDriverMock) Writer(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
	if s != nil && s.writerFn != nil {
		return s.writerFn(ctx, path, isAppend)
	}

	return &FileWriterMock{}, nil
}

func (s *StorageDriverMock) Stat(ctx context.Context, path string) (driver.FileInfo, error) {
	if s != nil && s.statFn != nil {
		return s.statFn(ctx, path)
	}

	return &FileInfoMock{}, nil
}

func (s *StorageDriverMock) List(ctx context.Context, path string) ([]string, error) {
	if s != nil && s.listFn != nil {
		return s.listFn(ctx, path)
	}

	return []string{"a"}, nil
}

func (s *StorageDriverMock) Move(ctx context.Context, sourcePath string, destPath string) error {
	if s != nil && s.moveFn != nil {
		return s.moveFn(ctx, sourcePath, destPath)
	}

	return nil
}

func (s *StorageDriverMock) Delete(ctx context.Context, path string) error {
	if s != nil && s.deleteFn != nil {
		return s.deleteFn(ctx, path)
	}

	return nil
}

func (s *StorageDriverMock) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	return "", nil
}

func (s *StorageDriverMock) Walk(ctx context.Context, path string, f driver.WalkFn) error {
	if s != nil && s.walkFn != nil {
		return s.walkFn(ctx, path, f)
	}

	return nil
}

func TestNegativeCasesObjectsStorage(t *testing.T) {
	skipIt(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	storeDriver, imgStore, _ := createObjectsStore(testDir)
	defer cleanupStorage(storeDriver, testDir)

	Convey("Invalid validate repo", t, func(c C) {
		So(imgStore, ShouldNotBeNil)
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
		storeDriver, imgStore, err := createObjectsStore(testDir)
		defer cleanupStorage(storeDriver, testDir)
		So(err, ShouldBeNil)
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
		storeDriver, imgStore, err := createObjectsStore(testDir)
		defer cleanupStorage(storeDriver, testDir)
		So(err, ShouldBeNil)
		So(imgStore, ShouldNotBeNil)
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
		storeDriver, imgStore, err := createObjectsStore(testDir)
		defer cleanupStorage(storeDriver, testDir)
		So(err, ShouldBeNil)
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
		storeDriver, imgStore, err := createObjectsStore(testDir)
		defer cleanupStorage(storeDriver, testDir)
		So(err, ShouldBeNil)
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
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{testImage}, errS3
			},
			moveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
			putContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return ioutil.NopCloser(strings.NewReader("")), errS3
			},
			walkFn: func(ctx context.Context, path string, f driver.WalkFn) error {
				return errS3
			},
			statFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
			deleteFn: func(ctx context.Context, path string) error {
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
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{testImage, testImage}, errS3
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo3", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo4", t, func(c C) {
		ociLayout := []byte(`{"imageLayoutVersion": "9.9.9"}`)
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return ociLayout, nil
			},
		})
		_, err := imgStore.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetRepositories", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			walkFn: func(ctx context.Context, path string, f driver.WalkFn) error {
				return f(new(FileInfoMock))
			},
		})
		repos, err := imgStore.GetRepositories()
		So(repos, ShouldBeEmpty)
		So(err, ShouldBeNil)
	})

	Convey("Test DeleteImageManifest", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		err := imgStore.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteImageManifest2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{})
		err := imgStore.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test NewBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			putContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
		})
		_, err := imgStore.NewBlobUpload(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			statFn: func(ctx context.Context, path string) (driver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
		})
		_, err := imgStore.GetBlobUpload(testImage, "uuid")
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{writeFn: func(b []byte) (int, error) {
					return 0, errS3
				}}, nil
			},
		})
		_, err := imgStore.PutBlobChunkStreamed(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					writeFn: func(b []byte) (int, error) {
						return 0, errS3
					},
					cancelFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		_, err := imgStore.PutBlobChunk(testImage, "uuid", 0, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk3", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					writeFn: func(b []byte) (int, error) {
						return 0, errS3
					},
				}, nil
			},
		})
		_, err := imgStore.PutBlobChunk(testImage, "uuid", 12, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					commitFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{
					closeFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload3", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, errS3
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := imgStore.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload4", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			moveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload2", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{})
		d := godigest.FromBytes([]byte(" "))
		_, _, err := imgStore.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload3", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			moveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return ioutil.NopCloser(strings.NewReader("")), errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := imgStore.GetBlob(testImage, d.String(), "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteBlob", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			deleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := imgStore.DeleteBlob(testImage, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetReferrers", t, func(c C) {
		imgStore = createMockStorage(testDir, &StorageDriverMock{
			deleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, err := imgStore.GetReferrers(testImage, d.String(), "application/image")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrMethodNotSupported)
	})
}
