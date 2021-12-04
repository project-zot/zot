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
	"time"

	godigest "github.com/opencontainers/go-digest"
	//"strings"

	"testing"

	guuid "github.com/gofrs/uuid"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/s3"

	// Add s3 support
	storageDriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"

	"gopkg.in/resty.v1"
)

// nolint: gochecknoglobals
var (
	testImage      = "test"
	fileWriterSize = 12
	fileInfoSize   = 10
	errorText      = "new s3 error"
	errS3          = errors.New(errorText)
)

func cleanupStorage(store storageDriver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func skipIt(t *testing.T) {
	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func createMockStorage(rootDir string, store storageDriver.StorageDriver) storage.ImageStore {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	il := s3.NewImageStore(rootDir, false, false, log, metrics, store)

	return il
}

func createObjectsStore(rootDir string) (storageDriver.StorageDriver, storage.ImageStore, error) {
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
	il := s3.NewImageStore(rootDir, false, false, log, metrics, store)

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
	writerFn     func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error)
	statFn       func(ctx context.Context, path string) (storageDriver.FileInfo, error)
	listFn       func(ctx context.Context, path string) ([]string, error)
	moveFn       func(ctx context.Context, sourcePath string, destPath string) error
	deleteFn     func(ctx context.Context, path string) error
	walkFn       func(ctx context.Context, path string, f storageDriver.WalkFn) error
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

func (s *StorageDriverMock) Writer(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
	if s != nil && s.writerFn != nil {
		return s.writerFn(ctx, path, append)
	}

	return &FileWriterMock{}, nil
}

func (s *StorageDriverMock) Stat(ctx context.Context, path string) (storageDriver.FileInfo, error) {
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

func (s *StorageDriverMock) Walk(ctx context.Context, path string, f storageDriver.WalkFn) error {
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

	store, il, _ := createObjectsStore(testDir)
	defer cleanupStorage(store, testDir)

	Convey("Invalid validate repo", t, func(c C) {
		So(il, ShouldNotBeNil)
		So(il.InitRepo(testImage), ShouldBeNil)
		objects, err := store.List(context.Background(), path.Join(il.RootDir(), testImage))
		So(err, ShouldBeNil)
		for _, object := range objects {
			t.Logf("Removing object: %s", object)
			err := store.Delete(context.Background(), object)
			So(err, ShouldBeNil)
		}
		_, err = il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
		_, err = il.GetRepositories()
		So(err, ShouldBeNil)
	})

	Convey("Invalid get image tags", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il.InitRepo(testImage), ShouldBeNil)

		So(store.Move(context.Background(), path.Join(testDir, testImage, "index.json"),
			path.Join(testDir, testImage, "blobs")), ShouldBeNil)
		ok, _ := il.ValidateRepo(testImage)
		So(ok, ShouldBeFalse)
		_, err = il.GetImageTags(testImage)
		So(err, ShouldNotBeNil)

		So(store.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)

		So(il.InitRepo(testImage), ShouldBeNil)
		So(store.PutContent(context.Background(), path.Join(testDir, testImage, "index.json"), []byte{}), ShouldBeNil)
		_, err = il.GetImageTags(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image manifest", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)
		So(il.InitRepo(testImage), ShouldBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, testImage, "index.json")), ShouldBeNil)
		_, _, _, err = il.GetImageManifest(testImage, "")
		So(err, ShouldNotBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)
		So(il.InitRepo(testImage), ShouldBeNil)
		So(store.PutContent(context.Background(), path.Join(testDir, testImage, "index.json"), []byte{}), ShouldBeNil)
		_, _, _, err = il.GetImageManifest(testImage, "")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid validate repo", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)

		So(il.InitRepo(testImage), ShouldBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, testImage, "index.json")), ShouldBeNil)
		_, err = il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, testImage)), ShouldBeNil)
		So(il.InitRepo(testImage), ShouldBeNil)
		So(store.Move(context.Background(), path.Join(testDir, testImage, "index.json"),
			path.Join(testDir, testImage, "_index.json")), ShouldBeNil)
		ok, err := il.ValidateRepo(testImage)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Invalid finish blob upload", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)

		So(il.InitRepo(testImage), ShouldBeNil)
		v, err := il.NewBlobUpload(testImage)
		So(err, ShouldBeNil)
		So(v, ShouldNotBeEmpty)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		d := godigest.FromBytes(content)

		b, err := il.PutBlobChunk(testImage, v, 0, int64(l), buf)
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)

		src := il.BlobUploadPath(testImage, v)
		fw, err := store.Writer(context.Background(), src, true)
		So(err, ShouldBeNil)

		_, err = fw.Write([]byte("another-chunk-of-data"))
		So(err, ShouldBeNil)

		err = fw.Close()
		So(err, ShouldBeNil)

		err = il.FinishBlobUpload(testImage, v, buf, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test storage driver errors", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
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
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return ioutil.NopCloser(strings.NewReader("")), errS3
			},
			walkFn: func(ctx context.Context, path string, f storageDriver.WalkFn) error {
				return errS3
			},
			statFn: func(ctx context.Context, path string) (storageDriver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
			deleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		So(il, ShouldNotBeNil)

		So(il.InitRepo(testImage), ShouldNotBeNil)
		_, err := il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)

		v, err := il.NewBlobUpload(testImage)
		So(err, ShouldNotBeNil)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		d := godigest.FromBytes(content)

		_, err = il.PutBlobChunk(testImage, v, 0, int64(l), buf)
		So(err, ShouldNotBeNil)

		err = il.FinishBlobUpload(testImage, v, buf, d.String())
		So(err, ShouldNotBeNil)

		err = il.DeleteBlob(testImage, d.String())
		So(err, ShouldNotBeNil)

		err = il.DeleteBlobUpload(testImage, v)
		So(err, ShouldNotBeNil)

		err = il.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)

		_, err = il.PutImageManifest(testImage, "1.0", "application/json", []byte{})
		So(err, ShouldNotBeNil)

		_, err = il.PutBlobChunkStreamed(testImage, v, bytes.NewBuffer([]byte(testImage)))
		So(err, ShouldNotBeNil)

		_, _, err = il.FullBlobUpload(testImage, bytes.NewBuffer([]byte{}), "inexistent")
		So(err, ShouldNotBeNil)

		_, _, err = il.CheckBlob(testImage, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{testImage, testImage}, errS3
			},
		})
		_, err := il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (storageDriver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
		})
		_, err := il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo3", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (storageDriver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		_, err := il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test ValidateRepo4", t, func(c C) {
		ociLayout := []byte(`{"imageLayoutVersion": "9.9.9"}`)
		il = createMockStorage(testDir, &StorageDriverMock{
			listFn: func(ctx context.Context, path string) ([]string, error) {
				return []string{"test/test/oci-layout", "test/test/index.json"}, nil
			},
			statFn: func(ctx context.Context, path string) (storageDriver.FileInfo, error) {
				return &FileInfoMock{}, nil
			},
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return ociLayout, nil
			},
		})
		_, err := il.ValidateRepo(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetRepositories", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			walkFn: func(ctx context.Context, path string, f storageDriver.WalkFn) error {
				return f(new(FileInfoMock))
			},
		})
		repos, err := il.GetRepositories()
		So(repos, ShouldBeEmpty)
		So(err, ShouldBeNil)
	})

	Convey("Test DeleteImageManifest", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			getContentFn: func(ctx context.Context, path string) ([]byte, error) {
				return []byte{}, errS3
			},
		})
		err := il.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteImageManifest2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{})
		err := il.DeleteImageManifest(testImage, "1.0")
		So(err, ShouldNotBeNil)
	})

	Convey("Test NewBlobUpload", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			putContentFn: func(ctx context.Context, path string, content []byte) error {
				return errS3
			},
		})
		_, err := il.NewBlobUpload(testImage)
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlobUpload", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			statFn: func(ctx context.Context, path string) (storageDriver.FileInfo, error) {
				return &FileInfoMock{}, errS3
			},
		})
		_, err := il.GetBlobUpload(testImage, "uuid")
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := il.PutBlobChunkStreamed(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunkStreamed2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{writeFn: func(b []byte) (int, error) {
					return 0, errS3
				}}, nil
			},
		})
		_, err := il.PutBlobChunkStreamed(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		_, err := il.PutBlobChunk(testImage, "uuid", 0, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
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
		_, err := il.PutBlobChunk(testImage, "uuid", 0, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test PutBlobChunk3", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{
					writeFn: func(b []byte) (int, error) {
						return 0, errS3
					},
				}, nil
			},
		})
		_, err := il.PutBlobChunk(testImage, "uuid", 12, 100, ioutil.NopCloser(strings.NewReader("")))
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{
					commitFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := il.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{
					closeFn: func() error {
						return errS3
					},
				}, nil
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := il.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload3", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, errS3
			},
		})
		d := godigest.FromBytes([]byte("test"))
		err := il.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FinishBlobUpload4", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			moveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := il.FinishBlobUpload(testImage, "uuid", ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			writerFn: func(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
				return &FileWriterMock{}, errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := il.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload2", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{})
		d := godigest.FromBytes([]byte(" "))
		_, _, err := il.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test FullBlobUpload3", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			moveFn: func(ctx context.Context, sourcePath, destPath string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := il.FullBlobUpload(testImage, ioutil.NopCloser(strings.NewReader("")), d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetBlob", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			readerFn: func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
				return ioutil.NopCloser(strings.NewReader("")), errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, _, err := il.GetBlob(testImage, d.String(), "")
		So(err, ShouldNotBeNil)
	})

	Convey("Test DeleteBlob", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			deleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		err := il.DeleteBlob(testImage, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test GetReferrers", t, func(c C) {
		il = createMockStorage(testDir, &StorageDriverMock{
			deleteFn: func(ctx context.Context, path string) error {
				return errS3
			},
		})
		d := godigest.FromBytes([]byte(""))
		_, err := il.GetReferrers(testImage, d.String(), "application/image")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrMethodNotSupported)
	})
}
