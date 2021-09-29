package storage_test

import (
	"bytes"
	"context"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"

	//"strings"

	"testing"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	guuid "github.com/gofrs/uuid"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	// Add s3 support
	storageDriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"

	"gopkg.in/resty.v1"
)

func cleanupStorage(store storageDriver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func skipIt(t *testing.T) {
	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func createMockObjectStore(rootDir string) (storageDriver.StorageDriver, storage.ImageStore) {
	store := new(StorageDriverMock)
	il := storage.NewObjectStorage(rootDir, false, false, log.Logger{Logger: zerolog.New(os.Stdout)}, store)

	return store, il
}

func createObjectsStore(rootDir string) (storageDriver.StorageDriver, storage.ImageStore, error) {
	bucket := "zot-storage-test"
	endpoint := os.Getenv("S3MOCK_ENDPOINT")
	objectsStoreParams := map[string]interface{}{
		"rootDir":        rootDir,
		"name":           "s3",
		"region":         "us-east-2",
		"bucket":         bucket,
		"regionendpoint": endpoint,
		"secure":         false,
		"skipverify":     false,
	}

	storeName := fmt.Sprintf("%v", objectsStoreParams["name"])

	store, err := factory.Create(storeName, objectsStoreParams)
	if err != nil {
		panic(err)
	}

	// create bucket if it doesn't exists
	_, err = resty.R().Put("http://" + endpoint + "/" + bucket)
	if err != nil {
		panic(err)
	}

	il := storage.NewObjectStorage(rootDir, false, false, log.Logger{Logger: zerolog.New(os.Stdout)}, store)

	return store, il, err
}

var errS3 = errors.New("couldn't get response from s3")

type StorageDriverMock struct {
}

func (s *StorageDriverMock) Name() string {
	return ""
}

func (s *StorageDriverMock) GetContent(ctx context.Context, path string) ([]byte, error) {
	return nil, errS3
}

func (s *StorageDriverMock) PutContent(ctx context.Context, path string, content []byte) error {
	return errS3
}

func (s *StorageDriverMock) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	return nil, errS3
}

func (s *StorageDriverMock) Writer(ctx context.Context, path string, append bool) (storageDriver.FileWriter, error) {
	return nil, errS3
}

func (s *StorageDriverMock) Stat(ctx context.Context, path string) (storageDriver.FileInfo, error) {
	return nil, errS3
}

func (s *StorageDriverMock) List(ctx context.Context, path string) ([]string, error) {
	return nil, errS3
}

func (s *StorageDriverMock) Move(ctx context.Context, sourcePath string, destPath string) error {
	return errS3
}

func (s *StorageDriverMock) Delete(ctx context.Context, path string) error {
	return errS3
}

func (s *StorageDriverMock) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	return "", errS3
}

func (s *StorageDriverMock) Walk(ctx context.Context, path string, f storageDriver.WalkFn) error {
	return errS3
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
		So(il.InitRepo("test"), ShouldBeNil)
		objects, err := store.List(context.Background(), path.Join(il.RootDir(), "test"))
		So(err, ShouldBeNil)
		for _, object := range objects {
			t.Logf("Removing object: %s", object)
			err := store.Delete(context.Background(), object)
			So(err, ShouldBeNil)
		}
		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)
		_, err = il.GetRepositories()
		So(err, ShouldBeNil)
	})

	Convey("Invalid get image tags", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)

		So(store.Move(context.Background(), path.Join(testDir, "test", "index.json"),
			path.Join(testDir, "test", "blobs")), ShouldBeNil)
		ok, _ := il.ValidateRepo("test")
		So(ok, ShouldBeFalse)
		_, err = il.GetImageTags("test")
		So(err, ShouldNotBeNil)

		So(store.Delete(context.Background(), path.Join(testDir, "test")), ShouldBeNil)

		So(il.InitRepo("test"), ShouldBeNil)
		So(store.PutContent(context.Background(), path.Join(testDir, "test", "index.json"), []byte{}), ShouldBeNil)
		_, err = il.GetImageTags("test")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image manifest", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, "test", "index.json")), ShouldBeNil)
		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, "test")), ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(store.PutContent(context.Background(), path.Join(testDir, "test", "index.json"), []byte{}), ShouldBeNil)
		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid validate repo", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)

		So(il.InitRepo("test"), ShouldBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, "test", "index.json")), ShouldBeNil)
		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, "test")), ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(store.Move(context.Background(), path.Join(testDir, "test", "index.json"),
			path.Join(testDir, "test", "_index.json")), ShouldBeNil)
		ok, err := il.ValidateRepo("test")
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Invalid finish blob upload", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il, ShouldNotBeNil)

		So(il.InitRepo("test"), ShouldBeNil)
		v, err := il.NewBlobUpload("test")
		So(err, ShouldBeNil)
		So(v, ShouldNotBeEmpty)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		d := godigest.FromBytes(content)

		b, err := il.PutBlobChunk("test", v, 0, int64(l), buf)
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)

		src := il.BlobUploadPath("test", v)
		fw, err := store.Writer(context.Background(), src, true)
		So(err, ShouldBeNil)

		_, err = fw.Write([]byte("another-chunk-of-data"))
		So(err, ShouldBeNil)

		err = fw.Close()
		So(err, ShouldBeNil)

		err = il.FinishBlobUpload("test", v, buf, d.String())
		So(err, ShouldNotBeNil)
	})

	Convey("Test storage driver errors", t, func(c C) {
		_, il := createMockObjectStore(testDir)
		So(il, ShouldNotBeNil)

		So(il.InitRepo("test"), ShouldNotBeNil)
		v, err := il.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		d := godigest.FromBytes(content)

		_, err = il.PutBlobChunk("test", v, 0, int64(l), buf)
		So(err, ShouldNotBeNil)

		err = il.FinishBlobUpload("test", v, buf, d.String())
		So(err, ShouldNotBeNil)

		err = il.DeleteBlob("test", d.String())
		So(err, ShouldNotBeNil)

		err = il.DeleteBlobUpload("test", v)
		So(err, ShouldNotBeNil)

		err = il.DeleteImageManifest("test", "1.0")
		So(err, ShouldNotBeNil)

		_, err = il.PutImageManifest("test", "1.0", "application/json", []byte{})
		So(err, ShouldNotBeNil)

		_, err = il.PutBlobChunkStreamed("test", v, bytes.NewBuffer([]byte("test")))
		So(err, ShouldNotBeNil)

		_, _, err = il.FullBlobUpload("test", bytes.NewBuffer([]byte{}), "inexistent")
		So(err, ShouldNotBeNil)

		_, _, err = il.CheckBlob("test", d.String())
		So(err, ShouldNotBeNil)
	})
}
