package storage_test

import (
	"context"
	_ "crypto/sha256"
	"fmt"
	"os"
	"path"

	//"strings"

	"testing"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
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
		return store, &storage.ObjectStorage{}, err
	}

	// create bucket
	_, err = resty.R().Put("http://" + endpoint + "/" + bucket)
	if err != nil {
		panic(err)
	}

	il := storage.NewObjectStorage(rootDir, false, false, log.Logger{Logger: zerolog.New(os.Stdout)}, objectsStoreParams)

	return store, il, err
}

func TestNegativeCasesObjectsStorage(t *testing.T) {
	skipIt(t)

	testDir := "/oci-repo-test-2"

	store, il, _ := createObjectsStore(testDir)
	defer cleanupStorage(store, testDir)

	Convey("Invalid validate repo", t, func(c C) {
		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		objects, err := store.List(context.Background(), il.RootDir())
		So(err, ShouldBeNil)
		for _, object := range objects {
			err := store.Delete(context.Background(), object)
			So(err, ShouldBeNil)
		}
		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)
		_, err = il.GetRepositories()
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image tags", t, func(c C) {
		store, il, err := createObjectsStore(testDir)
		defer cleanupStorage(store, testDir)
		So(err, ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(store.Delete(context.Background(), path.Join(testDir, "test", "index.json")), ShouldBeNil)
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
}
