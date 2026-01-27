package gcs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	bucket := "zot-storage-test"
	storageDriverParams := map[string]any{
		"rootDir": rootDir,
		"name":    "gcs",
		"bucket":  bucket,
	}

	storeName := fmt.Sprintf("%v", storageDriverParams["name"])

	store, err := factory.Create(context.Background(), storeName, storageDriverParams)
	if err != nil {
		return nil, nil, err
	}

	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	s3CacheDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

	if _, err := os.Stat(s3CacheDBPath); dedupe || (!dedupe && err == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	il := gcs.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, nil
}

func TestGCSDriver(t *testing.T) {
	tskip.SkipGCS(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	Convey("GCS Driver E2E", t, func() {
		// Create a fresh temp dir for each run to avoid BoltDB lock issues
		tdir := t.TempDir()
		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		Convey("Init Repo", func() {
			repoName := "test-repo-init"
			err := imgStore.InitRepo(repoName)
			So(err, ShouldBeNil)

			isValid, err := imgStore.ValidateRepo(repoName)
			So(err, ShouldBeNil)
			So(isValid, ShouldBeTrue)
		})

		Convey("Push and Pull Image", func() {
			repoName := "test-repo-push"
			image := CreateDefaultImage()

			// Upload layers
			for _, content := range image.Layers {
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)

				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)
			}

			// Upload config
			cblob, err := json.Marshal(image.Config)
			So(err, ShouldBeNil)
			cdigest := godigest.FromBytes(cblob)
			_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			// Upload manifest
			mblob, err := json.Marshal(image.Manifest)
			So(err, ShouldBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			// Verify manifest
			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldBeNil)

			// Verify blob
			blobReadCloser, _, err := imgStore.GetBlob(repoName, cdigest, ispec.MediaTypeImageConfig)
			So(err, ShouldBeNil)
			defer blobReadCloser.Close()
			content, err := io.ReadAll(blobReadCloser)
			So(err, ShouldBeNil)
			So(content, ShouldResemble, cblob)
		})

		Convey("Delete Image", func() {
			repoName := "test-repo-delete"
			// Setup image
			image := CreateDefaultImage()
			cblob, _ := json.Marshal(image.Config)
			cdigest := godigest.FromBytes(cblob)
			_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			mblob, _ := json.Marshal(image.Manifest)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, "1.0", false)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		})
	})
}
