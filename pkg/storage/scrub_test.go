package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	rediscfg "zotregistry.dev/zot/v2/pkg/api/config/redis"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const (
	repoName = "test"
	tag      = "1.0"
)

var errUnexpectedError = errors.New("unexpected err")

func TestLocalCheckAllBlobsIntegrity(t *testing.T) {
	Convey("test with local storage", t, func() {
		tdir := t.TempDir()
		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     tdir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		driver := local.New(true)
		imgStore := local.NewImageStore(tdir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func TestRedisCheckAllBlobsIntegrity(t *testing.T) {
	miniRedis := miniredis.RunT(t)

	Convey("test with local storage", t, func() {
		tdir := t.TempDir()
		log := log.NewTestLogger()

		metrics := monitoring.NewMetricsServer(false, log)

		client, _ := rediscfg.GetRedisClient(map[string]any{"url": "redis://" + miniRedis.Addr()}, log)

		cacheDriver, _ := storage.Create("redis", cache.RedisDriverParameters{
			Client:      client,
			RootDir:     tdir,
			UseRelPaths: false,
		}, log)
		driver := local.New(true)
		imgStore := local.NewImageStore(tdir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func TestS3CheckAllBlobsIntegrity(t *testing.T) {
	tskip.SkipS3(t)

	Convey("test with S3 storage", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()
		log := log.NewTestLogger()

		opts := createObjectStoreOpts{
			rootDir:     testDir,
			cacheDir:    tdir,
			cacheType:   storageConstants.BoltdbName,
			storageType: storageConstants.S3StorageDriverName,
		}

		driver, imgStore, _, _ := createObjectsStore(opts)
		defer cleanupStorage(driver, testDir)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func TestGCSCheckAllBlobsIntegrity(t *testing.T) {
	tskip.SkipGCS(t)

	Convey("test with GCS storage", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks

		opts := createObjectStoreOpts{
			rootDir:     testDir,
			cacheDir:    t.TempDir(),
			storageType: storageConstants.GCSStorageDriverName,
			cacheType:   storageConstants.BoltdbName,
		}

		driver, imgStore, _, err := createObjectsStore(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanupStorage(driver, testDir)

		RunCheckAllBlobsIntegrityTests(t, imgStore, driver, log)
	})
}

func RunCheckAllBlobsIntegrityTests( //nolint: thelper
	t *testing.T, imgStore storageTypes.ImageStore, driver storageTypes.Driver, log log.Logger,
) {
	Convey("Scrub only one repo", func() {
		// initialize repo
		err := imgStore.InitRepo(repoName)
		So(err, ShouldBeNil)

		ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
		So(ok, ShouldBeTrue)

		storeCtlr := storage.StoreController{}
		storeCtlr.DefaultStore = imgStore
		So(storeCtlr.GetImageStore(repoName), ShouldResemble, imgStore)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repoName, tag, storeCtlr)
		So(err, ShouldBeNil)

		Convey("Blobs integrity not affected", func() {
			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")

			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(0).Build(), repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test 2.0 ok")
		})

		Convey("Blobs integrity with context done", func() {
			buff := bytes.NewBufferString("")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err := storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
		})

		Convey("Manifest integrity affected", func() {
			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, image.ManifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "affected")

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)

			_, err = driver.WriteFile(manifestFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid manifest content", manifestDig))

			index, err = common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			_, _, err = storage.CheckManifestAndConfig(repoName, manifestDescriptor, []byte("invalid content"), imgStore)
			So(err, ShouldNotBeNil)
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := imgStore.GetBlobContent(repoName, image.ConfigDescriptor.Digest)
			So(err, ShouldBeNil)

			// delete content of config file
			configDig := image.ConfigDescriptor.Digest.Encoded()
			configFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", configDig)
			err = driver.Delete(configFile)
			So(err, ShouldBeNil)

			defer func() {
				// put config content back to file
				_, err = driver.WriteFile(configFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", configDig))

			_, err = driver.WriteFile(configFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid server config", configDig))
		})

		Convey("Layers integrity affected", func() {
			// get content of layer
			content, err := imgStore.GetBlobContent(repoName, image.Manifest.Layers[0].Digest)
			So(err, ShouldBeNil)

			// delete content of layer file
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layerDig)
			_, err = driver.WriteFile(layerFile, []byte(" "))
			So(err, ShouldBeNil)

			defer func() {
				// put layer content back to file
				_, err = driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s bad blob digest", layerDig))
		})

		Convey("Layer not found", func() {
			// get content of layer
			digest := image.Manifest.Layers[0].Digest
			content, err := imgStore.GetBlobContent(repoName, digest)
			So(err, ShouldBeNil)

			// change layer file permissions
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			repoDir := path.Join(imgStore.RootDir(), repoName)
			layerFile := path.Join(repoDir, "/blobs/sha256", layerDig)
			err = driver.Delete(layerFile)
			So(err, ShouldBeNil)

			defer func() {
				_, err := driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)

			// get content of layer
			imageRes := storage.CheckLayers(repoName, tag, []ispec.Descriptor{{Digest: digest}}, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "blob not found")

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", layerDig))
		})

		Convey("Scrub index with missing manifest blob - graceful handling", func() {
			// Create a multiarch image with multiple manifests
			multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
			err = WriteMultiArchImageToFileSystem(multiarchImage, repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			// Get the index to find the index manifest digest
			idx, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			// Find the index manifest
			var indexManifestDesc ispec.Descriptor

			for _, desc := range idx.Manifests {
				if desc.MediaType == ispec.MediaTypeImageIndex {
					indexManifestDesc = desc

					break
				}
			}

			// Get the index content to find the manifest digests within it
			indexBlob, err := imgStore.GetBlobContent(repoName, indexManifestDesc.Digest)
			So(err, ShouldBeNil)

			var indexContent ispec.Index
			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			// Delete one of the manifest blobs within the index (but not all)
			missingManifestDig := indexContent.Manifests[0].Digest.Encoded()
			missingManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", missingManifestDig)
			err = driver.Delete(missingManifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to missing manifest
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 2.0 affected")
			// Should continue processing and report the missing manifest
			So(actual, ShouldContainSubstring, missingManifestDig)
		})

		Convey("Scrub index with non-missing error on manifest blob via file permissions", func() {
			// Skip for non-local storage (S3/DynamoDB) since we can't chmod remote files
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			// Create a multiarch image with multiple manifests
			multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
			err = WriteMultiArchImageToFileSystem(multiarchImage, repoName, "2.1", storeCtlr)
			So(err, ShouldBeNil)

			// Get the index to find the index manifest digest
			idx, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			// Find the index manifest
			var indexManifestDesc ispec.Descriptor

			for _, desc := range idx.Manifests {
				if desc.MediaType == ispec.MediaTypeImageIndex {
					indexManifestDesc = desc

					break
				}
			}

			// Get the index content to find the manifest digests within it
			indexBlob, err := imgStore.GetBlobContent(repoName, indexManifestDesc.Digest)
			So(err, ShouldBeNil)

			var indexContent ispec.Index
			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			// Remove read permissions on one of the manifest blobs to cause a permission denied error (non-missing error)
			manifestDig := indexContent.Manifests[0].Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = os.Chmod(manifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(manifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to non-missing error on manifest
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 2.1 affected")
			// Should report the manifest digest as affected blob
			So(actual, ShouldContainSubstring, manifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})

		Convey("Scrub index", func() {
			newImage := CreateRandomImage()
			newManifestDigest := newImage.ManifestDescriptor.Digest

			err = WriteImageToFileSystem(newImage, repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			idx, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(idx, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			var index ispec.Index
			index.SchemaVersion = 2
			index.Subject = &manifestDescriptor
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    newManifestDigest,
					Size:      newImage.ManifestDescriptor.Size,
				},
			}

			indexBlob, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest, _, err := imgStore.PutImageManifest(repoName, "", ispec.MediaTypeImageIndex, indexBlob)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test ok")

			// test scrub context done
			buff = bytes.NewBufferString("")

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err = storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
			So(actual, ShouldNotContainSubstring, "test ok")

			// test scrub index - errors
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", newManifestDigest.Encoded())
			_, err = driver.WriteFile(manifestFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			// delete content of manifest file
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			indexFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", indexDigest.Encoded())
			err = driver.Delete(indexFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldNotContainSubstring, "test affected")

			index.Manifests[0].MediaType = "invalid"
			indexBlob, err = json.Marshal(index)
			So(err, ShouldBeNil)

			_, err = driver.WriteFile(indexFile, indexBlob)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			_, _, err = storage.CheckManifestAndConfig(repoName, index.Manifests[0], []byte{}, imgStore)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			_, err = driver.WriteFile(indexFile, []byte("invalid cotent"))
			So(err, ShouldBeNil)

			defer func() {
				err := driver.Delete(indexFile)
				So(err, ShouldBeNil)
			}()

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")
		})

		Convey("Manifest not found", func() {
			// delete manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", manifestDig))

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("use the result of an already scrubed manifest which is the subject of the current manifest", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteImageToFileSystem(CreateDefaultImageWith().Subject(&manifestDescriptor).Build(),
				repoName, "0.0.1", storeCtlr)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test 0.0.1 ok")
		})

		Convey("preserve affected status when CheckLayers would overwrite it", func() {
			// Create an image with a subject
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			subjectImage := CreateDefaultImageWith().Subject(&manifestDescriptor).Build()
			err = WriteImageToFileSystem(subjectImage, repoName, "0.0.3", storeCtlr)
			So(err, ShouldBeNil)

			// Delete the subject manifest to mark it as affected
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)
			err = driver.Delete(subjectManifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// The manifest with the missing subject should be marked as affected
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.3 affected")
			// Even if CheckLayers would pass, the affected status from the missing subject should be preserved
			So(actual, ShouldContainSubstring, subjectManifestDig)
		})

		Convey("the subject of the current manifest doesn't exist", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteImageToFileSystem(CreateDefaultImageWith().Subject(&manifestDescriptor).Build(),
				repoName, "0.0.2", storeCtlr)
			So(err, ShouldBeNil)

			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, manifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.2 affected")
		})

		Convey("the subject of the current index doesn't exist", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(1).Subject(&manifestDescriptor).Build(),
				repoName, "0.0.2", storeCtlr)
			So(err, ShouldBeNil)

			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, manifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.2 affected")
		})

		Convey("test errors", func() {
			mockedImgStore := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				ValidateRepoFn: func(name string) (bool, error) {
					return false, nil
				},
			}

			storeController := storage.StoreController{}
			storeController.DefaultStore = mockedImgStore

			_, err := storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrRepoBadLayout)

			mockedImgStore = mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte{}, errUnexpectedError
				},
			}

			storeController.DefaultStore = mockedImgStore

			_, err = storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, errUnexpectedError)

			manifestDigest := godigest.FromString("abcd")

			mockedImgStore = mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					var index ispec.Index
					index.SchemaVersion = 2
					index.Manifests = []ispec.Descriptor{
						{
							MediaType:   "InvalidMediaType",
							Digest:      manifestDigest,
							Size:        int64(100),
							Annotations: map[string]string{ispec.AnnotationRefName: "1.0"},
						},
					}

					return json.Marshal(index)
				},
			}

			storeController.DefaultStore = mockedImgStore

			res, err := storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")
			res.PrintScrubResults(buff)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("%s 1.0 affected %s invalid manifest content",
				repoName, manifestDigest.Encoded()))
		})

		Convey("scrub with non-missing error on manifest subject blob via file permissions", func() {
			// Skip for non-local storage (S3/DynamoDB) since we can't chmod remote files
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			// Create an image with a subject
			subjectImage := CreateDefaultImageWith().Subject(&manifestDescriptor).Build()
			err = WriteImageToFileSystem(subjectImage, repoName, "0.0.6", storeCtlr)
			So(err, ShouldBeNil)

			// Get the subject manifest digest
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)

			// Remove read permissions to cause a permission denied error (non-missing error)
			err = os.Chmod(subjectManifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(subjectManifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the manifest as affected due to non-missing error on subject
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.6 affected")
			// Should report the subject digest as affected blob
			So(actual, ShouldContainSubstring, subjectManifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})

		Convey("scrub with non-missing error on index subject blob via file permissions", func() {
			// Skip for non-local storage (S3/DynamoDB) since we can't chmod remote files
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			// Create a multiarch image with a subject
			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(1).Subject(&manifestDescriptor).Build(),
				repoName, "0.0.7", storeCtlr)
			So(err, ShouldBeNil)

			// Get the subject manifest digest
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)

			// Remove read permissions to cause a permission denied error (non-missing error)
			err = os.Chmod(subjectManifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(subjectManifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to non-missing error on subject
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.7 affected")
			// Should report the subject digest as affected blob
			So(actual, ShouldContainSubstring, subjectManifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})
	})
}
