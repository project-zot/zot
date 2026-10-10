package gcs_test

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
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/gcsemulator"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

//nolint:gochecknoglobals // test constants
const (
	repoName = "test"
)

var errUnexpectedError = errors.New("unexpected err") //nolint: gochecknoglobals

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

// createObjectsStore creates a GCS-backed store; dedupe is always true at call sites.
//
//nolint:unparam
func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	const bucket = "zot-storage-test"

	if err := gcsemulator.CreateBucket(bucket); err != nil {
		return nil, nil, err
	}

	params := map[string]any{
		"rootdirectory": rootDir,
		"name":          storageConstants.GCSStorageDriverName,
		"bucket":        bucket,
	}
	// Mirror production: default the prefix and pass RootDir() ("/") into the image store
	// so the driver (not the image store) owns the rootdirectory prefix.
	storage.NormalizeRootDirectory(storageConstants.GCSStorageDriverName, params)

	store, err := factory.Create(context.Background(), storageConstants.GCSStorageDriverName, params)
	if err != nil {
		return nil, nil, err
	}

	log := log.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

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

	il := gcs.NewImageStore(storage.RootDir(storageConstants.GCSStorageDriverName, params),
		cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, nil
}

func TestGCSDedupe(t *testing.T) {
	tskip.SkipGCS(t)

	Convey("Dedupe", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, "/")

		// manifest1
		upload, err := imgStore.NewBlobUpload(context.Background(), "dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed(context.Background(), "dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := digest
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize1, err := imgStore.CheckBlob(context.Background(), "dedupe1", digest)
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
		_, clen, err := imgStore.FullBlobUpload(context.Background(), "dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob(context.Background(), "dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest := ispec.Manifest{
			SchemaVersion: 2,
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

		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)

		_, _, err = imgStore.PutImageManifest(context.Background(), "dedupe1", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf, nil)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", manifestDigest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload(context.Background(), "dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunkStreamed(context.Background(), "dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest2 := digest
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize2, err := imgStore.CheckBlob(context.Background(), "dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize2, _, err = imgStore.StatBlob("dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload(context.Background(), "dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err = imgStore.CheckBlob(context.Background(), "dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest = ispec.Manifest{
			SchemaVersion: 2,
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

		manifestBuf, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest = godigest.FromBytes(manifestBuf)

		_, _, err = imgStore.PutImageManifest(context.Background(), "dedupe2", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf, nil)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", manifestDigest.String())
		So(err, ShouldBeNil)

		So(blobDigest1, ShouldEqual, blobDigest2)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)
	})
}

func TestGCSPullRange(t *testing.T) {
	tskip.SkipGCS(t)

	Convey("Pull range", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, "/")

		upload, err := imgStore.NewBlobUpload(context.Background(), "test")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed(context.Background(), "test", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("test", upload, buf, digest)
		So(err, ShouldBeNil)

		blobReadCloser, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 0, 4)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "test-")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range - "data3" is bytes 5-9 (inclusive) of "test-data3"
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 5, 9)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "data3")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range from negative offset
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", -4, 4)
		So(err, ShouldNotBeNil)
		So(blobReadCloser, ShouldBeNil)
	})
}

func TestGCSCheckAllBlobsIntegrity(t *testing.T) {
	tskip.SkipGCS(t)

	Convey("test with GCS storage", t, func() {
		uuid, err := guuid.NewV4()
		So(err, ShouldBeNil)

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)

		defer cleanupStorage(storeDriver, "/")

		testLog := log.NewTestLogger()

		RunGCSCheckAllBlobsIntegrityTests(t, imgStore, gcs.New(storeDriver), testLog)
	})
}

func RunGCSCheckAllBlobsIntegrityTests( //nolint: thelper
	t *testing.T, imgStore storageTypes.ImageStore, driver storageTypes.Driver, testLog log.Logger,
) {
	Convey("Scrub only one repo", func() {
		// initialize repo
		err := imgStore.InitRepo(context.Background(), repoName)
		So(err, ShouldBeNil)

		ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
		So(ok, ShouldBeTrue)

		storeCtlr := storage.StoreController{}
		storeCtlr.DefaultStore = imgStore
		So(storeCtlr.GetImageStore(repoName), ShouldResemble, imgStore)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repoName, "1.0", storeCtlr)
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
			// Top-level listed manifest Missing is soft-skipped (concurrent delete race).
			So(actual, ShouldNotContainSubstring, "affected")

			index, err := common.GetIndex(imgStore, repoName, testLog)
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

			index, err = common.GetIndex(imgStore, repoName, testLog)
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

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)

			// get content of layer
			imageRes := storage.CheckLayers(repoName, "1.0", []ispec.Descriptor{{Digest: digest}}, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			// mapStorageErr wraps Missing under ErrBlobNotFound; match the sentinel text.
			So(imageRes.Error, ShouldContainSubstring, "blob not found")

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
			idx, err := common.GetIndex(imgStore, repoName, testLog)
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
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			// Create a multiarch image with multiple manifests
			multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
			err = WriteMultiArchImageToFileSystem(multiarchImage, repoName, "2.1", storeCtlr)
			So(err, ShouldBeNil)

			// Get the index to find the index manifest digest
			idx, err := common.GetIndex(imgStore, repoName, testLog)
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

			idx, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(idx, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			index := ispec.Index{
				SchemaVersion: 2,
				Subject:       &manifestDescriptor,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    newManifestDigest,
						Size:      newImage.ManifestDescriptor.Size,
					},
				},
			}

			indexBlob, err := json.Marshal(index)
			So(err, ShouldBeNil)

			indexDigest, _, err := imgStore.PutImageManifest(
				context.Background(), repoName, "", ispec.MediaTypeImageIndex, indexBlob, nil)
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
			// Top-level listed index blob Missing is soft-skipped (concurrent delete race).
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
			// Top-level listed manifest Missing is soft-skipped (concurrent delete race).
			So(actual, ShouldNotContainSubstring, "test 1.0 affected "+manifestDig+" blob not found")

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("use the result of an already scrubed manifest which is the subject of the current manifest", func() {
			index, err := common.GetIndex(imgStore, repoName, testLog)
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
			index, err := common.GetIndex(imgStore, repoName, testLog)
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
			index, err := common.GetIndex(imgStore, repoName, testLog)
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
			index, err := common.GetIndex(imgStore, repoName, testLog)
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
					index := ispec.Index{
						SchemaVersion: 2,
						Manifests: []ispec.Descriptor{
							{
								MediaType:   "InvalidMediaType",
								Digest:      manifestDigest,
								Size:        int64(100),
								Annotations: map[string]string{ispec.AnnotationRefName: "1.0"},
							},
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
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, testLog)
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
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, testLog)
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
