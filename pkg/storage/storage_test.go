package storage_test

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
	"sync"
	"testing"
	"time"

	// Add s3 support.
	"github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/factory"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	storageCommon "zotregistry.dev/zot/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/gc"
	"zotregistry.dev/zot/pkg/storage/imagestore"
	"zotregistry.dev/zot/pkg/storage/local"
	"zotregistry.dev/zot/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

var trueVal bool = true //nolint: gochecknoglobals

var DeleteReferrers = config.ImageRetention{ //nolint: gochecknoglobals
	Delay: storageConstants.DefaultRetentionDelay,
	Policies: []config.RetentionPolicy{
		{
			Repositories:    []string{"**"},
			DeleteReferrers: true,
			DeleteUntagged:  &trueVal,
		},
	},
}

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func createObjectsStore(rootDir string, cacheDir string) (
	driver.StorageDriver, storageTypes.ImageStore, error,
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

	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)

	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     cacheDir,
		Name:        "cache",
		UseRelPaths: false,
	}, log)

	il := s3.NewImageStore(rootDir, cacheDir, true, false, log, metrics, nil, store, cacheDriver)

	return store, il, err
}

//nolint:gochecknoglobals
var testCases = []struct {
	testCaseName string
	storageType  string
}{
	{
		testCaseName: "S3APIs",
		storageType:  storageConstants.S3StorageDriverName,
	},
	{
		testCaseName: "FileSystemAPIs",
		storageType:  storageConstants.LocalStorageDriverName,
	},
}

func TestStorageNew(t *testing.T) {
	Convey("New fail", t, func() {
		// store name is wrong
		conf := config.New()
		conf.Storage.RootDirectory = "dir"
		conf.Storage.StorageDriver = map[string]interface{}{}

		_, err := storage.New(conf, nil, nil, zlog.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})
}

func TestStorageAPIs(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore
			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir := path.Join("/oci-repo-test", uuid.String())
				tdir := t.TempDir()

				var store driver.StorageDriver
				store, imgStore, _ = createObjectsStore(testDir, tdir)
				defer cleanupStorage(store, testDir)
			} else {
				dir := t.TempDir()

				log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
				metrics := monitoring.NewMetricsServer(false, log)
				cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     dir,
					Name:        "cache",
					UseRelPaths: true,
				}, log)

				driver := local.New(true)

				imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
			}

			Convey("Repo layout", t, func(c C) {
				repoName := "test"

				Convey("Get all blobs from repo without initialization", func() {
					allBlobs, err := imgStore.GetAllBlobs(repoName)
					So(err, ShouldBeNil)
					So(allBlobs, ShouldBeEmpty)

					ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
					So(ok, ShouldBeFalse)
				})

				Convey("Validate repo without initialization", func() {
					v, err := imgStore.ValidateRepo(repoName)
					So(v, ShouldEqual, false)
					So(err, ShouldNotBeNil)
					ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
					So(ok, ShouldBeFalse)
				})

				Convey("Initialize repo", func() {
					err := imgStore.InitRepo(repoName)
					So(err, ShouldBeNil)
					ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
					So(ok, ShouldBeTrue)
					storeController := storage.StoreController{}
					storeController.DefaultStore = imgStore
					So(storeController.GetImageStore("test"), ShouldResemble, imgStore)
				})

				Convey("Validate repo", func() {
					repos, err := imgStore.ValidateRepo(repoName)
					So(err, ShouldBeNil)
					So(repos, ShouldEqual, true)
				})

				Convey("Get repos", func() {
					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(repos, ShouldNotBeEmpty)
				})

				Convey("Get image tags", func() {
					v, err := imgStore.GetImageTags("test")
					So(err, ShouldBeNil)
					So(v, ShouldBeEmpty)
				})

				Convey("Full blob upload", func() {
					body := []byte("this is a blob")
					buf := bytes.NewBuffer(body)
					digest := godigest.FromBytes(body)
					upload, n, err := imgStore.FullBlobUpload("test", buf, digest)
					So(err, ShouldBeNil)
					So(n, ShouldEqual, len(body))
					So(upload, ShouldNotBeEmpty)

					err = imgStore.VerifyBlobDigestValue("test", digest)
					So(err, ShouldBeNil)
				})

				Convey("New blob upload", func() {
					upload, err := imgStore.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					err = imgStore.DeleteBlobUpload("test", upload)
					So(err, ShouldBeNil)

					upload, err = imgStore.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					Convey("Get blob upload", func() {
						bupload, err := imgStore.GetBlobUpload("test", "invalid")
						So(err, ShouldNotBeNil)
						So(bupload, ShouldEqual, -1)

						bupload, err = imgStore.GetBlobUpload("hi", " \255")
						So(err, ShouldNotBeNil)
						So(bupload, ShouldEqual, -1)

						bupload, err = imgStore.GetBlobUpload("test", upload)
						So(err, ShouldBeNil)
						So(bupload, ShouldBeGreaterThanOrEqualTo, 0)

						bupload, err = imgStore.BlobUploadInfo("test", upload)
						So(err, ShouldBeNil)
						So(bupload, ShouldBeGreaterThanOrEqualTo, 0)

						content := []byte("test-data1")
						firstChunkContent := []byte("test")
						firstChunkBuf := bytes.NewBuffer(firstChunkContent)
						secondChunkContent := []byte("-data1")
						secondChunkBuf := bytes.NewBuffer(secondChunkContent)
						firstChunkLen := firstChunkBuf.Len()
						secondChunkLen := secondChunkBuf.Len()

						buf := bytes.NewBuffer(content)
						buflen := buf.Len()
						digest := godigest.FromBytes(content)
						blobDigest := digest

						// invalid chunk range
						_, err = imgStore.PutBlobChunk("test", upload, 10, int64(buflen), buf)
						So(err, ShouldNotBeNil)

						bupload, err = imgStore.PutBlobChunk("test", upload, 0, int64(firstChunkLen), firstChunkBuf)
						So(err, ShouldBeNil)
						So(bupload, ShouldEqual, firstChunkLen)

						bupload, err = imgStore.GetBlobUpload("test", upload)
						So(err, ShouldBeNil)
						So(bupload, ShouldEqual, int64(firstChunkLen))

						bupload, err = imgStore.BlobUploadInfo("test", upload)
						So(err, ShouldBeNil)
						So(bupload, ShouldEqual, int64(firstChunkLen))

						bupload, err = imgStore.PutBlobChunk("test", upload, int64(firstChunkLen), int64(buflen), secondChunkBuf)
						So(err, ShouldBeNil)
						So(bupload, ShouldEqual, secondChunkLen)

						err = imgStore.FinishBlobUpload("test", upload, buf, digest)
						So(err, ShouldBeNil)

						_, _, err = imgStore.CheckBlob("test", digest)
						So(err, ShouldBeNil)

						ok, _, _, err := imgStore.StatBlob("test", digest)
						So(ok, ShouldBeTrue)
						So(err, ShouldBeNil)

						blob, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)

						blobBuf := new(strings.Builder)
						n, err := io.Copy(blobBuf, blob)
						// check errors
						So(n, ShouldEqual, buflen)
						So(err, ShouldBeNil)
						So(blobBuf.String(), ShouldEqual, buf.String())

						blobContent, err := imgStore.GetBlobContent("test", digest)
						So(err, ShouldBeNil)
						So(blobContent, ShouldResemble, content)

						err = blob.Close()
						So(err, ShouldBeNil)

						manifest := ispec.Manifest{}
						manifest.SchemaVersion = 2
						manifestBuf, err := json.Marshal(manifest)
						So(err, ShouldBeNil)

						Convey("Bad image manifest", func() {
							_, _, err = imgStore.PutImageManifest("test", digest.String(), "application/json",
								manifestBuf)
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								[]byte{})
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								[]byte(`{"test":true}`))
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								manifestBuf)
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("inexistent", digest.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							cblob, cdigest := GetRandomImageConfig()
							_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
							So(err, ShouldBeNil)
							So(clen, ShouldEqual, len(cblob))
							hasBlob, _, err := imgStore.CheckBlob("test", cdigest)
							So(err, ShouldBeNil)
							So(hasBlob, ShouldEqual, true)

							annotationsMap := make(map[string]string)
							annotationsMap[ispec.AnnotationRefName] = "1.0"
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
								Annotations: annotationsMap,
							}

							manifest.SchemaVersion = 2
							manifestBuf, err = json.Marshal(manifest)
							So(err, ShouldBeNil)
							digest := godigest.FromBytes(manifestBuf)

							// bad manifest
							manifest.Layers[0].Digest = godigest.FromBytes([]byte("inexistent"))
							badMb, err := json.Marshal(manifest)
							So(err, ShouldBeNil)

							_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, badMb)
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, _, err = imgStore.PutImageManifest("test", "2.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, _, err = imgStore.PutImageManifest("test", "3.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, err = imgStore.GetImageTags("inexistent")
							So(err, ShouldNotBeNil)

							// total tags should be 3 but they have same reference.
							tags, err := imgStore.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 3)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", "3.0")
							So(err, ShouldBeNil)

							err = imgStore.DeleteImageManifest("test", "1.0", false)
							So(err, ShouldBeNil)

							tags, err = imgStore.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 2)

							repos, err := imgStore.GetRepositories()
							So(err, ShouldBeNil)
							So(len(repos), ShouldEqual, 1)
							So(repos[0], ShouldEqual, "test")

							// We deleted only one tag, make sure blob should not be removed.
							hasBlob, _, err = imgStore.CheckBlob("test", digest)
							So(err, ShouldBeNil)
							So(hasBlob, ShouldEqual, true)

							// with detectManifestCollision should get error
							err = imgStore.DeleteImageManifest("test", digest.String(), true)
							So(err, ShouldNotBeNil)

							// If we pass reference all manifest with input reference should be deleted.
							err = imgStore.DeleteImageManifest("test", digest.String(), false)
							So(err, ShouldBeNil)

							tags, err = imgStore.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 0)

							// All tags/references are deleted, blob should not be present in disk.
							hasBlob, _, err = imgStore.CheckBlob("test", digest)
							So(err, ShouldNotBeNil)
							So(hasBlob, ShouldEqual, false)

							hasBlob, _, _, err = imgStore.StatBlob("test", digest)
							So(err, ShouldNotBeNil)
							So(hasBlob, ShouldEqual, false)

							err = imgStore.DeleteBlob("test", "inexistent")
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteBlob("test", godigest.FromBytes([]byte("inexistent")))
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteBlob("test", blobDigest)
							So(err, ShouldBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)
						})
					})

					err = imgStore.DeleteBlobUpload("test", upload)
					So(err, ShouldNotBeNil)
				})

				Convey("New blob upload streamed", func() {
					bupload, err := imgStore.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(bupload, ShouldNotBeEmpty)

					Convey("Get blob upload", func() {
						upload, err := imgStore.GetBlobUpload("test", "invalid")
						So(err, ShouldNotBeNil)
						So(upload, ShouldEqual, -1)

						upload, err = imgStore.GetBlobUpload("test", bupload)
						So(err, ShouldBeNil)
						So(upload, ShouldBeGreaterThanOrEqualTo, 0)

						_, err = imgStore.BlobUploadInfo("test", "inexistent")
						So(err, ShouldNotBeNil)

						upload, err = imgStore.BlobUploadInfo("test", bupload)
						So(err, ShouldBeNil)
						So(upload, ShouldBeGreaterThanOrEqualTo, 0)

						content := []byte("test-data2")
						buf := bytes.NewBuffer(content)
						buflen := buf.Len()
						digest := godigest.FromBytes(content)
						upload, err = imgStore.PutBlobChunkStreamed("test", bupload, buf)
						So(err, ShouldBeNil)
						So(upload, ShouldEqual, buflen)

						_, err = imgStore.PutBlobChunkStreamed("test", "inexistent", buf)
						So(err, ShouldNotBeNil)

						err = imgStore.FinishBlobUpload("test", "inexistent", buf, digest)
						So(err, ShouldNotBeNil)

						// invalid digest
						err = imgStore.FinishBlobUpload("test", "inexistent", buf, "sha256:invalid")
						So(err, ShouldNotBeNil)

						err = imgStore.FinishBlobUpload("test", bupload, buf, digest)
						So(err, ShouldBeNil)

						ok, _, err := imgStore.CheckBlob("test", digest)
						So(ok, ShouldBeTrue)
						So(err, ShouldBeNil)

						ok, _, _, err = imgStore.StatBlob("test", digest)
						So(ok, ShouldBeTrue)
						So(err, ShouldBeNil)

						_, _, err = imgStore.GetBlob("test", "inexistent", "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldNotBeNil)

						blob, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)
						err = blob.Close()
						So(err, ShouldBeNil)

						blobContent, err := imgStore.GetBlobContent("test", digest)
						So(err, ShouldBeNil)
						So(content, ShouldResemble, blobContent)

						_, err = imgStore.GetBlobContent("inexistent", digest)
						So(err, ShouldNotBeNil)

						manifest := ispec.Manifest{}
						manifest.SchemaVersion = 2
						manifestBuf, err := json.Marshal(manifest)
						So(err, ShouldBeNil)

						Convey("Bad digests", func() {
							_, _, err := imgStore.FullBlobUpload("test", bytes.NewBuffer([]byte{}), "inexistent")
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.CheckBlob("test", "inexistent")
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.StatBlob("test", "inexistent")
							So(err, ShouldNotBeNil)
						})

						Convey("Bad image manifest", func() {
							_, _, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldNotBeNil)

							_, _, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, []byte("bad json"))
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							cblob, cdigest := GetRandomImageConfig()
							_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
							So(err, ShouldBeNil)
							So(clen, ShouldEqual, len(cblob))
							hasBlob, _, err := imgStore.CheckBlob("test", cdigest)
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
							manifestBuf, err = json.Marshal(manifest)
							So(err, ShouldBeNil)
							digest := godigest.FromBytes(manifestBuf)
							_, _, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, _, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldBeNil)

							_, err = imgStore.GetIndexContent("inexistent")
							So(err, ShouldNotBeNil)

							indexContent, err := imgStore.GetIndexContent("test")
							So(err, ShouldBeNil)

							if testcase.storageType == storageConstants.LocalStorageDriverName {
								err = os.Chmod(path.Join(imgStore.RootDir(), "test", "index.json"), 0o000)
								So(err, ShouldBeNil)
								_, err = imgStore.GetIndexContent("test")
								So(err, ShouldNotBeNil)
								err = os.Chmod(path.Join(imgStore.RootDir(), "test", "index.json"), 0o644)
								So(err, ShouldBeNil)
							}

							var index ispec.Index

							err = json.Unmarshal(indexContent, &index)
							So(err, ShouldBeNil)

							So(len(index.Manifests), ShouldEqual, 1)
							err = imgStore.DeleteImageManifest("test", "1.0", false)
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteImageManifest("inexistent", "1.0", false)
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteImageManifest("test", digest.String(), false)
							So(err, ShouldBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)
						})
					})

					err = imgStore.DeleteBlobUpload("test", bupload)
					So(err, ShouldNotBeNil)
				})

				Convey("Modify manifest in-place", func() {
					// original blob
					upload, err := imgStore.NewBlobUpload("replace")
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content := []byte("test-data-replace-1")
					buf := bytes.NewBuffer(content)
					buflen := buf.Len()
					digest := godigest.FromBytes(content)
					blob, err := imgStore.PutBlobChunkStreamed("replace", upload, buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)
					blobDigest1 := strings.Split(digest.String(), ":")[1]
					So(blobDigest1, ShouldNotBeEmpty)

					err = imgStore.FinishBlobUpload("replace", upload, buf, digest)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err := imgStore.CheckBlob("replace", cdigest)
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
					_, _, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("replace", digest.String())
					So(err, ShouldBeNil)

					// new blob to replace
					upload, err = imgStore.NewBlobUpload("replace")
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content = []byte("test-data-replace-2")
					buf = bytes.NewBuffer(content)
					buflen = buf.Len()
					digest = godigest.FromBytes(content)
					blob, err = imgStore.PutBlobChunkStreamed("replace", upload, buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)
					blobDigest2 := strings.Split(digest.String(), ":")[1]
					So(blobDigest2, ShouldNotBeEmpty)

					err = imgStore.FinishBlobUpload("replace", upload, buf, digest)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					cblob, cdigest = GetRandomImageConfig()
					_, clen, err = imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err = imgStore.CheckBlob("replace", cdigest)
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
					_ = godigest.FromBytes(manifestBuf)
					_, _, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)
				})

				Convey("Locks", func() {
					// in parallel, a mix of read and write locks - mainly for coverage
					var wg sync.WaitGroup
					for i := 0; i < 1000; i++ {
						wg.Add(2)
						go func() {
							var lockLatency time.Time
							defer wg.Done()
							imgStore.Lock(&lockLatency)
							func() {}()
							imgStore.Unlock(&lockLatency)
						}()
						go func() {
							var lockLatency time.Time
							defer wg.Done()
							imgStore.RLock(&lockLatency)
							func() {}()
							imgStore.RUnlock(&lockLatency)
						}()
					}
					wg.Wait()
				})
			})
		})
	}
}

func TestMandatoryAnnotations(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore
			var testDir, tdir string
			var store driver.StorageDriver

			log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)

			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir = path.Join("/oci-repo-test", uuid.String())
				tdir = t.TempDir()

				store, _, _ = createObjectsStore(testDir, tdir)
				driver := s3.New(store)
				imgStore = imagestore.NewImageStore(testDir, tdir, false, false, log, metrics,
					&mocks.MockedLint{
						LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
							return false, nil
						},
					}, driver, nil)

				defer cleanupStorage(store, testDir)
			} else {
				tdir = t.TempDir()
				cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     tdir,
					Name:        "cache",
					UseRelPaths: true,
				}, log)
				driver := local.New(true)
				imgStore = imagestore.NewImageStore(tdir, tdir, true,
					true, log, metrics, &mocks.MockedLint{
						LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
							return false, nil
						},
					}, driver, cacheDriver)
			}

			Convey("Setup manifest", t, func() {
				content := []byte("test-data1")
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				_, _, err := imgStore.FullBlobUpload("test", bytes.NewReader(buf.Bytes()), digest)
				So(err, ShouldBeNil)

				cblob, cdigest := GetRandomImageConfig()
				_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
				So(err, ShouldBeNil)
				So(clen, ShouldEqual, len(cblob))

				annotationsMap := make(map[string]string)
				annotationsMap[ispec.AnnotationRefName] = "1.0"

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				Convey("Missing mandatory annotations", func() {
					_, _, err = imgStore.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldNotBeNil)
				})

				Convey("Error on mandatory annotations", func() {
					if testcase.storageType == storageConstants.S3StorageDriverName {
						driver := s3.New(store)
						imgStore = imagestore.NewImageStore(testDir, tdir, false, false, log, metrics,
							&mocks.MockedLint{
								LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
									//nolint: goerr113
									return false, errors.New("linter error")
								},
							}, driver, nil)
					} else {
						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     tdir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)
						driver := local.New(true)
						imgStore = imagestore.NewImageStore(tdir, tdir, true,
							true, log, metrics, &mocks.MockedLint{
								LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
									//nolint: goerr113
									return false, errors.New("linter error")
								},
							}, driver, cacheDriver)
					}

					_, _, err = imgStore.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldNotBeNil)
				})
			})
		})
	}
}

func TestStorageSubpaths(t *testing.T) {
	Convey("Reach for coverage", t, func() {
		tmpDirSubpath := t.TempDir()
		config := &config.Config{
			Storage: config.GlobalStorageConfig{
				StorageConfig: config.StorageConfig{RootDirectory: t.TempDir()},
				SubPaths: map[string]config.StorageConfig{
					"a/":          {RootDirectory: tmpDirSubpath},
					tmpDirSubpath: {RootDirectory: tmpDirSubpath},
				},
			},
		}

		_, err := storage.New(config, nil, nil, zlog.NewLogger("debug", ""))
		So(err, ShouldBeNil)
	})

	Convey("Create unique subpath, error for cache driver", t, func() {
		tmpDirSubpath := t.TempDir()
		config := &config.Config{
			Storage: config.GlobalStorageConfig{
				StorageConfig: config.StorageConfig{RootDirectory: t.TempDir()},
				SubPaths: map[string]config.StorageConfig{
					"a/": {
						RootDirectory: tmpDirSubpath,
						RemoteCache:   true,
						StorageDriver: map[string]interface{}{},
						Dedupe:        true,
					},
				},
			},
		}

		// create boltdb file and make it un-openable
		dbPath := path.Join(tmpDirSubpath, storageConstants.BoltdbName+storageConstants.DBExtensionName)
		err := os.WriteFile(dbPath, []byte(""), 0o000)
		So(err, ShouldBeNil)

		_, err = storage.New(config, nil, nil, zlog.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		err = os.Chmod(dbPath, 0o600)
		So(err, ShouldBeNil)
	})

	Convey("storeName != constants.S3StorageDriverName", t, func() {
		tmpDirSubpath := t.TempDir()
		config := &config.Config{
			Storage: config.GlobalStorageConfig{
				StorageConfig: config.StorageConfig{RootDirectory: t.TempDir()},
				SubPaths: map[string]config.StorageConfig{
					"a/": {
						RootDirectory: tmpDirSubpath,
						RemoteCache:   true,
						StorageDriver: map[string]interface{}{
							"name": "bad-name",
						},
					},
				},
			},
		}

		_, err := storage.New(config, nil, nil, zlog.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})
}

func TestDeleteBlobsInUse(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore
			var testDir, tdir string
			var store driver.StorageDriver

			log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)

			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir = path.Join("/oci-repo-test", uuid.String())
				tdir = t.TempDir()

				store, imgStore, _ = createObjectsStore(testDir, tdir)

				defer cleanupStorage(store, testDir)
			} else {
				tdir = t.TempDir()
				cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     tdir,
					Name:        "cache",
					UseRelPaths: true,
				}, log)
				driver := local.New(true)
				imgStore = imagestore.NewImageStore(tdir, tdir, true,
					true, log, metrics, nil, driver, cacheDriver)
			}

			Convey("Setup manifest", t, func() {
				// put an unused blob
				content := []byte("unused blob")
				buf := bytes.NewBuffer(content)
				unusedDigest := godigest.FromBytes(content)

				_, _, err := imgStore.FullBlobUpload("repo", bytes.NewReader(buf.Bytes()), unusedDigest)
				So(err, ShouldBeNil)

				content = []byte("test-data1")
				buf = bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				_, _, err = imgStore.FullBlobUpload("repo", bytes.NewReader(buf.Bytes()), digest)
				So(err, ShouldBeNil)

				cblob, cdigest := GetRandomImageConfig()
				_, clen, err := imgStore.FullBlobUpload("repo", bytes.NewReader(cblob), cdigest)
				So(err, ShouldBeNil)
				So(clen, ShouldEqual, len(cblob))

				annotationsMap := make(map[string]string)
				annotationsMap[ispec.AnnotationRefName] = tag

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				manifestDigest, _, err := imgStore.PutImageManifest("repo", tag, ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldBeNil)

				Convey("Try to delete blob currently in use", func() {
					// layer blob
					err := imgStore.DeleteBlob("repo", digest)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)

					// manifest
					err = imgStore.DeleteBlob("repo", manifestDigest)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)

					// config
					err = imgStore.DeleteBlob("repo", cdigest)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)
				})

				Convey("Delete unused blob", func() {
					err := imgStore.DeleteBlob("repo", unusedDigest)
					So(err, ShouldBeNil)
				})

				Convey("Delete manifest first, then blob", func() {
					err := imgStore.DeleteImageManifest("repo", manifestDigest.String(), false)
					So(err, ShouldBeNil)

					err = imgStore.DeleteBlob("repo", digest)
					So(err, ShouldBeNil)

					// config
					err = imgStore.DeleteBlob("repo", cdigest)
					So(err, ShouldBeNil)
				})

				if testcase.storageType != storageConstants.S3StorageDriverName {
					Convey("get image manifest error", func() {
						err := os.Chmod(path.Join(imgStore.RootDir(), "repo", "blobs", "sha256", manifestDigest.Encoded()), 0o000)
						So(err, ShouldBeNil)

						ok, _ := storageCommon.IsBlobReferenced(imgStore, "repo", unusedDigest, log)
						So(ok, ShouldBeFalse)

						err = os.Chmod(path.Join(imgStore.RootDir(), "repo", "blobs", "sha256", manifestDigest.Encoded()), 0o755)
						So(err, ShouldBeNil)
					})
				}
			})

			Convey("Setup multiarch manifest", t, func() {
				// put an unused blob
				content := []byte("unused blob")
				buf := bytes.NewBuffer(content)
				unusedDigest := godigest.FromBytes(content)

				_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(buf.Bytes()), unusedDigest)
				So(err, ShouldBeNil)

				// create a blob/layer
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				content = []byte("this is a blob1")
				buf = bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)
				bdgst1 := digest
				bsize1 := len(content)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				var index ispec.Index
				index.SchemaVersion = 2
				index.MediaType = ispec.MediaTypeImageIndex

				var cdigest godigest.Digest
				var cblob []byte

				//nolint: dupl
				for i := 0; i < 4; i++ {
					// upload image config blob
					upload, err = imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					cblob, cdigest = GetRandomImageConfig()
					buf = bytes.NewBuffer(cblob)
					buflen = buf.Len()
					blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
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
					_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
					So(err, ShouldBeNil)

					index.Manifests = append(index.Manifests, ispec.Descriptor{
						Digest:    digest,
						MediaType: ispec.MediaTypeImageManifest,
						Size:      int64(len(content)),
					})
				}

				// upload index image
				indexContent, err := json.Marshal(index)
				So(err, ShouldBeNil)
				indexDigest := godigest.FromBytes(indexContent)
				So(indexDigest, ShouldNotBeNil)

				indexManifestDigest, _, err := imgStore.PutImageManifest(repoName, "index", ispec.MediaTypeImageIndex, indexContent)
				So(err, ShouldBeNil)

				Convey("Try to delete manifest being referenced by image index", func() {
					// modifying multi arch images should not be allowed
					err := imgStore.DeleteImageManifest(repoName, digest.String(), false)
					So(err, ShouldEqual, zerr.ErrManifestReferenced)
				})

				Convey("Try to delete blob currently in use", func() {
					// layer blob
					err := imgStore.DeleteBlob("test", bdgst1)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)

					// manifest
					err = imgStore.DeleteBlob("test", digest)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)

					// config
					err = imgStore.DeleteBlob("test", cdigest)
					So(err, ShouldEqual, zerr.ErrBlobReferenced)
				})

				Convey("Delete unused blob", func() {
					err := imgStore.DeleteBlob(repoName, unusedDigest)
					So(err, ShouldBeNil)
				})

				Convey("Delete manifests first, then blob", func() {
					err := imgStore.DeleteImageManifest(repoName, indexManifestDigest.String(), false)
					So(err, ShouldBeNil)

					for _, manifestDesc := range index.Manifests {
						err := imgStore.DeleteImageManifest(repoName, manifestDesc.Digest.String(), false)
						So(err, ShouldBeNil)
					}

					err = imgStore.DeleteBlob(repoName, bdgst1)
					So(err, ShouldBeNil)

					// config
					err = imgStore.DeleteBlob("test", cdigest)
					So(err, ShouldBeNil)
				})

				if testcase.storageType != storageConstants.S3StorageDriverName {
					Convey("repo not found", func() {
						// delete repo
						err := os.RemoveAll(path.Join(imgStore.RootDir(), repoName))
						So(err, ShouldBeNil)

						ok, err := storageCommon.IsBlobReferenced(imgStore, repoName, bdgst1, log)
						So(err, ShouldNotBeNil)
						So(ok, ShouldBeFalse)
					})

					Convey("index.json not found", func() {
						err := os.Remove(path.Join(imgStore.RootDir(), repoName, "index.json"))
						So(err, ShouldBeNil)

						ok, err := storageCommon.IsBlobReferenced(imgStore, repoName, bdgst1, log)
						So(err, ShouldNotBeNil)
						So(ok, ShouldBeFalse)
					})

					Convey("multiarch image not found", func() {
						err := os.Remove(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", indexManifestDigest.Encoded()))
						So(err, ShouldBeNil)

						ok, err := storageCommon.IsBlobReferenced(imgStore, repoName, unusedDigest, log)
						So(err, ShouldNotBeNil)
						So(ok, ShouldBeFalse)
					})
				}
			})
		})
	}
}

func TestReuploadCorruptedBlob(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storageTypes.ImageStore
			var testDir, tdir string
			var store driver.StorageDriver
			var driver storageTypes.Driver

			log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)

			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipS3(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir = path.Join("/oci-repo-test", uuid.String())
				tdir = t.TempDir()

				store, imgStore, _ = createObjectsStore(testDir, tdir)
				driver = s3.New(store)
				defer cleanupStorage(store, testDir)
			} else {
				tdir = t.TempDir()
				cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
					RootDir:     tdir,
					Name:        "cache",
					UseRelPaths: true,
				}, log)
				driver = local.New(true)
				imgStore = imagestore.NewImageStore(tdir, tdir, true,
					true, log, metrics, nil, driver, cacheDriver)
			}

			Convey("Test errors paths", t, func() {
				storeController := storage.StoreController{DefaultStore: imgStore}

				image := CreateRandomImage()

				err := WriteImageToFileSystem(image, repoName, tag, storeController)
				So(err, ShouldBeNil)
			})

			Convey("Test reupload repair corrupted image", t, func() {
				storeController := storage.StoreController{DefaultStore: imgStore}

				image := CreateRandomImage()

				err := WriteImageToFileSystem(image, repoName, tag, storeController)
				So(err, ShouldBeNil)

				blob := image.Layers[0]
				blobDigest := godigest.FromBytes(blob)
				blobSize := len(blob)
				blobPath := imgStore.BlobPath(repoName, blobDigest)

				ok, size, err := imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(size, ShouldEqual, blobSize)
				So(err, ShouldBeNil)

				_, err = driver.WriteFile(blobPath, []byte("corrupted"))
				So(err, ShouldBeNil)

				ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeFalse)
				So(size, ShouldNotEqual, blobSize)
				So(err, ShouldEqual, zerr.ErrBlobNotFound)

				err = WriteImageToFileSystem(image, repoName, tag, storeController)
				So(err, ShouldBeNil)

				ok, size, _, err = imgStore.StatBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(blobSize, ShouldEqual, size)
				So(err, ShouldBeNil)

				ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(size, ShouldEqual, blobSize)
				So(err, ShouldBeNil)
			})

			Convey("Test reupload repair corrupted image index", t, func() {
				storeController := storage.StoreController{DefaultStore: imgStore}

				image := CreateRandomMultiarch()

				tag := "index"

				err := WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
				So(err, ShouldBeNil)

				blob := image.Images[0].Layers[0]
				blobDigest := godigest.FromBytes(blob)
				blobSize := len(blob)
				blobPath := imgStore.BlobPath(repoName, blobDigest)

				ok, size, err := imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(size, ShouldEqual, blobSize)
				So(err, ShouldBeNil)

				_, err = driver.WriteFile(blobPath, []byte("corrupted"))
				So(err, ShouldBeNil)

				ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeFalse)
				So(size, ShouldNotEqual, blobSize)
				So(err, ShouldEqual, zerr.ErrBlobNotFound)

				err = WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
				So(err, ShouldBeNil)

				ok, size, _, err = imgStore.StatBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(blobSize, ShouldEqual, size)
				So(err, ShouldBeNil)

				ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
				So(ok, ShouldBeTrue)
				So(size, ShouldEqual, blobSize)
				So(err, ShouldBeNil)
			})
		})
	}
}

func TestStorageHandler(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var firstStore storageTypes.ImageStore
			var secondStore storageTypes.ImageStore
			var thirdStore storageTypes.ImageStore
			var firstRootDir string
			var secondRootDir string
			var thirdRootDir string

			if testcase.storageType == storageConstants.S3StorageDriverName {
				tskip.SkipS3(t)
				var firstStorageDriver driver.StorageDriver
				var secondStorageDriver driver.StorageDriver
				var thirdStorageDriver driver.StorageDriver

				firstRootDir = "/util_test1"
				firstStorageDriver, firstStore, _ = createObjectsStore(firstRootDir, t.TempDir())
				defer cleanupStorage(firstStorageDriver, firstRootDir)

				secondRootDir = "/util_test2"
				secondStorageDriver, secondStore, _ = createObjectsStore(secondRootDir, t.TempDir())
				defer cleanupStorage(secondStorageDriver, secondRootDir)

				thirdRootDir = "/util_test3"
				thirdStorageDriver, thirdStore, _ = createObjectsStore(thirdRootDir, t.TempDir())
				defer cleanupStorage(thirdStorageDriver, thirdRootDir)
			} else {
				// Create temporary directory
				firstRootDir = t.TempDir()
				secondRootDir = t.TempDir()
				thirdRootDir = t.TempDir()

				log := zlog.NewLogger("debug", "")

				metrics := monitoring.NewMetricsServer(false, log)

				driver := local.New(true)

				// Create ImageStore
				firstStore = imagestore.NewImageStore(firstRootDir, firstRootDir, false, false, log, metrics, nil, driver, nil)

				secondStore = imagestore.NewImageStore(secondRootDir, secondRootDir, false, false, log, metrics, nil, driver, nil)

				thirdStore = imagestore.NewImageStore(thirdRootDir, thirdRootDir, false, false, log, metrics, nil, driver, nil)
			}

			Convey("Test storage handler", t, func() {
				storeController := storage.StoreController{}

				storeController.DefaultStore = firstStore

				subStore := make(map[string]storageTypes.ImageStore)

				subStore["/a"] = secondStore
				subStore["/b"] = thirdStore

				storeController.SubStore = subStore

				imgStore := storeController.GetImageStore("zot-x-test")
				So(imgStore.RootDir(), ShouldEqual, firstRootDir)

				imgStore = storeController.GetImageStore("a/zot-a-test")
				So(imgStore.RootDir(), ShouldEqual, secondRootDir)

				imgStore = storeController.GetImageStore("b/zot-b-test")
				So(imgStore.RootDir(), ShouldEqual, thirdRootDir)

				imgStore = storeController.GetImageStore("c/zot-c-test")
				So(imgStore.RootDir(), ShouldEqual, firstRootDir)
			})
		})
	}
}

func TestRoutePrefix(t *testing.T) {
	Convey("Test route prefix", t, func() {
		routePrefix := storage.GetRoutePrefix("test:latest")
		So(routePrefix, ShouldEqual, "/")

		routePrefix = storage.GetRoutePrefix("a/test:latest")
		So(routePrefix, ShouldEqual, "/a")

		routePrefix = storage.GetRoutePrefix("a/b/test:latest")
		So(routePrefix, ShouldEqual, "/a")
	})
}

func TestGarbageCollectImageManifest(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			log := zlog.NewLogger("debug", "")
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)

			ctx := context.Background()

			//nolint: contextcheck
			Convey("Repo layout", t, func(c C) {
				Convey("Garbage collect with default/long delay", func() {
					var imgStore storageTypes.ImageStore
					if testcase.storageType == storageConstants.S3StorageDriverName {
						tskip.SkipS3(t)

						uuid, err := guuid.NewV4()
						if err != nil {
							panic(err)
						}

						testDir := path.Join("/oci-repo-test", uuid.String())
						tdir := t.TempDir()

						var store driver.StorageDriver
						store, imgStore, _ = createObjectsStore(testDir, tdir)
						defer cleanupStorage(store, testDir)
					} else {
						dir := t.TempDir()

						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     dir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)

						driver := local.New(true)

						imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
					}

					gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
						Delay: storageConstants.DefaultGCDelay,
						ImageRetention: config.ImageRetention{
							Delay: storageConstants.DefaultRetentionDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
								},
							},
						},
					}, audit, log)

					repoName := "gc-long"

					upload, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content := []byte("test-data1")
					buf := bytes.NewBuffer(content)
					buflen := buf.Len()
					bdigest := godigest.FromBytes(content)

					blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest)
					So(err, ShouldBeNil)

					annotationsMap := make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = tag

					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest)
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
								Digest:    bdigest,
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err := json.Marshal(manifest)
					So(err, ShouldBeNil)
					digest := godigest.FromBytes(manifestBuf)

					_, _, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// put artifact referencing above image
					artifactBlob := []byte("artifact")
					artifactBlobDigest := godigest.FromBytes(artifactBlob)

					// push layer
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
					So(err, ShouldBeNil)

					// push config
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
						ispec.DescriptorEmptyJSON.Digest)
					So(err, ShouldBeNil)

					artifactManifest := ispec.Manifest{
						MediaType: ispec.MediaTypeImageManifest,
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/octet-stream",
								Digest:    artifactBlobDigest,
								Size:      int64(len(artifactBlob)),
							},
						},
						Config: ispec.DescriptorEmptyJSON,
						Subject: &ispec.Descriptor{
							MediaType: "application/vnd.oci.image.manifest.v1+json",
							Digest:    digest,
							Size:      int64(len(manifestBuf)),
						},
					}
					artifactManifest.SchemaVersion = 2

					artifactManifestBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					err = imgStore.DeleteImageManifest(repoName, digest.String(), false)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)
				})

				Convey("Garbage collect with short delay", func() {
					var imgStore storageTypes.ImageStore

					gcDelay := 1 * time.Second

					if testcase.storageType == storageConstants.S3StorageDriverName {
						tskip.SkipS3(t)

						uuid, err := guuid.NewV4()
						if err != nil {
							panic(err)
						}

						testDir := path.Join("/oci-repo-test", uuid.String())
						tdir := t.TempDir()

						var store driver.StorageDriver
						store, imgStore, _ = createObjectsStore(testDir, tdir)
						defer cleanupStorage(store, testDir)
					} else {
						dir := t.TempDir()

						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     dir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)

						driver := local.New(true)

						imgStore = imagestore.NewImageStore(dir, dir, true,
							true, log, metrics, nil, driver, cacheDriver)
					}

					gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
						Delay: gcDelay,
						ImageRetention: config.ImageRetention{ //nolint: gochecknoglobals
							Delay: gcDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log)

					// upload orphan blob
					upload, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content := []byte("test-data1")
					buf := bytes.NewBuffer(content)
					buflen := buf.Len()
					odigest := godigest.FromBytes(content)

					blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
					So(err, ShouldBeNil)

					// sleep so orphan blob can be GC'ed
					time.Sleep(1 * time.Second)

					// upload blob
					upload, err = imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content = []byte("test-data2")
					buf = bytes.NewBuffer(content)
					buflen = buf.Len()
					bdigest := godigest.FromBytes(content)

					blob, err = imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest)
					So(err, ShouldBeNil)

					annotationsMap := make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = tag

					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest)
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
								Digest:    bdigest,
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err := json.Marshal(manifest)
					So(err, ShouldBeNil)
					digest := godigest.FromBytes(manifestBuf)

					_, _, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					// put artifact referencing above image
					artifactBlob := []byte("artifact")
					artifactBlobDigest := godigest.FromBytes(artifactBlob)

					// push layer
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
					So(err, ShouldBeNil)

					// push config
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
						ispec.DescriptorEmptyJSON.Digest)
					So(err, ShouldBeNil)

					artifactManifest := ispec.Manifest{
						MediaType: ispec.MediaTypeImageManifest,
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/octet-stream",
								Digest:    artifactBlobDigest,
								Size:      int64(len(artifactBlob)),
							},
						},
						Config: ispec.DescriptorEmptyJSON,
						Subject: &ispec.Descriptor{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    digest,
							Size:      int64(len(manifestBuf)),
						},
					}
					artifactManifest.SchemaVersion = 2

					artifactManifestBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					// push artifact manifest pointing to artifact above
					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    artifactDigest,
						Size:      int64(len(artifactManifestBuf)),
					}
					artifactManifest.ArtifactType = "application/forArtifact" //nolint: goconst

					artifactManifestBuf, err = json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactOfArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)
					_, _, err = imgStore.PutImageManifest(repoName, artifactOfArtifactManifestDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					// push orphan artifact (missing subject)
					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("miss")),
						Size:      int64(30),
					}
					artifactManifest.ArtifactType = "application/orphan" //nolint: goconst

					artifactManifestBuf, err = json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					orphanArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

					// push orphan artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, orphanArtifactManifestDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					hasBlob, _, _, err = imgStore.StatBlob(repoName, odigest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, _, err = imgStore.StatBlob(repoName, bdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					// sleep so orphan blob can be GC'ed
					time.Sleep(1 * time.Second)

					Convey("Garbage collect blobs after manifest is removed", func() {
						err = imgStore.DeleteImageManifest(repoName, digest.String(), false)
						So(err, ShouldBeNil)

						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						// check artifacts are gc'ed
						_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						// check it gc'ed repo
						exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
						So(exists, ShouldBeFalse)
					})

					Convey("Garbage collect - don't gc manifests/blobs which are referenced by another image", func() {
						// upload same image with another tag
						_, _, err = imgStore.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, manifestBuf)
						So(err, ShouldBeNil)

						err = imgStore.DeleteImageManifest(repoName, tag, false)
						So(err, ShouldBeNil)

						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)

						hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)

						hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)

						// orphan artifact should be deleted
						_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						// check artifacts manifests
						_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldBeNil)
					})
				})

				Convey("Garbage collect with dedupe", func() {
					// garbage-collect is repo-local and dedupe is global and they can interact in strange ways
					var imgStore storageTypes.ImageStore

					gcDelay := 3 * time.Second

					if testcase.storageType == storageConstants.S3StorageDriverName {
						tskip.SkipS3(t)

						uuid, err := guuid.NewV4()
						if err != nil {
							panic(err)
						}

						testDir := path.Join("/oci-repo-test", uuid.String())
						tdir := t.TempDir()

						var store driver.StorageDriver
						store, imgStore, _ = createObjectsStore(testDir, tdir)
						defer cleanupStorage(store, testDir)
					} else {
						dir := t.TempDir()

						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     dir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)

						driver := local.New(true)

						imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
					}

					gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
						Delay:          gcDelay,
						ImageRetention: DeleteReferrers,
					}, audit, log)

					// first upload an image to the first repo and wait for GC timeout

					repo1Name := "gc1"

					// upload blob
					upload, err := imgStore.NewBlobUpload(repo1Name)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content := []byte("test-data")
					buf := bytes.NewBuffer(content)
					buflen := buf.Len()
					bdigest := godigest.FromBytes(content)
					tdigest := bdigest

					blob, err := imgStore.PutBlobChunk(repo1Name, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repo1Name, upload, buf, bdigest)
					So(err, ShouldBeNil)

					annotationsMap := make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = tag

					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload(repo1Name, bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err := imgStore.CheckBlob(repo1Name, cdigest)
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
								Digest:    bdigest,
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err := json.Marshal(manifest)
					So(err, ShouldBeNil)

					_, _, err = imgStore.PutImageManifest(repo1Name, tag, ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					// sleep so past GC timeout
					time.Sleep(3 * time.Second)

					hasBlob, _, err = imgStore.CheckBlob(repo1Name, tdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, err = imgStore.CheckBlob(repo1Name, tdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					// upload another image into a second repo with the same blob contents so dedupe is triggered

					repo2Name := "gc2"

					upload, err = imgStore.NewBlobUpload(repo2Name)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					buf = bytes.NewBuffer(content)
					buflen = buf.Len()

					blob, err = imgStore.PutBlobChunk(repo2Name, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repo2Name, upload, buf, bdigest)
					So(err, ShouldBeNil)

					annotationsMap = make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = tag

					cblob, cdigest = GetRandomImageConfig()
					_, clen, err = imgStore.FullBlobUpload(repo2Name, bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err = imgStore.CheckBlob(repo2Name, cdigest)
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
								Digest:    bdigest,
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err = json.Marshal(manifest)
					So(err, ShouldBeNil)

					_, _, err = imgStore.PutImageManifest(repo2Name, tag, ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					hasBlob, _, err = imgStore.CheckBlob(repo2Name, bdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					// immediately upload any other image to second repo which should invoke GC inline, but expect layers to persist

					upload, err = imgStore.NewBlobUpload(repo2Name)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content = []byte("test-data-more")
					buf = bytes.NewBuffer(content)
					buflen = buf.Len()
					bdigest = godigest.FromBytes(content)

					blob, err = imgStore.PutBlobChunk(repo2Name, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repo2Name, upload, buf, bdigest)
					So(err, ShouldBeNil)

					annotationsMap = make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = tag

					cblob, cdigest = GetRandomImageConfig()
					_, clen, err = imgStore.FullBlobUpload(repo2Name, bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err = imgStore.CheckBlob(repo2Name, cdigest)
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
								Digest:    bdigest,
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err = json.Marshal(manifest)
					So(err, ShouldBeNil)
					digest := godigest.FromBytes(manifestBuf)

					_, _, err = imgStore.PutImageManifest(repo2Name, tag, ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repo2Name)
					So(err, ShouldBeNil)

					// original blob should exist
					hasBlob, _, err = imgStore.CheckBlob(repo2Name, tdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					_, _, _, err = imgStore.GetImageManifest(repo2Name, digest.String())
					So(err, ShouldBeNil)
				})
			})
		})
	}
}

func TestGarbageCollectImageIndex(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			log := zlog.NewLogger("debug", "")
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)

			ctx := context.Background()

			//nolint: contextcheck
			Convey("Repo layout", t, func(c C) {
				Convey("Garbage collect with default/long delay", func() {
					var imgStore storageTypes.ImageStore
					if testcase.storageType == storageConstants.S3StorageDriverName {
						tskip.SkipS3(t)

						uuid, err := guuid.NewV4()
						if err != nil {
							panic(err)
						}

						testDir := path.Join("/oci-repo-test", uuid.String())
						tdir := t.TempDir()

						var store driver.StorageDriver
						store, imgStore, _ = createObjectsStore(testDir, tdir)
						defer cleanupStorage(store, testDir)
					} else {
						dir := t.TempDir()

						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     dir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)

						driver := local.New(true)

						imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
					}

					gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
						Delay:          storageConstants.DefaultGCDelay,
						ImageRetention: DeleteReferrers,
					}, audit, log)

					repoName := "gc-long"

					bdgst, digest, indexDigest, indexSize := pushRandomImageIndex(imgStore, repoName)

					// put artifact referencing above image
					artifactBlob := []byte("artifact")
					artifactBlobDigest := godigest.FromBytes(artifactBlob)

					// push layer
					_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
					So(err, ShouldBeNil)

					// push config
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
						ispec.DescriptorEmptyJSON.Digest)
					So(err, ShouldBeNil)

					artifactManifest := ispec.Manifest{
						MediaType: ispec.MediaTypeImageManifest,
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/octet-stream",
								Digest:    artifactBlobDigest,
								Size:      int64(len(artifactBlob)),
							},
						},
						Config: ispec.DescriptorEmptyJSON,
						Subject: &ispec.Descriptor{
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    indexDigest,
							Size:      indexSize,
						},
					}
					artifactManifest.SchemaVersion = 2

					artifactManifestBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest referencing index image
					_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      indexSize,
					}

					artifactManifestBuf, err = json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest referencing a manifest from index image
					_, _, err = imgStore.PutImageManifest(repoName, artifactManifestDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					hasBlob, _, err := imgStore.CheckBlob(repoName, bdgst)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					Convey("delete index manifest, layers should be persisted", func() {
						err = imgStore.DeleteImageManifest(repoName, indexDigest.String(), false)
						So(err, ShouldBeNil)

						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						hasBlob, _, err = imgStore.CheckBlob(repoName, bdgst)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)

						// check last manifest from index image
						hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)

						hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
						So(err, ShouldBeNil)
						So(hasBlob, ShouldEqual, true)
					})
				})

				Convey("Garbage collect with short delay", func() {
					var imgStore storageTypes.ImageStore

					gcDelay := 2 * time.Second
					imageRetentionDelay := 2 * time.Second

					if testcase.storageType == storageConstants.S3StorageDriverName {
						tskip.SkipS3(t)

						uuid, err := guuid.NewV4()
						if err != nil {
							panic(err)
						}

						testDir := path.Join("/oci-repo-test", uuid.String())
						tdir := t.TempDir()

						var store driver.StorageDriver
						store, imgStore, _ = createObjectsStore(testDir, tdir)
						defer cleanupStorage(store, testDir)
					} else {
						dir := t.TempDir()

						cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
							RootDir:     dir,
							Name:        "cache",
							UseRelPaths: true,
						}, log)

						driver := local.New(true)

						imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
					}

					gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
						Delay: gcDelay,
						ImageRetention: config.ImageRetention{ //nolint: gochecknoglobals
							Delay: imageRetentionDelay,
							Policies: []config.RetentionPolicy{
								{
									Repositories:    []string{"**"},
									DeleteReferrers: true,
									DeleteUntagged:  &trueVal,
								},
							},
						},
					}, audit, log)

					// upload orphan blob
					upload, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					content := []byte("test-data1")
					buf := bytes.NewBuffer(content)
					buflen := buf.Len()
					odigest := godigest.FromBytes(content)

					blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
					So(err, ShouldBeNil)

					bdgst, digest, indexDigest, indexSize := pushRandomImageIndex(imgStore, repoName)

					// put artifact referencing above image
					artifactBlob := []byte("artifact")
					artifactBlobDigest := godigest.FromBytes(artifactBlob)

					// push layer
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
					So(err, ShouldBeNil)

					// push config
					_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
						ispec.DescriptorEmptyJSON.Digest)
					So(err, ShouldBeNil)

					// push artifact manifest pointing to index
					artifactManifest := ispec.Manifest{
						MediaType: ispec.MediaTypeImageManifest,
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/octet-stream",
								Digest:    artifactBlobDigest,
								Size:      int64(len(artifactBlob)),
							},
						},
						Config: ispec.DescriptorEmptyJSON,
						Subject: &ispec.Descriptor{
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    indexDigest,
							Size:      indexSize,
						},
						ArtifactType: "application/forIndex",
					}
					artifactManifest.SchemaVersion = 2

					artifactManifestBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      int64(len(content)),
					}
					artifactManifest.ArtifactType = "application/forManifestInIndex"

					artifactManifestIndexBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactManifestIndexDigest := godigest.FromBytes(artifactManifestIndexBuf)

					// push artifact manifest referencing a manifest from index image
					_, _, err = imgStore.PutImageManifest(repoName, artifactManifestIndexDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestIndexBuf)
					So(err, ShouldBeNil)

					// push artifact manifest pointing to artifact above
					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    artifactDigest,
						Size:      int64(len(artifactManifestBuf)),
					}
					artifactManifest.ArtifactType = "application/forArtifact"

					artifactManifestBuf, err = json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactOfArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)
					_, _, err = imgStore.PutImageManifest(repoName, artifactOfArtifactManifestDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					// push orphan artifact (missing subject)
					artifactManifest.Subject = &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("miss")),
						Size:      int64(30),
					}
					artifactManifest.ArtifactType = "application/orphan"

					artifactManifestBuf, err = json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					orphanArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

					// push orphan artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, orphanArtifactManifestDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)

					hasBlob, _, err := imgStore.CheckBlob(repoName, bdgst)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, _, err = imgStore.StatBlob(repoName, bdgst)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					time.Sleep(2 * time.Second)

					Convey("delete inner referenced manifest", func() {
						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						// check orphan artifact is gc'ed
						_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldBeNil)

						err = imgStore.DeleteImageManifest(repoName, artifactDigest.String(), false)
						So(err, ShouldBeNil)

						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
						So(err, ShouldBeNil)
					})

					Convey("delete index manifest, references should not be persisted", func() {
						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						// check orphan artifact is gc'ed
						_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldBeNil)

						err = imgStore.DeleteImageManifest(repoName, indexDigest.String(), false)
						So(err, ShouldBeNil)

						err = gc.CleanRepo(ctx, repoName)
						So(err, ShouldBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
						So(err, ShouldNotBeNil)

						// orphan blob
						hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						hasBlob, _, _, err = imgStore.StatBlob(repoName, odigest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						hasBlob, _, err = imgStore.CheckBlob(repoName, bdgst)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						// check last manifest from index image
						hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						// check referrer is gc'ed
						_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
						So(err, ShouldNotBeNil)

						_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
						So(err, ShouldNotBeNil)

						hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
						So(err, ShouldNotBeNil)
						So(hasBlob, ShouldEqual, false)

						// check it gc'ed repo
						exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
						So(exists, ShouldBeFalse)
					})
				})
			})
		})
	}
}

func TestGarbageCollectChainedImageIndexes(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			log := zlog.NewLogger("debug", "")
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)

			ctx := context.Background()

			//nolint: contextcheck
			Convey("Garbage collect with short delay", t, func() {
				var imgStore storageTypes.ImageStore

				gcDelay := 5 * time.Second
				imageRetentionDelay := 5 * time.Second

				if testcase.storageType == storageConstants.S3StorageDriverName {
					tskip.SkipS3(t)

					uuid, err := guuid.NewV4()
					if err != nil {
						panic(err)
					}

					testDir := path.Join("/oci-repo-test", uuid.String())
					tdir := t.TempDir()

					var store driver.StorageDriver
					store, imgStore, _ = createObjectsStore(testDir, tdir)
					defer cleanupStorage(store, testDir)
				} else {
					dir := t.TempDir()

					cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
						RootDir:     dir,
						Name:        "cache",
						UseRelPaths: true,
					}, log)

					driver := local.New(true)

					imgStore = imagestore.NewImageStore(dir, dir, true, true, log, metrics, nil, driver, cacheDriver)
				}

				gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
					Delay: gcDelay,
					ImageRetention: config.ImageRetention{ //nolint: gochecknoglobals
						Delay: imageRetentionDelay,
						Policies: []config.RetentionPolicy{
							{
								Repositories:    []string{"**"},
								DeleteReferrers: true,
								DeleteUntagged:  &trueVal,
							},
						},
					},
				}, audit, log)

				// upload orphan blob
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				content := []byte("test-data1")
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				odigest := godigest.FromBytes(content)

				blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
				So(err, ShouldBeNil)

				content = []byte("this is a blob")
				bdgst := godigest.FromBytes(content)
				So(bdgst, ShouldNotBeNil)

				_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
				So(err, ShouldBeNil)
				So(bsize, ShouldEqual, len(content))

				artifactBlob := []byte("artifact")
				artifactBlobDigest := godigest.FromBytes(artifactBlob)

				// push layer
				_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
				So(err, ShouldBeNil)

				// push config
				_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
					ispec.DescriptorEmptyJSON.Digest)
				So(err, ShouldBeNil)

				var index ispec.Index
				index.SchemaVersion = 2
				index.MediaType = ispec.MediaTypeImageIndex

				var digest godigest.Digest
				for i := 0; i < 4; i++ { //nolint: dupl
					// upload image config blob
					upload, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					cblob, cdigest := GetRandomImageConfig()
					buf := bytes.NewBuffer(cblob)
					buflen := buf.Len()
					blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
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
								Digest:    bdgst,
								Size:      bsize,
							},
						},
					}
					manifest.SchemaVersion = 2
					content, err = json.Marshal(manifest)
					So(err, ShouldBeNil)
					digest = godigest.FromBytes(content)
					So(digest, ShouldNotBeNil)
					_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
					So(err, ShouldBeNil)

					index.Manifests = append(index.Manifests, ispec.Descriptor{
						Digest:    digest,
						MediaType: ispec.MediaTypeImageManifest,
						Size:      int64(len(content)),
					})

					// for each manifest inside index, push an artifact
					artifactManifest := ispec.Manifest{
						MediaType: ispec.MediaTypeImageManifest,
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/octet-stream",
								Digest:    artifactBlobDigest,
								Size:      int64(len(artifactBlob)),
							},
						},
						Config: ispec.DescriptorEmptyJSON,
						Subject: &ispec.Descriptor{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    digest,
							Size:      int64(len(content)),
						},
						ArtifactType: "application/forManifestInInnerIndex",
					}
					artifactManifest.SchemaVersion = 2

					artifactManifestBuf, err := json.Marshal(artifactManifest)
					So(err, ShouldBeNil)

					artifactDigest := godigest.FromBytes(artifactManifestBuf)

					// push artifact manifest
					_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
						ispec.MediaTypeImageManifest, artifactManifestBuf)
					So(err, ShouldBeNil)
				}

				// also add a new image index inside this one
				var innerIndex ispec.Index
				innerIndex.SchemaVersion = 2
				innerIndex.MediaType = ispec.MediaTypeImageIndex

				for i := 0; i < 3; i++ { //nolint: dupl
					// upload image config blob
					upload, err := imgStore.NewBlobUpload(repoName)
					So(err, ShouldBeNil)
					So(upload, ShouldNotBeEmpty)

					cblob, cdigest := GetRandomImageConfig()
					buf := bytes.NewBuffer(cblob)
					buflen := buf.Len()
					blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
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
								Digest:    bdgst,
								Size:      bsize,
							},
						},
					}
					manifest.SchemaVersion = 2
					content, err = json.Marshal(manifest)
					So(err, ShouldBeNil)
					digest := godigest.FromBytes(content)
					So(digest, ShouldNotBeNil)
					_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
					So(err, ShouldBeNil)

					innerIndex.Manifests = append(innerIndex.Manifests, ispec.Descriptor{
						Digest:    digest,
						MediaType: ispec.MediaTypeImageManifest,
						Size:      int64(len(content)),
					})
				}

				// upload inner index image
				innerIndexContent, err := json.Marshal(index)
				So(err, ShouldBeNil)
				innerIndexDigest := godigest.FromBytes(innerIndexContent)
				So(innerIndexDigest, ShouldNotBeNil)

				_, _, err = imgStore.PutImageManifest(repoName, innerIndexDigest.String(),
					ispec.MediaTypeImageIndex, innerIndexContent)
				So(err, ShouldBeNil)

				// add inner index into  root index
				index.Manifests = append(index.Manifests, ispec.Descriptor{
					Digest:    innerIndexDigest,
					MediaType: ispec.MediaTypeImageIndex,
					Size:      int64(len(innerIndexContent)),
				})

				// push root index
				// upload index image
				indexContent, err := json.Marshal(index)
				So(err, ShouldBeNil)
				indexDigest := godigest.FromBytes(indexContent)
				So(indexDigest, ShouldNotBeNil)

				_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
				So(err, ShouldBeNil)

				artifactManifest := ispec.Manifest{
					MediaType: ispec.MediaTypeImageManifest,
					Layers: []ispec.Descriptor{
						{
							MediaType: "application/octet-stream",
							Digest:    artifactBlobDigest,
							Size:      int64(len(artifactBlob)),
						},
					},
					Config: ispec.DescriptorEmptyJSON,
					Subject: &ispec.Descriptor{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    indexDigest,
						Size:      int64(len(indexContent)),
					},
					ArtifactType: "application/forIndex",
				}
				artifactManifest.SchemaVersion = 2

				artifactManifestBuf, err := json.Marshal(artifactManifest)
				So(err, ShouldBeNil)

				artifactDigest := godigest.FromBytes(artifactManifestBuf)

				// push artifact manifest
				_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
					ispec.MediaTypeImageManifest, artifactManifestBuf)
				So(err, ShouldBeNil)

				artifactManifest.Subject = &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest,
					Size:      int64(len(content)),
				}
				artifactManifest.ArtifactType = "application/forManifestInIndex"

				artifactManifestIndexBuf, err := json.Marshal(artifactManifest)
				So(err, ShouldBeNil)

				artifactManifestIndexDigest := godigest.FromBytes(artifactManifestIndexBuf)

				// push artifact manifest referencing a manifest from index image
				_, _, err = imgStore.PutImageManifest(repoName, artifactManifestIndexDigest.String(),
					ispec.MediaTypeImageManifest, artifactManifestIndexBuf)
				So(err, ShouldBeNil)

				artifactManifest.Subject = &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    innerIndexDigest,
					Size:      int64(len(innerIndexContent)),
				}
				artifactManifest.ArtifactType = "application/forInnerIndex"

				artifactManifestInnerIndexBuf, err := json.Marshal(artifactManifest)
				So(err, ShouldBeNil)

				artifactManifestInnerIndexDigest := godigest.FromBytes(artifactManifestInnerIndexBuf)

				// push artifact manifest referencing a manifest from index image
				_, _, err = imgStore.PutImageManifest(repoName, artifactManifestInnerIndexDigest.String(),
					ispec.MediaTypeImageManifest, artifactManifestInnerIndexBuf)
				So(err, ShouldBeNil)

				// push artifact manifest pointing to artifact above

				artifactManifest.Subject = &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    artifactDigest,
					Size:      int64(len(artifactManifestBuf)),
				}
				artifactManifest.ArtifactType = "application/forArtifact"

				artifactManifestBuf, err = json.Marshal(artifactManifest)
				So(err, ShouldBeNil)

				artifactOfArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)
				_, _, err = imgStore.PutImageManifest(repoName, artifactOfArtifactManifestDigest.String(),
					ispec.MediaTypeImageManifest, artifactManifestBuf)
				So(err, ShouldBeNil)

				// push orphan artifact (missing subject)
				artifactManifest.Subject = &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    godigest.FromBytes([]byte("miss")),
					Size:      int64(30),
				}
				artifactManifest.ArtifactType = "application/orphan"

				artifactManifestBuf, err = json.Marshal(artifactManifest)
				So(err, ShouldBeNil)

				orphanArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

				// push orphan artifact manifest
				_, _, err = imgStore.PutImageManifest(repoName, orphanArtifactManifestDigest.String(),
					ispec.MediaTypeImageManifest, artifactManifestBuf)
				So(err, ShouldBeNil)

				hasBlob, _, err := imgStore.CheckBlob(repoName, bdgst)
				So(err, ShouldBeNil)
				So(hasBlob, ShouldEqual, true)

				hasBlob, _, _, err = imgStore.StatBlob(repoName, bdgst)
				So(err, ShouldBeNil)
				So(hasBlob, ShouldEqual, true)

				hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
				So(err, ShouldBeNil)
				So(hasBlob, ShouldEqual, true)

				time.Sleep(5 * time.Second)

				Convey("delete inner referenced manifest", func() {
					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// check orphan artifact is gc'ed
					_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
					So(err, ShouldBeNil)

					err = imgStore.DeleteImageManifest(repoName, artifactDigest.String(), false)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
					So(err, ShouldBeNil)
				})

				Convey("delete index manifest, references should not be persisted", func() {
					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					// check orphan artifact is gc'ed
					_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
					So(err, ShouldBeNil)

					err = imgStore.DeleteImageManifest(repoName, indexDigest.String(), false)
					So(err, ShouldBeNil)

					err = gc.CleanRepo(ctx, repoName)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
					So(err, ShouldNotBeNil)

					// orphan blob
					hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					hasBlob, _, _, err = imgStore.StatBlob(repoName, odigest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					// check artifact is gc'ed
					_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
					So(err, ShouldNotBeNil)

					// check inner index artifact is gc'ed
					_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestInnerIndexDigest.String())
					So(err, ShouldNotBeNil)

					// check last manifest from index image
					hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
					So(err, ShouldNotBeNil)

					hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					hasBlob, _, err = imgStore.CheckBlob(repoName, bdgst)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					// check it gc'ed repo
					exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
					So(exists, ShouldBeFalse)
				})
			})
		})
	}
}

func pushRandomImageIndex(imgStore storageTypes.ImageStore, repoName string,
) (godigest.Digest, godigest.Digest, godigest.Digest, int64) {
	content := []byte("this is a blob")
	bdgst := godigest.FromBytes(content)
	So(bdgst, ShouldNotBeNil)

	_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
	So(err, ShouldBeNil)
	So(bsize, ShouldEqual, len(content))

	var index ispec.Index
	index.SchemaVersion = 2
	index.MediaType = ispec.MediaTypeImageIndex

	var digest godigest.Digest

	for i := 0; i < 4; i++ { //nolint: dupl
		// upload image config blob
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest := GetRandomImageConfig()
		buf := bytes.NewBuffer(cblob)
		buflen := buf.Len()
		blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
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
					Digest:    bdgst,
					Size:      bsize,
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest = godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		index.Manifests = append(index.Manifests, ispec.Descriptor{
			Digest:    digest,
			MediaType: ispec.MediaTypeImageManifest,
			Size:      int64(len(content)),
		})
	}

	// upload index image
	indexContent, err := json.Marshal(index)
	So(err, ShouldBeNil)
	indexDigest := godigest.FromBytes(indexContent)
	So(indexDigest, ShouldNotBeNil)

	_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
	So(err, ShouldBeNil)

	return bdgst, digest, indexDigest, int64(len(indexContent))
}
