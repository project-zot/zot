package storage_test

import (
	"bytes"
	"context"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/s3"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
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

func createObjectsStore(rootDir string, cacheDir string) (driver.StorageDriver, storage.ImageStore, error) {
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
		true, false, log, metrics, nil, store,
	)

	return store, il, err
}

// nolint: gochecknoglobals
var testCases = []struct {
	testCaseName string
	storageType  string
}{
	{
		testCaseName: "S3APIs",
		storageType:  "s3",
	},
	{
		testCaseName: "FileSystemAPIs",
		storageType:  "fs",
	},
}

func TestStorageAPIs(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var imgStore storage.ImageStore
			if testcase.storageType == "s3" {
				skipIt(t)

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

				log := log.Logger{Logger: zerolog.New(os.Stdout)}
				metrics := monitoring.NewMetricsServer(false, log)
				imgStore = local.NewImageStore(dir, true, storConstants.DefaultGCDelay, true,
					true, log, metrics, nil)
			}

			Convey("Repo layout", t, func(c C) {
				repoName := "test"

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
					v, err := imgStore.ValidateRepo(repoName)
					So(err, ShouldBeNil)
					So(v, ShouldEqual, true)
				})

				Convey("Get repos", func() {
					v, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)
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
					upload, n, err := imgStore.FullBlobUpload("test", buf, digest.String())
					So(err, ShouldBeNil)
					So(n, ShouldEqual, len(body))
					So(upload, ShouldNotBeEmpty)
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

						err = imgStore.FinishBlobUpload("test", upload, buf, digest.String())
						So(err, ShouldBeNil)

						_, _, err = imgStore.CheckBlob("test", digest.String())
						So(err, ShouldBeNil)

						blob, _, err := imgStore.GetBlob("test", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)
						err = blob.Close()
						So(err, ShouldBeNil)

						manifest := ispec.Manifest{}
						manifest.SchemaVersion = 2
						manifestBuf, err := json.Marshal(manifest)
						So(err, ShouldBeNil)

						Convey("Bad image manifest", func() {
							_, err = imgStore.PutImageManifest("test", digest.String(), "application/json",
								manifestBuf)
							So(err, ShouldNotBeNil)

							_, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								[]byte{})
							So(err, ShouldNotBeNil)

							_, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								[]byte(`{"test":true}`))
							So(err, ShouldNotBeNil)

							_, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
								manifestBuf)
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("inexistent", digest.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							cblob, cdigest := test.GetRandomImageConfig()
							_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest.String())
							So(err, ShouldBeNil)
							So(clen, ShouldEqual, len(cblob))
							hasBlob, _, err := imgStore.CheckBlob("test", cdigest.String())
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

							_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, badMb)
							So(err, ShouldNotBeNil)

							_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, err = imgStore.PutImageManifest("test", "2.0", ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, err = imgStore.PutImageManifest("test", "3.0", ispec.MediaTypeImageManifest, manifestBuf)
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

							err = imgStore.DeleteImageManifest("test", "1.0")
							So(err, ShouldBeNil)

							tags, err = imgStore.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 2)

							// We deleted only one tag, make sure blob should not be removed.
							hasBlob, _, err = imgStore.CheckBlob("test", digest.String())
							So(err, ShouldBeNil)
							So(hasBlob, ShouldEqual, true)

							// If we pass reference all manifest with input reference should be deleted.
							err = imgStore.DeleteImageManifest("test", digest.String())
							So(err, ShouldBeNil)

							tags, err = imgStore.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 0)

							// All tags/references are deleted, blob should not be present in disk.
							hasBlob, _, err = imgStore.CheckBlob("test", digest.String())
							So(err, ShouldNotBeNil)
							So(hasBlob, ShouldEqual, false)

							err = imgStore.DeleteBlob("test", "inexistent")
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteBlob("test", godigest.FromBytes([]byte("inexistent")).String())
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteBlob("test", blobDigest.String())
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
						err = imgStore.FinishBlobUpload("test", bupload, bytes.NewBuffer([]byte{}), "inexistent")
						So(err, ShouldNotBeNil)

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

						err = imgStore.FinishBlobUpload("test", "inexistent", buf, digest.String())
						So(err, ShouldNotBeNil)

						err = imgStore.FinishBlobUpload("test", bupload, buf, digest.String())
						So(err, ShouldBeNil)

						_, _, err = imgStore.CheckBlob("test", digest.String())
						So(err, ShouldBeNil)

						_, _, err = imgStore.GetBlob("test", "inexistent", "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldNotBeNil)

						blob, _, err := imgStore.GetBlob("test", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)
						err = blob.Close()
						So(err, ShouldBeNil)

						blobContent, err := imgStore.GetBlobContent("test", digest.String())
						So(err, ShouldBeNil)
						So(content, ShouldResemble, blobContent)

						_, err = imgStore.GetBlobContent("inexistent", digest.String())
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
						})

						Convey("Bad image manifest", func() {
							_, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldNotBeNil)

							_, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, []byte("bad json"))
							So(err, ShouldNotBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							cblob, cdigest := test.GetRandomImageConfig()
							_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest.String())
							So(err, ShouldBeNil)
							So(clen, ShouldEqual, len(cblob))
							hasBlob, _, err := imgStore.CheckBlob("test", cdigest.String())
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
							_, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, err = imgStore.PutImageManifest("test", digest.String(),
								ispec.MediaTypeImageManifest, manifestBuf)
							So(err, ShouldBeNil)

							_, _, _, err = imgStore.GetImageManifest("test", digest.String())
							So(err, ShouldBeNil)

							_, err = imgStore.GetIndexContent("inexistent")
							So(err, ShouldNotBeNil)

							indexContent, err := imgStore.GetIndexContent("test")
							So(err, ShouldBeNil)

							if testcase.storageType == "fs" {
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
							err = imgStore.DeleteImageManifest("test", "1.0")
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteImageManifest("inexistent", "1.0")
							So(err, ShouldNotBeNil)

							err = imgStore.DeleteImageManifest("test", digest.String())
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

					err = imgStore.FinishBlobUpload("replace", upload, buf, digest.String())
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					cblob, cdigest := test.GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest.String())
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err := imgStore.CheckBlob("replace", cdigest.String())
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
					_, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
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

					err = imgStore.FinishBlobUpload("replace", upload, buf, digest.String())
					So(err, ShouldBeNil)
					So(blob, ShouldEqual, buflen)

					cblob, cdigest = test.GetRandomImageConfig()
					_, clen, err = imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest.String())
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))
					hasBlob, _, err = imgStore.CheckBlob("replace", cdigest.String())
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
					_, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
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
			var imgStore storage.ImageStore
			var testDir, tdir string
			var store driver.StorageDriver

			log := log.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)

			if testcase.storageType == "s3" {
				skipIt(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir = path.Join("/oci-repo-test", uuid.String())
				tdir = t.TempDir()

				store, _, _ = createObjectsStore(testDir, tdir)
				imgStore = s3.NewImageStore(testDir, tdir, false, 1, false, false, log, metrics,
					&mocks.MockedLint{
						LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
							return false, nil
						},
					}, store)

				defer cleanupStorage(store, testDir)
			} else {
				tdir = t.TempDir()

				imgStore = local.NewImageStore(tdir, true, storConstants.DefaultGCDelay, true,
					true, log, metrics, &mocks.MockedLint{
						LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
							return false, nil
						},
					})
			}

			Convey("Setup manifest", t, func() {
				content := []byte("test-data1")
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				_, _, err := imgStore.FullBlobUpload("test", bytes.NewReader(buf.Bytes()), digest.String())
				So(err, ShouldBeNil)

				cblob, cdigest := test.GetRandomImageConfig()
				_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest.String())
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
					_, err = imgStore.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldNotBeNil)
				})

				Convey("Error on mandatory annotations", func() {
					if testcase.storageType == "s3" {
						imgStore = s3.NewImageStore(testDir, tdir, false, 1, false, false, log, metrics,
							&mocks.MockedLint{
								LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
									// nolint: goerr113
									return false, errors.New("linter error")
								},
							}, store)
					} else {
						imgStore = local.NewImageStore(tdir, true, storConstants.DefaultGCDelay, true,
							true, log, metrics, &mocks.MockedLint{
								LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
									// nolint: goerr113
									return false, errors.New("linter error")
								},
							})
					}

					_, err = imgStore.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldNotBeNil)
				})
			})
		})
	}
}

func TestStorageHandler(t *testing.T) {
	for _, testcase := range testCases {
		testcase := testcase
		t.Run(testcase.testCaseName, func(t *testing.T) {
			var firstStore storage.ImageStore
			var secondStore storage.ImageStore
			var thirdStore storage.ImageStore
			var firstRootDir string
			var secondRootDir string
			var thirdRootDir string

			if testcase.storageType == "s3" {
				skipIt(t)
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

				log := log.NewLogger("debug", "")

				metrics := monitoring.NewMetricsServer(false, log)

				// Create ImageStore
				firstStore = local.NewImageStore(firstRootDir, false, storConstants.DefaultGCDelay,
					false, false, log, metrics, nil)

				secondStore = local.NewImageStore(secondRootDir, false,
					storConstants.DefaultGCDelay, false, false, log, metrics, nil)

				thirdStore = local.NewImageStore(thirdRootDir, false, storConstants.DefaultGCDelay,
					false, false, log, metrics, nil)
			}

			Convey("Test storage handler", t, func() {
				storeController := storage.StoreController{}

				storeController.DefaultStore = firstStore

				subStore := make(map[string]storage.ImageStore)

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
