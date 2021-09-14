package storage_test

import (
	"bytes"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"

	//"strings"
	"testing"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	// Add s3 support

	"github.com/docker/distribution/registry/storage/driver"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
)

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
			var il storage.ImageStore
			if testcase.storageType == "s3" {
				skipIt(t)

				uuid, err := guuid.NewV4()
				if err != nil {
					panic(err)
				}

				testDir := path.Join("/oci-repo-test", uuid.String())

				var store driver.StorageDriver
				store, il, _ = createObjectsStore(testDir)
				defer cleanupStorage(store, testDir)
			} else {
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}

				defer os.RemoveAll(dir)

				il = storage.NewImageStoreFS(dir, true, true, log.Logger{Logger: zerolog.New(os.Stdout)})
			}

			Convey("Repo layout", t, func(c C) {
				repoName := "test"

				Convey("Validate repo without initialization", func() {
					v, err := il.ValidateRepo(repoName)
					So(v, ShouldEqual, false)
					So(err, ShouldNotBeNil)
					ok := il.DirExists(path.Join(il.RootDir(), repoName))
					So(ok, ShouldBeFalse)
				})

				Convey("Initialize repo", func() {
					err := il.InitRepo(repoName)
					So(err, ShouldBeNil)
					ok := il.DirExists(path.Join(il.RootDir(), repoName))
					So(ok, ShouldBeTrue)
				})

				Convey("Validate repo", func() {
					v, err := il.ValidateRepo(repoName)
					So(err, ShouldBeNil)
					So(v, ShouldEqual, true)
				})

				Convey("Get repos", func() {
					v, err := il.GetRepositories()
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)
				})

				Convey("Get image tags", func() {
					v, err := il.GetImageTags("test")
					So(err, ShouldBeNil)
					So(v, ShouldBeEmpty)
				})

				Convey("Full blob upload", func() {
					body := []byte("this is a blob")
					buf := bytes.NewBuffer(body)
					d := godigest.FromBytes(body)
					u, n, err := il.FullBlobUpload("test", buf, d.String())
					So(err, ShouldBeNil)
					So(n, ShouldEqual, len(body))
					So(u, ShouldNotBeEmpty)
				})

				Convey("New blob upload", func() {
					v, err := il.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)

					err = il.DeleteBlobUpload("test", v)
					So(err, ShouldBeNil)

					v, err = il.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)

					Convey("Get blob upload", func() {
						b, err := il.GetBlobUpload("test", "invalid")
						So(err, ShouldNotBeNil)
						So(b, ShouldEqual, -1)

						b, err = il.GetBlobUpload("test", v)
						So(err, ShouldBeNil)
						So(b, ShouldBeGreaterThanOrEqualTo, 0)

						b, err = il.BlobUploadInfo("test", v)
						So(err, ShouldBeNil)
						So(b, ShouldBeGreaterThanOrEqualTo, 0)

						content := []byte("test-data1")
						buf := bytes.NewBuffer(content)
						l := buf.Len()
						d := godigest.FromBytes(content)

						// invalid chunk range - fails with localstack...
						_, err = il.PutBlobChunk("test", v, 10, int64(l), buf)
						So(err, ShouldNotBeNil)

						b, err = il.PutBlobChunk("test", v, 0, int64(l), buf)
						So(err, ShouldBeNil)
						So(b, ShouldEqual, l)
						blobDigest := d

						err = il.FinishBlobUpload("test", v, buf, d.String())
						So(err, ShouldBeNil)

						_, _, err = il.CheckBlob("test", d.String())
						So(err, ShouldBeNil)

						_, _, err = il.GetBlob("test", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)

						m := ispec.Manifest{}
						m.SchemaVersion = 2
						mb, _ := json.Marshal(m)

						Convey("Bad image manifest", func() {
							_, err = il.PutImageManifest("test", d.String(), "application/json", mb)
							So(err, ShouldNotBeNil)

							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, []byte{})
							So(err, ShouldNotBeNil)

							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, []byte(`{"test":true}`))
							So(err, ShouldNotBeNil)

							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
							So(err, ShouldNotBeNil)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldNotBeNil)

							_, _, _, err = il.GetImageManifest("inexistent", d.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							annotationsMap := make(map[string]string)
							annotationsMap[ispec.AnnotationRefName] = "1.0"
							m := ispec.Manifest{
								Config: ispec.Descriptor{
									Digest: d,
									Size:   int64(l),
								},
								Layers: []ispec.Descriptor{
									{
										MediaType: "application/vnd.oci.image.layer.v1.tar",
										Digest:    d,
										Size:      int64(l),
									},
								},
								Annotations: annotationsMap,
							}

							m.SchemaVersion = 2
							mb, _ = json.Marshal(m)
							d := godigest.FromBytes(mb)

							// bad manifest
							m.Layers[0].Digest = godigest.FromBytes([]byte("inexistent"))
							badMb, _ := json.Marshal(m)

							_, err = il.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, badMb)
							So(err, ShouldNotBeNil)

							_, err = il.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, err = il.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							_, err = il.PutImageManifest("test", "2.0", ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							_, err := il.PutImageManifest("test", "3.0", ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							_, err = il.GetImageTags("inexistent")
							So(err, ShouldNotBeNil)

							// total tags should be 3 but they have same reference.
							tags, err := il.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 3)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldBeNil)

							_, _, _, err = il.GetImageManifest("test", "3.0")
							So(err, ShouldBeNil)

							err = il.DeleteImageManifest("test", "1.0")
							So(err, ShouldBeNil)

							tags, err = il.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 2)

							// We deleted only one tag, make sure blob should not be removed.
							hasBlob, _, err := il.CheckBlob("test", d.String())
							So(err, ShouldBeNil)
							So(hasBlob, ShouldEqual, true)

							// If we pass reference all manifest with input reference should be deleted.
							err = il.DeleteImageManifest("test", d.String())
							So(err, ShouldBeNil)

							tags, err = il.GetImageTags("test")
							So(err, ShouldBeNil)
							So(len(tags), ShouldEqual, 0)

							// All tags/references are deleted, blob should not be present in disk.
							hasBlob, _, err = il.CheckBlob("test", d.String())
							So(err, ShouldNotBeNil)
							So(hasBlob, ShouldEqual, false)

							err = il.DeleteBlob("test", "inexistent")
							So(err, ShouldNotBeNil)

							err = il.DeleteBlob("test", godigest.FromBytes([]byte("inexistent")).String())
							So(err, ShouldNotBeNil)

							err = il.DeleteBlob("test", blobDigest.String())
							So(err, ShouldBeNil)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldNotBeNil)
						})
					})

					err = il.DeleteBlobUpload("test", v)
					So(err, ShouldNotBeNil)
				})

				Convey("New blob upload streamed", func() {
					v, err := il.NewBlobUpload("test")
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)

					Convey("Get blob upload", func() {
						err = il.FinishBlobUpload("test", v, bytes.NewBuffer([]byte{}), "inexistent")
						So(err, ShouldNotBeNil)

						b, err := il.GetBlobUpload("test", "invalid")
						So(err, ShouldNotBeNil)
						So(b, ShouldEqual, -1)

						b, err = il.GetBlobUpload("test", v)
						So(err, ShouldBeNil)
						So(b, ShouldBeGreaterThanOrEqualTo, 0)

						_, err = il.BlobUploadInfo("test", "inexistent")
						So(err, ShouldNotBeNil)

						b, err = il.BlobUploadInfo("test", v)
						So(err, ShouldBeNil)
						So(b, ShouldBeGreaterThanOrEqualTo, 0)

						content := []byte("test-data2")
						buf := bytes.NewBuffer(content)
						l := buf.Len()
						d := godigest.FromBytes(content)
						b, err = il.PutBlobChunkStreamed("test", v, buf)
						So(err, ShouldBeNil)
						So(b, ShouldEqual, l)

						_, err = il.PutBlobChunkStreamed("test", "inexistent", buf)
						So(err, ShouldNotBeNil)

						err = il.FinishBlobUpload("test", "inexistent", buf, d.String())
						So(err, ShouldNotBeNil)

						err = il.FinishBlobUpload("test", v, buf, d.String())
						So(err, ShouldBeNil)

						_, _, err = il.CheckBlob("test", d.String())
						So(err, ShouldBeNil)

						_, _, err = il.GetBlob("test", "inexistent", "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldNotBeNil)

						_, _, err = il.GetBlob("test", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
						So(err, ShouldBeNil)

						blobContent, err := il.GetBlobContent("test", d.String())
						So(err, ShouldBeNil)
						So(content, ShouldResemble, blobContent)

						_, err = il.GetBlobContent("inexistent", d.String())
						So(err, ShouldNotBeNil)

						m := ispec.Manifest{}
						m.SchemaVersion = 2
						mb, _ := json.Marshal(m)

						Convey("Bad digests", func() {
							_, _, err := il.FullBlobUpload("test", bytes.NewBuffer([]byte{}), "inexistent")
							So(err, ShouldNotBeNil)

							_, _, err = il.CheckBlob("test", "inexistent")
							So(err, ShouldNotBeNil)
						})

						Convey("Bad image manifest", func() {
							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
							So(err, ShouldNotBeNil)

							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, []byte("bad json"))
							So(err, ShouldNotBeNil)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldNotBeNil)
						})

						Convey("Good image manifest", func() {
							m := ispec.Manifest{
								Config: ispec.Descriptor{
									Digest: d,
									Size:   int64(l),
								},
								Layers: []ispec.Descriptor{
									{
										MediaType: "application/vnd.oci.image.layer.v1.tar",
										Digest:    d,
										Size:      int64(l),
									},
								},
							}
							m.SchemaVersion = 2
							mb, _ = json.Marshal(m)
							d := godigest.FromBytes(mb)
							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							// same manifest for coverage
							_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
							So(err, ShouldBeNil)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldBeNil)

							_, err = il.GetIndexContent("inexistent")
							So(err, ShouldNotBeNil)

							indexContent, err := il.GetIndexContent("test")
							So(err, ShouldBeNil)

							var index ispec.Index

							err = json.Unmarshal(indexContent, &index)
							So(err, ShouldBeNil)

							So(len(index.Manifests), ShouldEqual, 1)
							err = il.DeleteImageManifest("test", "1.0")
							So(err, ShouldNotBeNil)

							err = il.DeleteImageManifest("inexistent", "1.0")
							So(err, ShouldNotBeNil)

							err = il.DeleteImageManifest("test", d.String())
							So(err, ShouldBeNil)

							_, _, _, err = il.GetImageManifest("test", d.String())
							So(err, ShouldNotBeNil)
						})
					})

					err = il.DeleteBlobUpload("test", v)
					So(err, ShouldNotBeNil)
				})

				Convey("Modify manifest in-place", func() {
					// original blob
					v, err := il.NewBlobUpload("replace")
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)

					content := []byte("test-data-replace-1")
					buf := bytes.NewBuffer(content)
					l := buf.Len()
					d := godigest.FromBytes(content)
					b, err := il.PutBlobChunkStreamed("replace", v, buf)
					So(err, ShouldBeNil)
					So(b, ShouldEqual, l)
					blobDigest1 := strings.Split(d.String(), ":")[1]
					So(blobDigest1, ShouldNotBeEmpty)

					err = il.FinishBlobUpload("replace", v, buf, d.String())
					So(err, ShouldBeNil)
					So(b, ShouldEqual, l)

					m := ispec.Manifest{}
					m.SchemaVersion = 2
					m = ispec.Manifest{
						Config: ispec.Descriptor{
							Digest: d,
							Size:   int64(l),
						},
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/vnd.oci.image.layer.v1.tar",
								Digest:    d,
								Size:      int64(l),
							},
						},
					}
					m.SchemaVersion = 2
					mb, _ := json.Marshal(m)
					d = godigest.FromBytes(mb)
					_, err = il.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)

					_, _, _, err = il.GetImageManifest("replace", d.String())
					So(err, ShouldBeNil)

					// new blob to replace
					v, err = il.NewBlobUpload("replace")
					So(err, ShouldBeNil)
					So(v, ShouldNotBeEmpty)

					content = []byte("test-data-replace-2")
					buf = bytes.NewBuffer(content)
					l = buf.Len()
					d = godigest.FromBytes(content)
					b, err = il.PutBlobChunkStreamed("replace", v, buf)
					So(err, ShouldBeNil)
					So(b, ShouldEqual, l)
					blobDigest2 := strings.Split(d.String(), ":")[1]
					So(blobDigest2, ShouldNotBeEmpty)

					err = il.FinishBlobUpload("replace", v, buf, d.String())
					So(err, ShouldBeNil)
					So(b, ShouldEqual, l)

					m = ispec.Manifest{
						Config: ispec.Descriptor{
							Digest: d,
							Size:   int64(l),
						},
						Layers: []ispec.Descriptor{
							{
								MediaType: "application/vnd.oci.image.layer.v1.tar",
								Digest:    d,
								Size:      int64(l),
							},
						},
					}
					m.SchemaVersion = 2
					mb, _ = json.Marshal(m)
					_ = godigest.FromBytes(mb)
					_, err = il.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)
				})

				Convey("Locks", func() {
					// in parallel, a mix of read and write locks - mainly for coverage
					var wg sync.WaitGroup
					for i := 0; i < 1000; i++ {
						wg.Add(2)
						go func() {
							defer wg.Done()
							il.Lock()
							func() {}()
							il.Unlock()
						}()
						go func() {
							defer wg.Done()
							il.RLock()
							func() {}()
							il.RUnlock()
						}()
					}
					wg.Wait()
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
				firstStorageDriver, firstStore, _ = createObjectsStore(firstRootDir)
				defer cleanupStorage(firstStorageDriver, firstRootDir)

				secondRootDir = "/util_test2"
				secondStorageDriver, secondStore, _ = createObjectsStore(secondRootDir)
				defer cleanupStorage(secondStorageDriver, secondRootDir)

				thirdRootDir = "/util_test3"
				thirdStorageDriver, thirdStore, _ = createObjectsStore(thirdRootDir)
				defer cleanupStorage(thirdStorageDriver, thirdRootDir)
			} else {
				// Create temporary directory
				var err error

				firstRootDir, err = ioutil.TempDir("", "util_test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(firstRootDir)

				secondRootDir, err = ioutil.TempDir("", "util_test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(secondRootDir)

				thirdRootDir, err = ioutil.TempDir("", "util_test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(thirdRootDir)

				log := log.NewLogger("debug", "")

				// Create ImageStore
				firstStore = storage.NewImageStoreFS(firstRootDir, false, false, log)

				secondStore = storage.NewImageStoreFS(secondRootDir, false, false, log)

				thirdStore = storage.NewImageStoreFS(thirdRootDir, false, false, log)
			}

			Convey("Test storage handler", t, func() {
				storeController := storage.StoreController{}

				storeController.DefaultStore = firstStore

				subStore := make(map[string]storage.ImageStore)

				subStore["/a"] = secondStore
				subStore["/b"] = thirdStore

				storeController.SubStore = subStore

				is := storeController.GetImageStore("zot-x-test")
				So(is.RootDir(), ShouldEqual, firstRootDir)

				is = storeController.GetImageStore("a/zot-a-test")
				So(is.RootDir(), ShouldEqual, secondRootDir)

				is = storeController.GetImageStore("b/zot-b-test")
				So(is.RootDir(), ShouldEqual, thirdRootDir)

				is = storeController.GetImageStore("c/zot-c-test")
				So(is.RootDir(), ShouldEqual, firstRootDir)
			})
		})
	}
}
