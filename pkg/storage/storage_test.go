package storage_test

import (
	"bytes"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAPIs(t *testing.T) {
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	il := storage.NewImageStore(dir, true, true, log, metrics)

	Convey("Repo layout", t, func(c C) {
		repoName := "test"

		Convey("Validate repo without initialization", func() {
			v, err := il.ValidateRepo(repoName)
			So(v, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})

		Convey("Initialize repo", func() {
			err := il.InitRepo(repoName)
			So(err, ShouldBeNil)
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
				b, err = il.PutBlobChunk("test", v, 0, int64(l), buf)
				So(err, ShouldBeNil)
				So(b, ShouldEqual, l)
				blobDigest := d

				err = il.FinishBlobUpload("test", v, buf, d.String())
				So(err, ShouldBeNil)
				So(b, ShouldEqual, l)

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

					_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
					So(err, ShouldNotBeNil)

					_, _, _, err = il.GetImageManifest("test", d.String())
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
					mb, _ := json.Marshal(m)
					d := godigest.FromBytes(mb)
					_, err = il.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)

					_, err = il.PutImageManifest("test", "2.0", ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)

					_, err = il.PutImageManifest("test", "3.0", ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)

					// total tags should be 3 but they have same reference.
					tags, err := il.GetImageTags("test")
					So(err, ShouldBeNil)
					So(len(tags), ShouldEqual, 3)

					_, _, _, err = il.GetImageManifest("test", d.String())
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
				b, err := il.GetBlobUpload("test", "invalid")
				So(err, ShouldNotBeNil)
				So(b, ShouldEqual, -1)

				b, err = il.GetBlobUpload("test", v)
				So(err, ShouldBeNil)
				So(b, ShouldBeGreaterThanOrEqualTo, 0)

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

				err = il.FinishBlobUpload("test", v, buf, d.String())
				So(err, ShouldBeNil)
				So(b, ShouldEqual, l)

				_, _, err = il.CheckBlob("test", d.String())
				So(err, ShouldBeNil)

				_, _, err = il.GetBlob("test", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldBeNil)

				m := ispec.Manifest{}
				m.SchemaVersion = 2
				mb, _ := json.Marshal(m)

				Convey("Bad image manifest", func() {
					_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
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

					_, _, _, err = il.GetImageManifest("test", d.String())
					So(err, ShouldBeNil)

					err = il.DeleteImageManifest("test", "1.0")
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

		Convey("Dedupe", func() {
			blobDigest1 := ""
			blobDigest2 := ""

			// manifest1
			v, err := il.NewBlobUpload("dedupe1")
			So(err, ShouldBeNil)
			So(v, ShouldNotBeEmpty)

			content := []byte("test-data3")
			buf := bytes.NewBuffer(content)
			l := buf.Len()
			d := godigest.FromBytes(content)
			b, err := il.PutBlobChunkStreamed("dedupe1", v, buf)
			So(err, ShouldBeNil)
			So(b, ShouldEqual, l)
			blobDigest1 = strings.Split(d.String(), ":")[1]
			So(blobDigest1, ShouldNotBeEmpty)

			err = il.FinishBlobUpload("dedupe1", v, buf, d.String())
			So(err, ShouldBeNil)
			So(b, ShouldEqual, l)

			_, _, err = il.CheckBlob("dedupe1", d.String())
			So(err, ShouldBeNil)

			_, _, err = il.GetBlob("dedupe1", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)

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
			_, err = il.PutImageManifest("dedupe1", d.String(), ispec.MediaTypeImageManifest, mb)
			So(err, ShouldBeNil)

			_, _, _, err = il.GetImageManifest("dedupe1", d.String())
			So(err, ShouldBeNil)

			// manifest2
			v, err = il.NewBlobUpload("dedupe2")
			So(err, ShouldBeNil)
			So(v, ShouldNotBeEmpty)

			content = []byte("test-data3")
			buf = bytes.NewBuffer(content)
			l = buf.Len()
			d = godigest.FromBytes(content)
			b, err = il.PutBlobChunkStreamed("dedupe2", v, buf)
			So(err, ShouldBeNil)
			So(b, ShouldEqual, l)
			blobDigest2 = strings.Split(d.String(), ":")[1]
			So(blobDigest2, ShouldNotBeEmpty)

			err = il.FinishBlobUpload("dedupe2", v, buf, d.String())
			So(err, ShouldBeNil)
			So(b, ShouldEqual, l)

			_, _, err = il.CheckBlob("dedupe2", d.String())
			So(err, ShouldBeNil)

			_, _, err = il.GetBlob("dedupe2", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)

			m = ispec.Manifest{}
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
			mb, _ = json.Marshal(m)
			d = godigest.FromBytes(mb)
			_, err = il.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest, mb)
			So(err, ShouldBeNil)

			_, _, _, err = il.GetImageManifest("dedupe2", d.String())
			So(err, ShouldBeNil)

			// verify that dedupe with hard links happened
			fi1, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest1))
			So(err, ShouldBeNil)
			fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
			So(err, ShouldBeNil)
			So(os.SameFile(fi1, fi2), ShouldBeTrue)
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
}

func TestDedupe(t *testing.T) {
	Convey("Dedupe", t, func(c C) {
		Convey("Nil ImageStore", func() {
			is := &storage.ImageStore{}
			So(func() { _ = is.DedupeBlob("", "", "") }, ShouldPanic)
		})

		Convey("Valid ImageStore", func() {
			dir, err := ioutil.TempDir("", "oci-repo-test")
			if err != nil {
				panic(err)
			}
			defer os.RemoveAll(dir)

			log := log.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)
			is := storage.NewImageStore(dir, true, true, log, metrics)

			So(is.DedupeBlob("", "", ""), ShouldNotBeNil)
		})
	})
}

func TestNegativeCases(t *testing.T) {
	Convey("Invalid root dir", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		So(storage.NewImageStore(dir, true, true, log, metrics), ShouldNotBeNil)
		if os.Geteuid() != 0 {
			So(storage.NewImageStore("/deadBEEF", true, true, log, metrics), ShouldBeNil)
		}
	})

	Convey("Invalid init repo", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		il := storage.NewImageStore(dir, true, true, log, metrics)
		err = os.Chmod(dir, 0000) // remove all perms
		So(err, ShouldBeNil)
		if os.Geteuid() != 0 {
			err = il.InitRepo("test")
			So(err, ShouldNotBeNil)
		}

		err = os.Chmod(dir, 0755)
		So(err, ShouldBeNil)

		// Init repo should fail if repo is a file.
		err = ioutil.WriteFile(path.Join(dir, "file-test"), []byte("this is test file"), 0755) // nolint:gosec
		So(err, ShouldBeNil)
		err = il.InitRepo("file-test")
		So(err, ShouldNotBeNil)

		err = os.Mkdir(path.Join(dir, "test-dir"), 0755)
		So(err, ShouldBeNil)

		err = il.InitRepo("test-dir")
		So(err, ShouldBeNil)
	})

	Convey("Invalid validate repo", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		il := storage.NewImageStore(dir, true, true, log, metrics)
		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)

		err = os.MkdirAll(path.Join(dir, "invalid-test"), 0755)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0000) // remove all perms
		So(err, ShouldBeNil)

		_, err = il.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrRepoNotFound)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0755) // remove all perms
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "blobs"), []byte{}, 0755) // nolint: gosec
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "index.json"), []byte{}, 0755) // nolint: gosec
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte{}, 0755) // nolint: gosec
		So(err, ShouldBeNil)

		isValid, err := il.ValidateRepo("invalid-test")
		So(err, ShouldBeNil)
		So(isValid, ShouldEqual, false)

		err = os.Remove(path.Join(dir, "invalid-test", "blobs"))
		So(err, ShouldBeNil)

		err = os.Mkdir(path.Join(dir, "invalid-test", "blobs"), 0755)
		So(err, ShouldBeNil)

		isValid, err = il.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(isValid, ShouldEqual, false)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte("{}"), 0755) // nolint: gosec
		So(err, ShouldBeNil)

		isValid, err = il.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrRepoBadVersion)
		So(isValid, ShouldEqual, false)

		files, err := ioutil.ReadDir(path.Join(dir, "test"))
		So(err, ShouldBeNil)
		for _, f := range files {
			os.Remove(path.Join(dir, "test", f.Name()))
		}
		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)
		os.RemoveAll(path.Join(dir, "test"))
		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)
		err = os.Chmod(dir, 0000) // remove all perms
		So(err, ShouldBeNil)
		if os.Geteuid() != 0 {
			So(func() { _, _ = il.ValidateRepo("test") }, ShouldPanic)
		}
		os.RemoveAll(dir)
		_, err = il.GetRepositories()
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image tags", t, func(c C) {
		il := &storage.ImageStore{}
		_, err := il.GetImageTags("test")
		So(err, ShouldNotBeNil)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		il = storage.NewImageStore(dir, true, true, log, metrics)
		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(os.Remove(path.Join(dir, "test", "index.json")), ShouldBeNil)
		_, err = il.GetImageTags("test")
		So(err, ShouldNotBeNil)
		So(os.RemoveAll(path.Join(dir, "test")), ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(ioutil.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0600), ShouldBeNil)
		_, err = il.GetImageTags("test")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image manifest", t, func(c C) {
		il := &storage.ImageStore{}
		_, _, _, err := il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		il = storage.NewImageStore(dir, true, true, log, metrics)
		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(os.Remove(path.Join(dir, "test", "index.json")), ShouldBeNil)
		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
		So(os.RemoveAll(path.Join(dir, "test")), ShouldBeNil)
		So(il.InitRepo("test"), ShouldBeNil)
		So(ioutil.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0600), ShouldBeNil)
		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid dedupe scenarios", t, func() {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		il := storage.NewImageStore(dir, true, true, log, metrics)
		v, err := il.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(v, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		d := godigest.FromBytes(content)
		b, err := il.PutBlobChunkStreamed("dedupe1", v, buf)
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)

		blobDigest1 := strings.Split(d.String(), ":")[1]
		So(blobDigest1, ShouldNotBeEmpty)

		err = il.FinishBlobUpload("dedupe1", v, buf, d.String())
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)

		// Create a file at the same place where FinishBlobUpload will create
		err = il.InitRepo("dedupe2")
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(dir, "dedupe2", "blobs/sha256"), 0755)
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1), content, 0755) // nolint: gosec
		So(err, ShouldBeNil)

		v, err = il.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(v, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		l = buf.Len()
		d = godigest.FromBytes(content)
		b, err = il.PutBlobChunkStreamed("dedupe2", v, buf)
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)

		cmd := exec.Command("sudo", "chattr", "+i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = il.FinishBlobUpload("dedupe2", v, buf, d.String())
		So(err, ShouldNotBeNil)
		So(b, ShouldEqual, l)

		cmd = exec.Command("sudo", "chattr", "-i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = il.FinishBlobUpload("dedupe2", v, buf, d.String())
		So(err, ShouldBeNil)
		So(b, ShouldEqual, l)
	})
}

func TestHardLink(t *testing.T) {
	Convey("Test if filesystem supports hardlink", t, func() {
		dir, err := ioutil.TempDir("", "storage-hard-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		err = storage.ValidateHardLink(dir)
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "hardtest.txt"), []byte("testing hard link code"), 0644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(dir, 0400)
		if err != nil {
			panic(err)
		}

		err = storage.CheckHardLink(path.Join(dir, "hardtest.txt"), path.Join(dir, "duphardtest.txt"))
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0644)
		if err != nil {
			panic(err)
		}
	})
}

func TestStorageHandler(t *testing.T) {
	Convey("Test storage handler", t, func() {
		// Create temporary directory
		firstRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(firstRootDir)

		secondRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(secondRootDir)

		thirdRootDir, err := ioutil.TempDir("", "util_test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(thirdRootDir)

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)

		// Create ImageStore
		firstStore := storage.NewImageStore(firstRootDir, false, false, log, metrics)

		secondStore := storage.NewImageStore(secondRootDir, false, false, log, metrics)

		thirdStore := storage.NewImageStore(thirdRootDir, false, false, log, metrics)

		storeController := storage.StoreController{}

		storeController.DefaultStore = firstStore

		subStore := make(map[string]*storage.ImageStore)

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
}
