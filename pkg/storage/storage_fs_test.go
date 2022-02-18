package storage_test

import (
	"bytes"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	tag = "1.0"
)

func TestStorageFSAPIs(t *testing.T) {
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

	Convey("Repo layout", t, func(c C) {
		repoName := "test"

		Convey("Bad image manifest", func() {
			upload, err := imgStore.NewBlobUpload("test")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)

			blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload("test", upload, buf, digest.String())
			So(err, ShouldBeNil)

			annotationsMap := make(map[string]string)
			annotationsMap[ispec.AnnotationRefName] = tag

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
				Annotations: annotationsMap,
			}

			manifest.SchemaVersion = 2
			manifestBuf, _ := json.Marshal(manifest)
			digest = godigest.FromBytes(manifestBuf)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "index.json"), 0o000)
			if err != nil {
				panic(err)
			}

			_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "index.json"), 0o755)
			if err != nil {
				panic(err)
			}

			_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			manifestPath := path.Join(imgStore.RootDir(), repoName, "blobs", digest.Algorithm().String(), digest.Encoded())

			err = os.Chmod(manifestPath, 0o000)
			if err != nil {
				panic(err)
			}

			_, _, _, err = imgStore.GetImageManifest(repoName, digest.String())
			So(err, ShouldNotBeNil)

			err = os.Remove(manifestPath)
			if err != nil {
				panic(err)
			}

			_, _, _, err = imgStore.GetImageManifest(repoName, digest.String())
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o000)
			if err != nil {
				panic(err)
			}

			_, err = imgStore.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)
			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o755)
			if err != nil {
				panic(err)
			}

			// invalid GetReferrers
			_, err = imgStore.GetReferrers("invalid", "invalid", "invalid")
			So(err, ShouldNotBeNil)

			_, err = imgStore.GetReferrers(repoName, "invalid", "invalid")
			So(err, ShouldNotBeNil)

			_, err = imgStore.GetReferrers(repoName, digest.String(), "invalid")
			So(err, ShouldNotBeNil)

			// invalid DeleteImageManifest
			indexPath := path.Join(imgStore.RootDir(), repoName, "index.json")
			err = os.Chmod(indexPath, 0o000)
			if err != nil {
				panic(err)
			}

			err = imgStore.DeleteImageManifest(repoName, digest.String())
			So(err, ShouldNotBeNil)

			err = os.RemoveAll(path.Join(imgStore.RootDir(), repoName))
			if err != nil {
				panic(err)
			}
		})
	})
}

func TestDedupeLinks(t *testing.T) {
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

	Convey("Dedupe", t, func(c C) {
		// manifest1
		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
		blobDigest1 := strings.Split(digest.String(), ":")[1]
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, _, err = imgStore.CheckBlob("dedupe1", digest.String())
		So(err, ShouldBeNil)

		_, _, err = imgStore.GetBlob("dedupe1", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)

		cblob, cdigest := test.GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest.String())
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))
		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest.String())
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
		manifestBuf, _ := json.Marshal(manifest)
		digest = godigest.FromBytes(manifestBuf)
		_, err = imgStore.PutImageManifest("dedupe1", digest.String(), ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", digest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)
		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
		blobDigest2 := strings.Split(digest.String(), ":")[1]
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		_, _, err = imgStore.CheckBlob("dedupe2", digest.String())
		So(err, ShouldBeNil)

		_, _, err = imgStore.GetBlob("dedupe2", digest.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)

		cblob, cdigest = test.GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest.String())
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))
		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest.String())
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
		manifestBuf, _ = json.Marshal(manifest)
		digest = godigest.FromBytes(manifestBuf)
		_, err = imgStore.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", digest.String())
		So(err, ShouldBeNil)

		// verify that dedupe with hard links happened
		fi1, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest1))
		So(err, ShouldBeNil)
		fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
		So(err, ShouldBeNil)
		So(os.SameFile(fi1, fi2), ShouldBeTrue)
	})
}

func TestDedupe(t *testing.T) {
	Convey("Dedupe", t, func(c C) {
		Convey("Nil ImageStore", func() {
			var is storage.ImageStore
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
			il := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

			So(il.DedupeBlob("", "", ""), ShouldNotBeNil)
		})
	})
}

// nolint: gocyclo
func TestNegativeCases(t *testing.T) {
	Convey("Invalid root dir", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		So(storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics), ShouldNotBeNil)
		if os.Geteuid() != 0 {
			So(storage.NewImageStore("/deadBEEF", true, storage.DefaultGCDelay, true, true, log, metrics), ShouldBeNil)
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
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		err = os.Chmod(dir, 0o000) // remove all perms
		if err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			err = imgStore.InitRepo("test")
			So(err, ShouldNotBeNil)
		}

		err = os.Chmod(dir, 0o755)
		if err != nil {
			panic(err)
		}

		// Init repo should fail if repo is a file.
		err = ioutil.WriteFile(path.Join(dir, "file-test"), []byte("this is test file"), 0o755) // nolint:gosec
		So(err, ShouldBeNil)
		err = imgStore.InitRepo("file-test")
		So(err, ShouldNotBeNil)

		err = os.Mkdir(path.Join(dir, "test-dir"), 0o755)
		So(err, ShouldBeNil)

		err = imgStore.InitRepo("test-dir")
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
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err = os.MkdirAll(path.Join(dir, "invalid-test"), 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0o000) // remove all perms
		if err != nil {
			panic(err)
		}
		_, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrRepoNotFound)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0o755) // remove all perms
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "blobs"), []byte{}, 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "index.json"), []byte{}, 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte{}, 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err := imgStore.ValidateRepo("invalid-test")
		So(err, ShouldBeNil)
		So(isValid, ShouldEqual, false)

		err = os.Remove(path.Join(dir, "invalid-test", "blobs"))
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(path.Join(dir, "invalid-test", "blobs"), 0o755)
		if err != nil {
			panic(err)
		}
		isValid, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(isValid, ShouldEqual, false)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte("{}"), 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrRepoBadVersion)
		So(isValid, ShouldEqual, false)

		files, err := ioutil.ReadDir(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		for _, f := range files {
			os.Remove(path.Join(dir, "test", f.Name()))
		}

		_, err = imgStore.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		_, err = imgStore.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o000) // remove all perms
		if err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			So(func() { _, _ = imgStore.ValidateRepo("test") }, ShouldPanic)
		}

		err = os.Chmod(dir, 0o755) // remove all perms
		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(dir)
		if err != nil {
			panic(err)
		}

		_, err = imgStore.GetRepositories()
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image tags", t, func(c C) {
		var ilfs storage.ImageStoreFS
		_, err := ilfs.GetImageTags("test")
		So(err, ShouldNotBeNil)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)
		So(os.Remove(path.Join(dir, "test", "index.json")), ShouldBeNil)
		_, err = imgStore.GetImageTags("test")
		So(err, ShouldNotBeNil)
		So(os.RemoveAll(path.Join(dir, "test")), ShouldBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)
		So(ioutil.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0o600), ShouldBeNil)
		_, err = imgStore.GetImageTags("test")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image manifest", t, func(c C) {
		var ilfs storage.ImageStoreFS
		_, _, _, err := ilfs.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.Remove(path.Join(dir, "test", "index.json"))
		if err != nil {
			panic(err)
		}

		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		So(imgStore.InitRepo("test"), ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0o600)
		if err != nil {
			panic(err)
		}
		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid new blob upload", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o000)
		if err != nil {
			panic(err)
		}
		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0o000)
		if err != nil {
			panic(err)
		}

		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0o755)
		if err != nil {
			panic(err)
		}

		So(imgStore.InitRepo("test"), ShouldBeNil)

		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o755)
		if err != nil {
			panic(err)
		}

		upload, err := imgStore.NewBlobUpload("test")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o000)
		if err != nil {
			panic(err)
		}

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		_, err = imgStore.PutBlobChunkStreamed("test", upload, buf)
		So(err, ShouldNotBeNil)

		_, err = imgStore.PutBlobChunk("test", upload, 0, int64(l), buf)
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
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := strings.Split(digest.String(), ":")[1]
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// Create a file at the same place where FinishBlobUpload will create
		err = imgStore.InitRepo("dedupe2")
		So(err, ShouldBeNil)

		err = os.MkdirAll(path.Join(dir, "dedupe2", "blobs/sha256"), 0o755)
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1), content, 0o755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)
		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		cmd := exec.Command("sudo", "chattr", "+i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldNotBeNil)
		So(blob, ShouldEqual, buflen)

		cmd = exec.Command("sudo", "chattr", "-i", path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1)) // nolint: gosec
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest.String())
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
	})

	Convey("DirExists call with a filename as argument", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		filePath := path.Join(dir, "file.txt")
		err = ioutil.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		ok := storage.DirExists(filePath)
		So(ok, ShouldBeFalse)
	})
}

func TestHardLink(t *testing.T) {
	Convey("Test that ValidateHardLink creates rootDir if it does not exist", t, func() {
		var randomDir string

		for {
			nBig, err := rand.Int(rand.Reader, big.NewInt(100))
			if err != nil {
				panic(err)
			}
			randomDir = "/tmp/" + randSeq(int(nBig.Int64()))

			if _, err := os.Stat(randomDir); os.IsNotExist(err) {
				break
			}
		}
		defer os.RemoveAll(randomDir)

		err := storage.ValidateHardLink(randomDir)
		So(err, ShouldBeNil)
	})
	Convey("Test that ValidateHardLink returns error if rootDir is a file", t, func() {
		dir, err := ioutil.TempDir("", "storage-hard-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		filePath := path.Join(dir, "file.txt")
		err = ioutil.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = storage.ValidateHardLink(filePath)
		So(err, ShouldNotBeNil)
	})
	Convey("Test if filesystem supports hardlink", t, func() {
		dir, err := ioutil.TempDir("", "storage-hard-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		err = storage.ValidateHardLink(dir)
		So(err, ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "hardtest.txt"), []byte("testing hard link code"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(dir, 0o400)
		if err != nil {
			panic(err)
		}

		err = os.Link(path.Join(dir, "hardtest.txt"), path.Join(dir, "duphardtest.txt"))
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o644)
		if err != nil {
			panic(err)
		}
	})
}

func TestInjectWriteFile(t *testing.T) {
	Convey("writeFile with commit", t, func() {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)

		Convey("Failure path1", func() {
			injected := test.InjectFailure(0)

			err := imgStore.InitRepo("repo1")
			if injected {
				So(err, ShouldNotBeNil)
			} else {
				So(err, ShouldBeNil)
			}
		})

		Convey("Failure path2", func() {
			injected := test.InjectFailure(1)

			err := imgStore.InitRepo("repo2")
			if injected {
				So(err, ShouldNotBeNil)
			} else {
				So(err, ShouldBeNil)
			}
		})
	})

	Convey("writeFile without commit", t, func() {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, false, log, metrics)

		Convey("Failure path not reached", func() {
			err := imgStore.InitRepo("repo1")
			So(err, ShouldBeNil)
		})
	})
}

func TestGarbageCollect(t *testing.T) {
	Convey("Repo layout", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-gc-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(dir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		Convey("Garbage collect with default/long delay", func() {
			imgStore := storage.NewImageStore(dir, true, storage.DefaultGCDelay, true, true, log, metrics)
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

			err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest.String())
			So(err, ShouldBeNil)

			annotationsMap := make(map[string]string)
			annotationsMap[ispec.AnnotationRefName] = tag

			cblob, cdigest := test.GetRandomImageConfig()
			_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest.String())
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))
			hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest.String())
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
			manifestBuf, _ := json.Marshal(manifest)
			digest := godigest.FromBytes(manifestBuf)

			_, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest.String())
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

			err = imgStore.DeleteImageManifest(repoName, digest.String())
			So(err, ShouldBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest.String())
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)
		})

		Convey("Garbage collect with short delay", func() {
			imgStore := storage.NewImageStore(dir, true, 1*time.Second, true, true, log, metrics)
			repoName := "gc-short"

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

			err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest.String())
			So(err, ShouldBeNil)

			// sleep so orphan blob can be GC'ed
			time.Sleep(5 * time.Second)

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

			err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest.String())
			So(err, ShouldBeNil)

			annotationsMap := make(map[string]string)
			annotationsMap[ispec.AnnotationRefName] = tag

			cblob, cdigest := test.GetRandomImageConfig()
			_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest.String())
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))
			hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest.String())
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
			manifestBuf, _ := json.Marshal(manifest)
			digest := godigest.FromBytes(manifestBuf)

			_, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, odigest.String())
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest.String())
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

			// sleep so orphan blob can be GC'ed
			time.Sleep(5 * time.Second)

			err = imgStore.DeleteImageManifest(repoName, digest.String())
			So(err, ShouldBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest.String())
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)
		})
	})
}

func randSeq(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	buf := make([]rune, n)
	for index := range buf {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}

		buf[index] = letters[int(nBig.Int64())]
	}

	return string(buf)
}
