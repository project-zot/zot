package storage_test

import (
	"bytes"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"math/rand"
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
)

func TestStorageFSAPIs(t *testing.T) {
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

		Convey("Bad image manifest", func() {
			v, err := il.NewBlobUpload("test")
			So(err, ShouldBeNil)
			So(v, ShouldNotBeEmpty)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			l := buf.Len()
			d := godigest.FromBytes(content)

			b, err := il.PutBlobChunk(repoName, v, 0, int64(l), buf)
			So(err, ShouldBeNil)
			So(b, ShouldEqual, l)

			err = il.FinishBlobUpload("test", v, buf, d.String())
			So(err, ShouldBeNil)

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
			d = godigest.FromBytes(mb)

			err = os.Chmod(path.Join(il.RootDir(), repoName, "index.json"), 0000)
			if err != nil {
				panic(err)
			}

			_, err = il.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mb)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(il.RootDir(), repoName, "index.json"), 0755)
			if err != nil {
				panic(err)
			}

			_, err = il.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mb)
			So(err, ShouldBeNil)

			manifestPath := path.Join(il.RootDir(), repoName, "blobs", d.Algorithm().String(), d.Encoded())

			err = os.Chmod(manifestPath, 0000)
			if err != nil {
				panic(err)
			}

			_, _, _, err = il.GetImageManifest(repoName, d.String())
			So(err, ShouldNotBeNil)

			err = os.Remove(manifestPath)
			if err != nil {
				panic(err)
			}

			_, _, _, err = il.GetImageManifest(repoName, d.String())
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(il.RootDir(), repoName), 0000)
			if err != nil {
				panic(err)
			}

			_, err = il.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, mb)
			So(err, ShouldNotBeNil)
			err = os.Chmod(path.Join(il.RootDir(), repoName), 0755)
			if err != nil {
				panic(err)
			}

			// invalid GetReferrers
			_, err = il.GetReferrers("invalid", "invalid", "invalid")
			So(err, ShouldNotBeNil)

			_, err = il.GetReferrers(repoName, "invalid", "invalid")
			So(err, ShouldNotBeNil)

			_, err = il.GetReferrers(repoName, d.String(), "invalid")
			So(err, ShouldNotBeNil)

			// invalid DeleteImageManifest
			indexPath := path.Join(il.RootDir(), repoName, "index.json")
			err = os.Chmod(indexPath, 0000)
			if err != nil {
				panic(err)
			}

			err = il.DeleteImageManifest(repoName, d.String())
			So(err, ShouldNotBeNil)

			err = os.RemoveAll(path.Join(il.RootDir(), repoName))
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
	il := storage.NewImageStore(dir, true, true, log, metrics)

	Convey("Dedupe", t, func(c C) {
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
			il := storage.NewImageStore(dir, true, true, log, metrics)

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
		if err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			err = il.InitRepo("test")
			So(err, ShouldNotBeNil)
		}

		err = os.Chmod(dir, 0755)
		if err != nil {
			panic(err)
		}

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
		if err != nil {
			panic(err)
		}
		_, err = il.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrRepoNotFound)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0755) // remove all perms
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "blobs"), []byte{}, 0755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", "index.json"), []byte{}, 0755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte{}, 0755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err := il.ValidateRepo("invalid-test")
		So(err, ShouldBeNil)
		So(isValid, ShouldEqual, false)

		err = os.Remove(path.Join(dir, "invalid-test", "blobs"))
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(path.Join(dir, "invalid-test", "blobs"), 0755)
		if err != nil {
			panic(err)
		}
		isValid, err = il.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(isValid, ShouldEqual, false)

		err = ioutil.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte("{}"), 0755) // nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err = il.ValidateRepo("invalid-test")
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

		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		_, err = il.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0000) // remove all perms
		if err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			So(func() { _, _ = il.ValidateRepo("test") }, ShouldPanic)
		}

		err = os.Chmod(dir, 0755) // remove all perms
		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(dir)
		if err != nil {
			panic(err)
		}

		_, err = il.GetRepositories()
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
		il := storage.NewImageStore(dir, true, true, log, metrics)

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
		il := storage.NewImageStore(dir, true, true, log, metrics)

		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", "index.json"), 0000)
		if err != nil {
			panic(err)
		}

		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.Remove(path.Join(dir, "test", "index.json"))
		if err != nil {
			panic(err)
		}

		_, _, _, err = il.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		So(il.InitRepo("test"), ShouldBeNil)

		err = ioutil.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0600)
		if err != nil {
			panic(err)
		}
		_, _, _, err = il.GetImageManifest("test", "")
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
		il := storage.NewImageStore(dir, true, true, log, metrics)

		So(il, ShouldNotBeNil)
		So(il.InitRepo("test"), ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0000)
		if err != nil {
			panic(err)
		}
		_, err = il.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0000)
		if err != nil {
			panic(err)
		}

		_, err = il.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0755)
		if err != nil {
			panic(err)
		}

		So(il.InitRepo("test"), ShouldBeNil)

		_, err = il.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0755)
		if err != nil {
			panic(err)
		}

		v, err := il.NewBlobUpload("test")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0000)
		if err != nil {
			panic(err)
		}

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		_, err = il.PutBlobChunkStreamed("test", v, buf)
		So(err, ShouldNotBeNil)

		_, err = il.PutBlobChunk("test", v, 0, int64(l), buf)
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
		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(path.Join(dir, "dedupe2", "blobs/sha256", blobDigest1), content, 0755) // nolint: gosec
		if err != nil {
			panic(err)
		}

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

	Convey("DirExists call with a filename as argument", t, func(c C) {
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		filePath := path.Join(dir, "file.txt")
		err = ioutil.WriteFile(filePath, []byte("some dummy file content"), 0644) //nolint: gosec
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

		rand.Seed(time.Now().UnixNano())
		for {
			randomLen := rand.Intn(100)
			randomDir = "/tmp/" + randSeq(randomLen)

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
		err = ioutil.WriteFile(filePath, []byte("some dummy file content"), 0644) //nolint: gosec
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

		err = ioutil.WriteFile(path.Join(dir, "hardtest.txt"), []byte("testing hard link code"), 0644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(dir, 0400)
		if err != nil {
			panic(err)
		}

		err = os.Link(path.Join(dir, "hardtest.txt"), path.Join(dir, "duphardtest.txt"))
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0644)
		if err != nil {
			panic(err)
		}
	})
}

func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}
