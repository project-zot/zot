package storage_test

import (
	"bytes"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

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

	il := storage.NewImageStore(dir, log.Logger{Logger: zerolog.New(os.Stdout)})

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

				content := []byte("test-data")
				buf := bytes.NewBuffer(content)
				l := buf.Len()
				d := godigest.FromBytes(content)
				b, err = il.PutBlobChunk("test", v, 0, int64(l), buf)
				So(err, ShouldBeNil)
				So(b, ShouldEqual, l)

				err = il.FinishBlobUpload("test", v, buf, d.String())
				So(err, ShouldBeNil)
				So(b, ShouldEqual, l)

				_, _, err = il.CheckBlob("test", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldBeNil)

				_, _, err = il.GetBlob("test", d.String(), "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldBeNil)

				m := ispec.Manifest{}
				mb, _ := json.Marshal(m)

				Convey("Bad image manifest", func() {
					_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
					So(err, ShouldNotBeNil)

					_, _, _, err = il.GetImageManifest("test", d.String())
					So(err, ShouldNotBeNil)
				})

				Convey("Good image manifest", func() {
					m := ispec.Manifest{Layers: []ispec.Descriptor{{Digest: d}}}
					mb, _ = json.Marshal(m)
					d := godigest.FromBytes(mb)
					_, err = il.PutImageManifest("test", d.String(), ispec.MediaTypeImageManifest, mb)
					So(err, ShouldBeNil)

					_, _, _, err = il.GetImageManifest("test", d.String())
					So(err, ShouldBeNil)

					err = il.DeleteImageManifest("test", d.String())
					So(err, ShouldBeNil)

					_, _, _, err = il.GetImageManifest("test", d.String())
					So(err, ShouldNotBeNil)
				})

				err = il.DeleteBlob("test", d.String())
				So(err, ShouldBeNil)
			})

			err = il.DeleteBlobUpload("test", v)
			So(err, ShouldBeNil)
		})
	})
}
