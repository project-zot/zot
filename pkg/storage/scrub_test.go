package storage_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

const (
	repoName = "test"
)

func TestCheckAllBlobsIntegrity(t *testing.T) {
	dir, err := ioutil.TempDir("", "scrub-test")
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(dir)

	log := log.NewLogger("debug", "")

	metrics := monitoring.NewMetricsServer(false, log)

	il := storage.NewImageStore(dir, true, true, log, metrics)

	Convey("Scrub only one repo", t, func(c C) {
		// initialize repo
		err = il.InitRepo(repoName)
		So(err, ShouldBeNil)
		ok := il.DirExists(path.Join(il.RootDir(), repoName))
		So(ok, ShouldBeTrue)
		storeController := storage.StoreController{}
		storeController.DefaultStore = il
		So(storeController.GetImageStore(repoName), ShouldResemble, il)

		sc := storage.StoreController{}
		sc.DefaultStore = il

		const tag = "1.0"

		var manifest string
		var config string
		var layer string

		// create layer digest
		body := []byte("this is a blob")
		buf := bytes.NewBuffer(body)
		l := buf.Len()
		d := godigest.FromBytes(body)
		u, n, err := il.FullBlobUpload(repoName, buf, d.String())
		So(err, ShouldBeNil)
		So(n, ShouldEqual, len(body))
		So(u, ShouldNotBeEmpty)
		layer = d.String()

		//create config digest
		created := time.Now().Format("2006-01-02T15:04:05Z")
		configBody := []byte(fmt.Sprintf(`{
				"created":      "%v",
				"architecture": "amd64",
				"os":           "linux",
				"rootfs": {
					"type": "layers",
					"diff_ids": [
						"",
						""
					]
				},
				"history": [
					{
					  "created": "%v",
					  "created_by": ""
					},
					{
						"created": "%v",
						"created_by": "",
						"empty_layer": true
					}
				]
			}`, created, created, created))
		configBuf := bytes.NewBuffer(configBody)
		configLen := configBuf.Len()
		configDigest := godigest.FromBytes(configBody)
		uConfig, nConfig, err := il.FullBlobUpload(repoName, configBuf, configDigest.String())
		So(err, ShouldBeNil)
		So(nConfig, ShouldEqual, len(configBody))
		So(uConfig, ShouldNotBeEmpty)
		config = configDigest.String()

		// create manifest and add it to the repository
		annotationsMap := make(map[string]string)
		annotationsMap[ispec.AnnotationRefName] = tag
		m := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(configLen),
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

		manifest, err = il.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, mb)
		So(err, ShouldBeNil)

		Convey("Blobs integrity not affected", func() {
			buff := bytes.NewBufferString("")

			res, err := sc.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
		})

		Convey("Manifest integrity affected", func() {
			// get content of manifest file
			content, _, _, err := il.GetImageManifest(repoName, manifest)
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifest = strings.ReplaceAll(manifest, "sha256:", "")
			manifestFile := path.Join(il.RootDir(), repoName, "/blobs/sha256", manifest)
			err = os.Truncate(manifestFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := sc.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, "test 1.0 affected parse application/vnd.oci.image.manifest.v1+json")

			// put manifest content back to file
			err = ioutil.WriteFile(manifestFile, content, 0600)
			So(err, ShouldBeNil)
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := il.GetBlobContent(repoName, config)
			So(err, ShouldBeNil)

			// delete content of config file
			config = strings.ReplaceAll(config, "sha256:", "")
			configFile := path.Join(il.RootDir(), repoName, "/blobs/sha256", config)
			err = os.Truncate(configFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := sc.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected stat: parse application/vnd.oci.image.config.v1+json")

			// put config content back to file
			err = ioutil.WriteFile(configFile, content, 0600)
			So(err, ShouldBeNil)
		})

		Convey("Layers integrity affected", func() {
			// get content of layer
			content, err := il.GetBlobContent(repoName, layer)
			So(err, ShouldBeNil)

			// delete content of layer file
			layer = strings.ReplaceAll(layer, "sha256:", "")
			layerFile := path.Join(il.RootDir(), repoName, "/blobs/sha256", layer)
			err = os.Truncate(layerFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := sc.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected blob: bad blob digest")

			// put layer content back to file
			err = ioutil.WriteFile(layerFile, content, 0600)
			So(err, ShouldBeNil)
		})

		Convey("Layer not found", func() {
			// delete layer file
			layer = strings.ReplaceAll(layer, "sha256:", "")
			layerFile := path.Join(il.RootDir(), repoName, "/blobs/sha256", layer)
			err = os.Remove(layerFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := sc.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected blob: not found")
		})
	})
}
