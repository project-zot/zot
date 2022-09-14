package storage_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"zotregistry.io/zot/pkg/storage/local"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
)

const (
	repoName = "test"
)

func TestCheckAllBlobsIntegrity(t *testing.T) {
	dir := t.TempDir()

	log := log.NewLogger("debug", "")

	metrics := monitoring.NewMetricsServer(false, log)

	imgStore := local.NewImageStore(dir, true, storConstants.DefaultGCDelay,
		true, true, log, metrics, nil)

	Convey("Scrub only one repo", t, func(c C) {
		// initialize repo
		err := imgStore.InitRepo(repoName)
		So(err, ShouldBeNil)
		ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
		So(ok, ShouldBeTrue)
		storeController := storage.StoreController{}
		storeController.DefaultStore = imgStore
		So(storeController.GetImageStore(repoName), ShouldResemble, imgStore)

		storeCtlr := storage.StoreController{}
		storeCtlr.DefaultStore = imgStore

		const tag = "1.0"

		var manifest string
		var config string
		var layer string

		// create layer digest
		body := []byte("this is a blob")
		buf := bytes.NewBuffer(body)
		buflen := buf.Len()
		digest := godigest.FromBytes(body)
		upload, n, err := imgStore.FullBlobUpload(repoName, buf, digest.String())
		So(err, ShouldBeNil)
		So(n, ShouldEqual, len(body))
		So(upload, ShouldNotBeEmpty)
		layer = digest.String()

		// create config digest
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
		uConfig, nConfig, err := imgStore.FullBlobUpload(repoName, configBuf, configDigest.String())
		So(err, ShouldBeNil)
		So(nConfig, ShouldEqual, len(configBody))
		So(uConfig, ShouldNotBeEmpty)
		config = configDigest.String()

		// create manifest and add it to the repository
		annotationsMap := make(map[string]string)
		annotationsMap[ispec.AnnotationRefName] = tag
		mnfst := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(configLen),
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

		mnfst.SchemaVersion = 2
		mbytes, err := json.Marshal(mnfst)
		So(err, ShouldBeNil)

		manifest, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest,
			mbytes)
		So(err, ShouldBeNil)

		Convey("Blobs integrity not affected", func() {
			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
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
			content, _, _, err := imgStore.GetImageManifest(repoName, manifest)
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifest = strings.ReplaceAll(manifest, "sha256:", "")
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifest)
			err = os.Truncate(manifestFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, "test 1.0 affected parse application/vnd.oci.image.manifest.v1+json")

			// put manifest content back to file
			err = os.WriteFile(manifestFile, content, 0o600)
			So(err, ShouldBeNil)
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := imgStore.GetBlobContent(repoName, config)
			So(err, ShouldBeNil)

			// delete content of config file
			config = strings.ReplaceAll(config, "sha256:", "")
			configFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", config)
			err = os.Truncate(configFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected stat: parse application/vnd.oci.image.config.v1+json")

			// put config content back to file
			err = os.WriteFile(configFile, content, 0o600)
			So(err, ShouldBeNil)
		})

		Convey("Layers integrity affected", func() {
			// get content of layer
			content, err := imgStore.GetBlobContent(repoName, layer)
			So(err, ShouldBeNil)

			// delete content of layer file
			layer = strings.ReplaceAll(layer, "sha256:", "")
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layer)
			err = os.Truncate(layerFile, 0)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected blob: bad blob digest")

			// put layer content back to file
			err = os.WriteFile(layerFile, content, 0o600)
			So(err, ShouldBeNil)
		})

		Convey("Layer not found", func() {
			// delete layer file
			layer = strings.ReplaceAll(layer, "sha256:", "")
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layer)
			err = os.Remove(layerFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
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
