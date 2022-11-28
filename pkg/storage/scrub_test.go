package storage_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

const (
	repoName = "test"
	tag      = "1.0"
)

func TestCheckAllBlobsIntegrity(t *testing.T) {
	dir := t.TempDir()

	log := log.NewLogger("debug", "")

	metrics := monitoring.NewMetricsServer(false, log)
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)
	imgStore := local.NewImageStore(dir, true, storage.DefaultGCDelay,
		true, true, log, metrics, nil, cacheDriver)

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

		config, layers, manifest, err := test.GetImageComponents(1000)
		So(err, ShouldBeNil)

		layerReader := bytes.NewReader(layers[0])
		layerDigest := godigest.FromBytes(layers[0])
		_, _, err = imgStore.FullBlobUpload(repoName, layerReader, layerDigest)
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)
		configReader := bytes.NewReader(configBlob)
		configDigest := godigest.FromBytes(configBlob)
		_, _, err = imgStore.FullBlobUpload(repoName, configReader, configDigest)
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		manifestDigest, err := imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBlob)
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
			content, _, _, err := imgStore.GetImageManifest(repoName, manifestDigest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := manifestDigest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
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

			index, err := storage.GetIndex(imgStore, repoName, log.With().Caller().Logger())
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			repoDir := path.Join(dir, repoName)
			imageRes := storage.CheckLayers(repoName, tag, repoDir, manifestDescriptor)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "unexpected end of JSON input")

			// put manifest content back to file
			err = os.WriteFile(manifestFile, content, 0o600)
			So(err, ShouldBeNil)
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := imgStore.GetBlobContent(repoName, configDigest)
			So(err, ShouldBeNil)

			// delete content of config file
			configDig := configDigest.Encoded()
			configFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", configDig)
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
			content, err := imgStore.GetBlobContent(repoName, layerDigest)
			So(err, ShouldBeNil)

			// delete content of layer file
			layerDig := layerDigest.Encoded()
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layerDig)
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
			// change layer file permissions
			layerDig := layerDigest.Encoded()
			repoDir := path.Join(dir, repoName)
			layerFile := path.Join(repoDir, "/blobs/sha256", layerDig)
			err = os.Chmod(layerFile, 0x0200)
			So(err, ShouldBeNil)

			index, err := storage.GetIndex(imgStore, repoName, log.With().Caller().Logger())
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			imageRes := storage.CheckLayers(repoName, tag, repoDir, manifestDescriptor)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "blob: not found")
			err = os.Chmod(layerFile, 0x0600)
			So(err, ShouldBeNil)

			// delete layer file
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

		Convey("Scrub index", func() {
			newConfig, newLayers, newManifest, err := test.GetImageComponents(10)
			So(err, ShouldBeNil)

			newLayerReader := bytes.NewReader(newLayers[0])
			newLayerDigest := godigest.FromBytes(newLayers[0])
			_, _, err = imgStore.FullBlobUpload(repoName, newLayerReader, newLayerDigest)
			So(err, ShouldBeNil)

			newConfigBlob, err := json.Marshal(newConfig)
			So(err, ShouldBeNil)
			newConfigReader := bytes.NewReader(newConfigBlob)
			newConfigDigest := godigest.FromBytes(newConfigBlob)
			_, _, err = imgStore.FullBlobUpload(repoName, newConfigReader, newConfigDigest)
			So(err, ShouldBeNil)

			newManifestBlob, err := json.Marshal(newManifest)
			So(err, ShouldBeNil)
			newManifestReader := bytes.NewReader(newManifestBlob)
			newManifestDigest := godigest.FromBytes(newManifestBlob)
			_, _, err = imgStore.FullBlobUpload(repoName, newManifestReader, newManifestDigest)
			So(err, ShouldBeNil)

			var index ispec.Index
			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    newManifestDigest,
					Size:      int64(len(newManifestBlob)),
				},
			}

			indexBlob, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest, err := imgStore.PutImageManifest(repoName, "", ispec.MediaTypeImageIndex, indexBlob)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test ok")

			// test scrub index - errors
			indexFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", indexDigest.Encoded())
			err = os.Chmod(indexFile, 0o000)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			err = os.Chmod(indexFile, 0o600)
			So(err, ShouldBeNil)

			err = os.Truncate(indexFile, 0)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test affected")
		})

		Convey("Manifest not found", func() {
			// delete manifest file
			manifestDig := manifestDigest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = os.Remove(manifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity()
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG STATUS ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 affected")
			So(actual, ShouldContainSubstring, "no such file or directory")

			index, err := storage.GetIndex(imgStore, repoName, log.With().Caller().Logger())
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 2)
			manifestDescriptor := index.Manifests[0]

			repoDir := path.Join(dir, repoName)
			imageRes := storage.CheckLayers(repoName, tag, repoDir, manifestDescriptor)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldContainSubstring, "no such file or directory")
		})
	})
}
