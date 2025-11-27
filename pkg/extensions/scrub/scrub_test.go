//go:build scrub

package scrub_test

import (
	"context"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/extensions/scrub"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
)

const (
	repoName = "test"
)

func TestScrubExtension(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		port := test.GetFreePort()

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		subdir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		substore := config.StorageConfig{RootDirectory: subdir}
		conf.Storage.SubPaths = map[string]config.StorageConfig{"/a": substore}
		conf.Log.Output = logPath
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		err := WriteImageToFileSystem(CreateDefaultVulnerableImage(), repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		found, err := test.ReadLogFileAndSearchString(logPath, "blobs/manifest ok", 60*time.Second)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})

	Convey("Blobs integrity affected", t, func(c C) {
		port := test.GetFreePort()

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		conf.Log.Output = logPath
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		image := CreateDefaultVulnerableImage()
		err := WriteImageToFileSystem(image, repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		layerDigest := image.Manifest.Layers[0].Digest

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", layerDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		found, err := test.ReadLogFileAndSearchString(logPath, "blobs/manifest affected", 60*time.Second)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})

	Convey("Generator error - not enough permissions to access root directory", t, func(c C) {
		port := test.GetFreePort()

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		conf.Log.Output = logPath
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log.NewTestLogger())
		image := CreateDefaultVulnerableImage()

		err := WriteImageToFileSystem(image, repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		found, err := test.ReadLogFileAndSearchString(logPath, "failed to execute generator", 60*time.Second)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}

func TestRunScrubRepo(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logPath)
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true,
			true, log, metrics, nil, cacheDriver, nil, nil)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log)
		image := CreateDefaultVulnerableImage()

		err := WriteImageToFileSystem(image, repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		err = scrub.RunScrubRepo(context.Background(), imgStore, repoName, log)
		So(err, ShouldBeNil)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "blobs/manifest ok")
	})

	Convey("Blobs integrity affected", t, func(c C) {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logPath)
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true,
			true, log, metrics, nil, cacheDriver, nil, nil)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log)
		image := CreateDefaultVulnerableImage()

		err := WriteImageToFileSystem(image, repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		layerDigest := image.Manifest.Layers[0].Digest

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", layerDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		err = scrub.RunScrubRepo(context.Background(), imgStore, repoName, log)
		So(err, ShouldBeNil)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "blobs/manifest affected")
	})

	Convey("CheckRepo error - not enough permissions to access root directory", t, func(c C) {
		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logPath)
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log)
		image := CreateDefaultVulnerableImage()

		err := WriteImageToFileSystem(image, repoName, "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		err = scrub.RunScrubRepo(context.Background(), imgStore, repoName, log)
		So(err, ShouldNotBeNil)

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"failed to run scrub for "+imgStore.RootDir())
		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}
