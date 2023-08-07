//go:build scrub
// +build scrub

package scrub_test

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/scrub"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

const (
	repoName = "test"
)

func TestScrubExtension(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		port := test.GetFreePort()

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		subdir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		substore := config.StorageConfig{RootDirectory: subdir}
		conf.Storage.SubPaths = map[string]config.StorageConfig{"/a": substore}
		conf.Log.Output = logFile.Name()
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		time.Sleep(6 * time.Second)

		defer cm.StopServer()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest ok")
	})

	Convey("Blobs integrity affected", t, func(c C) {
		port := test.GetFreePort()

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		conf.Log.Output = logFile.Name()
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		var manifestDigest godigest.Digest
		manifestDigest, _, _ = test.GetOciLayoutDigests("../../../test/data/zot-test")

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		time.Sleep(6 * time.Second)

		defer cm.StopServer()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest affected")
	})

	Convey("Generator error - not enough permissions to access root directory", t, func(c C) {
		port := test.GetFreePort()

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = false
		conf.Storage.GC = false

		conf.Log.Output = logFile.Name()
		trueValue := true
		scrubConfig := &extconf.ScrubConfig{
			BaseConfig: extconf.BaseConfig{Enable: &trueValue},
			Interval:   2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		time.Sleep(6 * time.Second)

		defer cm.StopServer()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "error while executing generator")

		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}

func TestRunScrubRepo(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, 1*time.Second, true,
			true, log, metrics, nil, cacheDriver)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))

		err = scrub.RunScrubRepo(imgStore, repoName, log)
		So(err, ShouldBeNil)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest ok")
	})

	Convey("Blobs integrity affected", t, func(c C) {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, 1*time.Second, true,
			true, log, metrics, nil, cacheDriver)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		var manifestDigest godigest.Digest
		manifestDigest, _, _ = test.GetOciLayoutDigests("../../../test/data/zot-test")

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		err = scrub.RunScrubRepo(imgStore, repoName, log)
		So(err, ShouldBeNil)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest affected")
	})

	Convey("CheckRepo error - not enough permissions to access root directory", t, func(c C) {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Lint = &extconf.LintConfig{}

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, 1*time.Second,
			true, true, log, metrics, nil, cacheDriver,
		)

		test.CopyTestFiles("../../../test/data/zot-test", path.Join(dir, repoName))

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		err = scrub.RunScrubRepo(imgStore, repoName, log)
		So(err, ShouldNotBeNil)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("error while running scrub for %s", imgStore.RootDir()))
		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}
