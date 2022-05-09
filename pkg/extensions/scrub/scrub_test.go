//go:build extended
// +build extended

package scrub_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/extensions/scrub"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	repoName = "test"
)

func TestScrubExtension(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Log.Output = logFile.Name()
		scrubConfig := &extconf.ScrubConfig{
			Interval: 2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}

		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)

		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(1 * time.Second)

		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest ok")
	})

	Convey("Blobs integrity affected", t, func(c C) {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Log.Output = logFile.Name()
		scrubConfig := &extconf.ScrubConfig{
			Interval: 2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}
		var manifestDigest digest.Digest
		manifestDigest, _, _ = test.GetOciLayoutDigests("../../../test/data/zot-test")

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)

		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)

		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest affected")
	})

	Convey("RunBackgroundTasks error - not enough permissions to access root directory", t, func(c C) {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		conf.Storage.RootDirectory = dir
		conf.Log.Output = logFile.Name()
		scrubConfig := &extconf.ScrubConfig{
			Interval: 2,
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Scrub: scrubConfig,
		}

		ctlr := api.NewController(conf)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)

		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)

		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("error while running background task for %s", ctlr.StoreController.DefaultStore.RootDir()))

		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}

func TestRunScrubRepo(t *testing.T) {
	Convey("Blobs integrity not affected", t, func(c C) {
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, 1*time.Second, true, true, log, metrics)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}

		scrub.RunScrubRepo(imgStore, repoName, log)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest ok")
	})

	Convey("Blobs integrity affected", t, func(c C) {
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, 1*time.Second, true, true, log, metrics)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}
		var manifestDigest digest.Digest
		manifestDigest, _, _ = test.GetOciLayoutDigests("../../../test/data/zot-test")

		err = os.Remove(path.Join(dir, repoName, "blobs/sha256", manifestDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		scrub.RunScrubRepo(imgStore, repoName, log)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "scrub: blobs/manifest affected")
	})

	Convey("CheckRepo error - not enough permissions to access root directory", t, func(c C) {
		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		dir := t.TempDir()
		log := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := storage.NewImageStore(dir, true, 1*time.Second, true, true, log, metrics)

		err = test.CopyFiles("../../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}

		So(os.Chmod(path.Join(dir, repoName), 0o000), ShouldBeNil)

		scrub.RunScrubRepo(imgStore, repoName, log)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("error while running scrub for %s", imgStore.RootDir()))
		So(os.Chmod(path.Join(dir, repoName), 0o755), ShouldBeNil)
	})
}
