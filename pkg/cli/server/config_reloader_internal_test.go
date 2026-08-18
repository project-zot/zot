package server //nolint:testpackage // white-box tests for unexported signalHandler and watcher close

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestHotReloaderStop(t *testing.T) {
	Convey("Stop is safe with nil done and watcher", t, func() {
		reloader := &HotReloader{}
		So(func() { reloader.Stop() }, ShouldNotPanic)
		So(func() { reloader.Stop() }, ShouldNotPanic)
	})

	Convey("SIGTERM stops the reloader and shuts down the controller", t, func() {
		reloader := newTestHotReloader(t)
		reloader.Start()
		So(waitForWatch(reloader, 2*time.Second), ShouldBeTrue)

		sigCh := make(chan os.Signal, 1)
		finished := make(chan struct{})

		go func() {
			signalHandler(reloader.ctlr, reloader, sigCh)
			close(finished)
		}()

		sigCh <- syscall.SIGTERM
		So(waitChan(finished, 2*time.Second), ShouldBeTrue)
		So(isClosed(reloader.done), ShouldBeTrue)
	})

	Convey("closed signal channel returns without stopping the reloader", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		sigCh := make(chan os.Signal)
		finished := make(chan struct{})

		go func() {
			signalHandler(reloader.ctlr, reloader, sigCh)
			close(finished)
		}()

		close(sigCh)
		So(waitChan(finished, 2*time.Second), ShouldBeTrue)
		So(isClosed(reloader.done), ShouldBeFalse)
	})

	Convey("closed watcher events channel exits the watch loop", t, func() {
		reloader := newTestHotReloader(t)
		// Block the Errors case so select must take Events once the watcher is closed.
		reloader.watcher.Errors = nil
		startReloaderAndCloseWatcher(t, reloader)
	})

	Convey("closed watcher errors channel exits the watch loop", t, func() {
		reloader := newTestHotReloader(t)
		// Block the Events case so select must take Errors once the watcher is closed.
		reloader.watcher.Events = nil
		startReloaderAndCloseWatcher(t, reloader)
	})
}

func testServerConfig(t *testing.T) *config.Config {
	t.Helper()

	conf := config.New()
	conf.HTTP.Address = "127.0.0.1"
	conf.HTTP.Port = "0"
	conf.Storage.RootDirectory = t.TempDir()

	return conf
}

func newTestHotReloader(t *testing.T) *HotReloader {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "zot.json")
	err := os.WriteFile(configPath, []byte(`{}`), 0o600)
	So(err, ShouldBeNil)

	reloader, err := NewHotReloader(api.NewController(testServerConfig(t)), configPath, "")
	So(err, ShouldBeNil)

	return reloader
}

func startReloaderAndCloseWatcher(t *testing.T, reloader *HotReloader) {
	t.Helper()

	reloader.Start()
	So(waitForWatch(reloader, 2*time.Second), ShouldBeTrue)

	err := reloader.watcher.Close()
	So(err, ShouldBeNil)

	// Let the watch loop observe the closed channel before Stop() also unblocks <-done.
	time.Sleep(100 * time.Millisecond)
	reloader.Stop()
}

func waitForWatch(reloader *HotReloader, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if len(reloader.watcher.WatchList()) > 0 {
			return true
		}

		time.Sleep(10 * time.Millisecond)
	}

	return false
}

func waitChan(done <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func isClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
