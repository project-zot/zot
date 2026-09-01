package server //nolint:testpackage // white-box tests for unexported signalHandler and watcher close

import (
	"errors"
	"fmt"
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

	reloader := NewHotReloader(api.NewController(testServerConfig(t)), configPath, "")

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

// TestCancelPendingReload covers the case where a poll tick lands inside the
// debounce window opened by a write: the poll reloads immediately, and the
// timer left armed would reload the same change a second time, restarting
// every background task again.
func TestCancelPendingReload(t *testing.T) {
	Convey("cancelling drops a debounce that has not fired", t, func() {
		reloader := &HotReloader{}

		reloader.scheduleReload()
		So(reloader.getDebounceChannel(), ShouldNotBeNil)

		reloader.cancelPendingReload()
		So(reloader.getDebounceChannel(), ShouldBeNil)
	})

	Convey("cancelling a debounce that already fired still retires it", t, func() {
		reloader := &HotReloader{}

		reloader.scheduleReload()

		// let it fire, so a tick is already prepared
		time.Sleep(configEventDebounceInterval * 2)

		reloader.cancelPendingReload()

		// the loop must not be able to select that tick afterwards
		So(reloader.getDebounceChannel(), ShouldBeNil)
	})

	Convey("scheduling again while armed extends the same timer", t, func() {
		reloader := &HotReloader{}

		reloader.scheduleReload()
		first := reloader.getDebounceChannel()
		So(first, ShouldNotBeNil)

		reloader.scheduleReload()

		// a burst of writes coalesces into one reload rather than one each
		So(reloader.getDebounceChannel(), ShouldEqual, first)
	})

	Convey("cancelling with nothing scheduled is a no-op", t, func() {
		reloader := &HotReloader{}

		So(func() { reloader.cancelPendingReload() }, ShouldNotPanic)
		So(reloader.getDebounceChannel(), ShouldBeNil)
	})

	Convey("a poll-driven reload drops the debounce armed for the same change", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		// baseline as Start does, so only a later change reads as one
		reloader.configInfo = statOrNil(reloader.configPath)

		// a write arrived and armed the debounce
		reloader.scheduleReload()
		So(reloader.getDebounceChannel(), ShouldNotBeNil)

		// the poll then sees that same change first. What it reloads does not
		// matter here: cancelling happens before the reload is attempted, and a
		// config that fails to load keeps this off the controller's background
		// tasks, which this controller never started.
		So(os.WriteFile(reloader.configPath, []byte("not json"), 0o600), ShouldBeNil)

		reloader.pollForChanges()

		// left armed it fires straight after, reloading the same edit twice
		So(reloader.getDebounceChannel(), ShouldBeNil)
	})
}

func TestFileChanged(t *testing.T) {
	Convey("an unset path never counts as changed", t, func() {
		So(fileChanged("", nil), ShouldBeFalse)
	})

	Convey("a path that cannot be stat'd is left for the next tick", t, func() {
		// transient while a replacement is in flight, so not a change yet
		So(fileChanged(filepath.Join(t.TempDir(), "absent.json"), nil), ShouldBeFalse)
	})

	Convey("a file with no baseline counts as changed", t, func() {
		path := filepath.Join(t.TempDir(), "zot.json")
		So(os.WriteFile(path, []byte(`{}`), 0o600), ShouldBeNil)

		So(fileChanged(path, nil), ShouldBeTrue)
	})

	Convey("a rewrite of the same file counts as changed", t, func() {
		path := filepath.Join(t.TempDir(), "zot.json")
		So(os.WriteFile(path, []byte(`{}`), 0o600), ShouldBeNil)

		before := statOrNil(path)
		So(before, ShouldNotBeNil)
		So(fileChanged(path, before), ShouldBeFalse)

		// a different size is enough, even inside one timestamp granule
		So(os.WriteFile(path, []byte(`{"a":1}`), 0o600), ShouldBeNil)
		So(fileChanged(path, before), ShouldBeTrue)
	})

	Convey("a replacement by rename counts as changed", t, func() {
		dir := t.TempDir()
		path := filepath.Join(dir, "zot.json")
		So(os.WriteFile(path, []byte(`{}`), 0o600), ShouldBeNil)

		before := statOrNil(path)
		So(before, ShouldNotBeNil)

		// same content and size, different inode: only identity catches this
		replacement := filepath.Join(dir, "zot.json.new")
		So(os.WriteFile(replacement, []byte(`{}`), 0o600), ShouldBeNil)
		So(os.Rename(replacement, path), ShouldBeNil)

		So(fileChanged(path, before), ShouldBeTrue)
	})
}

func TestStatOrNil(t *testing.T) {
	Convey("an unset path has no fingerprint", t, func() {
		So(statOrNil(""), ShouldBeNil)
	})

	Convey("a missing file has no fingerprint", t, func() {
		So(statOrNil(filepath.Join(t.TempDir(), "absent.json")), ShouldBeNil)
	})
}

func TestSamePath(t *testing.T) {
	Convey("an empty name or target never matches", t, func() {
		So(samePath("", "/etc/zot/config.json"), ShouldBeFalse)
		So(samePath("/etc/zot/config.json", ""), ShouldBeFalse)
	})

	Convey("paths match after cleaning", t, func() {
		So(samePath("/etc/zot/../zot/config.json", "/etc/zot/config.json"), ShouldBeTrue)
		So(samePath("/etc/zot/other.json", "/etc/zot/config.json"), ShouldBeFalse)
	})
}

// TestWatchFailuresFallBackToPolling covers the paths taken when inotify cannot
// be established or is lost: none of them may stop the reloader, because the
// stat poll still carries reloads on its own.
func TestWatchFailuresFallBackToPolling(t *testing.T) {
	Convey("files that are not there yet still start the reloader", t, func() {
		dir := t.TempDir()

		reloader := NewHotReloader(api.NewController(testServerConfig(t)),
			filepath.Join(dir, "absent.json"), filepath.Join(dir, "absent-creds.json"))
		t.Cleanup(reloader.Stop)

		// both watcher.Add calls fail, and Start has to carry on regardless
		So(func() { reloader.Start() }, ShouldNotPanic)
	})

	Convey("re-adding watches for files that are gone is tolerated", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		reloader.ldapCredentialsPath = filepath.Join(t.TempDir(), "absent-creds.json")
		So(os.Remove(reloader.configPath), ShouldBeNil)

		So(func() { reloader.readdWatches() }, ShouldNotPanic)
	})

	Convey("a watcher error is logged without stopping the loop", t, func() {
		reloader := newTestHotReloader(t)

		watcherErrors := make(chan error, 1)
		reloader.watcher.Errors = watcherErrors
		// block the Events case so the select has to take the error
		reloader.watcher.Events = nil

		reloader.Start()

		watcherErrors <- errors.New("inotify queue overflow")

		// dropped events are the poll's problem, so the loop keeps running
		time.Sleep(200 * time.Millisecond)
		So(isClosed(reloader.done), ShouldBeFalse)

		reloader.Stop()
		So(isClosed(reloader.done), ShouldBeTrue)
	})
}

// TestPollingOnlyMode covers the reloader running with no fsnotify watcher at
// all, which is what a host out of inotify instances looks like: reloads must
// still happen, just at poll latency.
func TestPollingOnlyMode(t *testing.T) {
	Convey("a reloader with no watcher still starts and stops", t, func() {
		reloader := newTestHotReloader(t)

		// stand in for fsnotify.NewWatcher having failed
		So(reloader.watcher.Close(), ShouldBeNil)
		reloader.watcher = nil

		So(func() { reloader.Start() }, ShouldNotPanic)
		So(func() { reloader.readdWatches() }, ShouldNotPanic)
		So(func() { reloader.Stop() }, ShouldNotPanic)
	})

	Convey("a poll still reloads with no watcher present", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		So(reloader.watcher.Close(), ShouldBeNil)
		reloader.watcher = nil

		// a change the watch could never have reported
		So(os.WriteFile(reloader.configPath, []byte("not json"), 0o600), ShouldBeNil)
		So(reloader.checkFilesChanged(), ShouldBeTrue)

		So(func() { reloader.pollForChanges() }, ShouldNotPanic)

		// the poll consumed the change, so it is not seen twice
		So(reloader.checkFilesChanged(), ShouldBeFalse)
	})
}

// TestBaselineTakenAtConstruction covers a config replaced while the controller
// was still initialising: the fingerprint has to describe what was loaded, not
// what happens to be on disk once Start finally runs.
func TestBaselineTakenAtConstruction(t *testing.T) {
	Convey("a change landing before Start is still seen as a change", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		// the file moves on while Controller.Init is still running
		So(os.WriteFile(reloader.configPath, []byte(`{"a":1}`), 0o600), ShouldBeNil)

		reloader.Start()

		// Start must not adopt the new file as the baseline: the running config
		// was built from the old one and still needs reloading
		So(reloader.checkFilesChanged(), ShouldBeTrue)
	})
}

func TestFailedLoadKeepsWatchingLiveCredentials(t *testing.T) {
	Convey("a load that failed for an unrelated reason keeps the live credentials file", t, func() {
		dir := t.TempDir()
		credsPath := filepath.Join(dir, "ldap-creds.json")
		So(os.WriteFile(credsPath, []byte(`{"bindDN":"cn=ro","bindPassword":"pass"}`), 0o600), ShouldBeNil)

		configPath := filepath.Join(dir, "zot.json")
		So(os.WriteFile(configPath, []byte(`{}`), 0o600), ShouldBeNil)

		reloader := NewHotReloader(api.NewController(testServerConfig(t)), configPath, credsPath)
		t.Cleanup(reloader.Stop)

		// a syntax error that has nothing to do with ldap
		So(os.WriteFile(configPath, []byte("{ this is not json"), 0o600), ShouldBeNil)

		reloader.reloadConfig("test")

		// the running config still authenticates against this file, so dropping
		// it would stop noticing rotations there
		So(reloader.ldapCredentialsPath, ShouldEqual, credsPath)

		So(os.WriteFile(credsPath, []byte(`{"bindDN":"cn=rw","bindPassword":"new"}`), 0o600), ShouldBeNil)
		So(reloader.checkFilesChanged(), ShouldBeTrue)
	})
}

func TestFailedLoadFollowsPendingCredentials(t *testing.T) {
	Convey("a load that failed on its credentials file follows that file", t, func() {
		reloader := newTestHotReloader(t)
		t.Cleanup(reloader.Stop)

		credsPath := filepath.Join(t.TempDir(), "ldap-creds.json")

		conf := fmt.Sprintf(`{
			"distSpecVersion": "1.1.1",
			"storage": {"rootDirectory": %q},
			"http": {
				"address": "127.0.0.1", "port": "0",
				"auth": {"ldap": {
					"credentialsFile": %q,
					"address": "127.0.0.1", "port": 389,
					"baseDN": "ou=users,dc=example,dc=org", "userAttribute": "uid"
				}}
			}
		}`, t.TempDir(), credsPath)

		So(os.WriteFile(reloader.configPath, []byte(conf), 0o600), ShouldBeNil)

		// the credentials file is not there yet, so the load fails after having
		// decoded where it should be
		reloader.reloadConfig("test")

		So(reloader.pendingLdapPath, ShouldEqual, credsPath)
		So(reloader.checkFilesChanged(), ShouldBeFalse)

		// creating it has to read as a change, or the config is never retried
		So(os.WriteFile(credsPath, []byte(`{"bindDN":"cn=ro","bindPassword":"pass"}`), 0o600), ShouldBeNil)
		So(reloader.checkFilesChanged(), ShouldBeTrue)
	})
}

func TestWarnsOnRotatedNonReloadableSecret(t *testing.T) {
	Convey("a rotated storage secret is reported without being logged", t, func() {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "zot.log")

		conf := testServerConfig(t)
		conf.Log = &config.LogConfig{Level: "debug", Output: logPath}
		conf.Storage.StorageDriver = map[string]any{"name": "s3", "secretkey": "old-secret-value"}

		configPath := filepath.Join(dir, "zot.json")
		So(os.WriteFile(configPath, []byte(`{}`), 0o600), ShouldBeNil)

		reloader := NewHotReloader(api.NewController(conf), configPath, "")
		t.Cleanup(reloader.Stop)

		// the storage driver is outside the reloadable set, so rotating its
		// secret needs a restart
		newConfig := config.New()
		newConfig.Storage.RootDirectory = conf.Storage.RootDirectory
		newConfig.Storage.StorageDriver = map[string]any{"name": "s3", "secretkey": "new-secret-value"}

		reloader.warnNonReloadableChanges(newConfig)

		logs, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)

		So(string(logs), ShouldContainSubstring, "need a restart")
		So(string(logs), ShouldContainSubstring, "secretkey")

		// the path is enough: the value itself must never reach the log
		So(string(logs), ShouldNotContainSubstring, "new-secret-value")
		So(string(logs), ShouldNotContainSubstring, "old-secret-value")
	})
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
