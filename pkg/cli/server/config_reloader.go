package server

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

const (
	// configEventDebounceInterval coalesces bursts of fsnotify events into one reload.
	configEventDebounceInterval = 150 * time.Millisecond
	// configStatCheckInterval is the polling interval used as a backstop when
	// inotify watching is unavailable or events were dropped.
	configStatCheckInterval = 1 * time.Second
)

// HotReloader reloads the server configuration when the config file (or the
// LDAP credentials file it references) changes. The file watch gives
// low-latency reloads; the stat fingerprint poll is the guarantee, catching
// changes the watch cannot see (Kubernetes ConfigMap/Secret symlink swaps).
type HotReloader struct {
	watcher             *fsnotify.Watcher
	configPath          string
	ldapCredentialsPath string
	ctlr                *api.Controller

	// the fields below belong to the watcher loop once Start has launched it,
	// and are only touched from there.
	debounceTimer *time.Timer
	// stat fingerprints at the last successful reload; polling compares
	// identity, size and mtime against them.
	configInfo os.FileInfo
	ldapInfo   os.FileInfo
	// a credentials path a failed load decoded, fingerprinted so its arrival
	// retries the config. The live path keeps its own watch: a config that
	// failed for an unrelated reason must not stop tracking the file the
	// running config still authenticates against.
	pendingLdapPath string
	pendingLdapInfo os.FileInfo

	done chan struct{}
	// mu guards stopped, which Start writes and Stop reads
	mu sync.Mutex
	// closed by the watcher loop on exit, so Stop can wait out an in-flight reload
	stopped  chan struct{}
	stopOnce sync.Once
}

func NewHotReloader(ctlr *api.Controller, filePath, ldapCredentialsPath string) *HotReloader {
	// carry on without a watcher rather than refusing to start: the fingerprint
	// poll drives reloads on its own, so inotify being unavailable degrades the
	// latency of a reload, not whether one happens
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		ctlr.Log.Error().Err(err).Msg("failed to create fsnotify watcher, relying on stat-based polling")

		watcher = nil
	}

	hotReloader := &HotReloader{
		watcher:             watcher,
		configPath:          filePath,
		ldapCredentialsPath: ldapCredentialsPath,
		ctlr:                ctlr,
		done:                make(chan struct{}),
	}

	// fingerprint the files as they were loaded, not as they are once the
	// controller has finished initialising: a replacement landing in between
	// would otherwise be baselined as already applied and never reload
	hotReloader.configInfo = statOrNil(filePath)
	hotReloader.ldapInfo = statOrNil(ldapCredentialsPath)

	return hotReloader
}

func signalHandler(ctlr *api.Controller, hr *HotReloader, sigCh chan os.Signal) {
	// if signal then shutdown
	if sig, ok := <-sigCh; ok {
		ctlr.Log.Info().Interface("signal", sig).Msg("received signal")

		hr.Stop()
		// gracefully shutdown http server
		ctlr.Shutdown() //nolint: contextcheck
	}
}

func initShutDownRoutine(ctlr *api.Controller, hr *HotReloader) {
	sigCh := make(chan os.Signal, 1)

	go signalHandler(ctlr, hr, sigCh)

	// block all async signals to this server
	signal.Ignore()

	// handle SIGINT and SIGHUP.
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func (hr *HotReloader) Stop() {
	hr.stopOnce.Do(func() {
		if hr.done != nil {
			close(hr.done)
		}
		if hr.watcher != nil {
			_ = hr.watcher.Close()
		}

		hr.mu.Lock()
		stopped := hr.stopped
		hr.mu.Unlock()

		// wait for the loop and any in-flight reload; nil if Start never ran
		if stopped != nil {
			<-stopped
		}
	})
}

func (hr *HotReloader) Start() {
	// watch failures are tolerated: the fingerprint poll is the backstop
	if hr.watcher != nil {
		if err := hr.watcher.Add(hr.configPath); err != nil {
			hr.ctlr.Log.Error().Err(err).Str("config", hr.configPath).
				Msg("failed to add config file to fsnotify watcher, relying on stat-based polling")
		}

		if hr.ldapCredentialsPath != "" {
			if err := hr.watcher.Add(hr.ldapCredentialsPath); err != nil {
				hr.ctlr.Log.Error().Err(err).Str("ldap-credentials", hr.ldapCredentialsPath).
					Msg("failed to add ldap-credentials to fsnotify watcher, relying on stat-based polling")
			}
		}
	}

	hr.mu.Lock()
	hr.stopped = make(chan struct{})
	stopped := hr.stopped
	hr.mu.Unlock()

	go hr.loop(stopped)
}

func (hr *HotReloader) loop(stopped chan struct{}) {
	defer close(stopped)

	// nil channels block forever in a select, which is what leaves the loop
	// polling-only when there is no watcher
	var eventsCh chan fsnotify.Event

	var errorsCh chan error

	if hr.watcher != nil {
		eventsCh = hr.watcher.Events
		errorsCh = hr.watcher.Errors
	}

	statTicker := time.NewTicker(configStatCheckInterval)
	defer statTicker.Stop()

	for {
		select {
		case <-hr.done:
			return

		// watch for events
		case event, ok := <-eventsCh:
			if !ok {
				return
			}

			// only in-place writes: a replaced file retires the watched inode
			// without one, and the poll is what picks that up
			if event.Op&fsnotify.Write == 0 {
				continue
			}

			if !samePath(event.Name, hr.configPath) &&
				!samePath(event.Name, hr.ldapCredentialsPath) {
				continue
			}

			hr.scheduleReload()

		case <-hr.getDebounceChannel():
			hr.debounceTimer = nil

			select {
			case <-hr.done:
				return
			default:
			}

			hr.reloadConfig("debounced file change")

		case <-statTicker.C:
			// always poll: it covers whatever the watch missed
			hr.pollForChanges()

		// watch for errors
		case err, ok := <-errorsCh:
			if !ok {
				return
			}

			// events may have been dropped, which the next poll tick resolves
			hr.ctlr.Log.Error().Err(err).Str("config", hr.configPath).
				Msg("failed to watch config file, relying on stat-based polling")
		}
	}
}

// pollForChanges reloads when a fingerprint moved. It is what picks up a file
// that was replaced rather than written in place, which is how a Kubernetes
// ConfigMap update arrives, and it re-binds the watch to the new inode.
func (hr *HotReloader) pollForChanges() {
	if !hr.checkFilesChanged() {
		return
	}

	hr.readdWatches()

	// a write may have armed a debounce for this same change, which would
	// reload a second time and restart every background task again for one edit
	hr.cancelPendingReload()

	hr.reloadConfig("stat-based polling")
}

func (hr *HotReloader) reloadConfig(reason string) {
	hr.ctlr.Log.Info().Str("config", hr.configPath).Str("reason", reason).
		Msg("config file changed, trying to reload config")

	// sample fingerprints before reading, so a replacement mid-read is re-detected
	configInfo := statOrNil(hr.configPath)
	ldapInfo := statOrNil(hr.ldapCredentialsPath)

	newConfig := config.New()

	err := LoadConfiguration(newConfig, hr.configPath)
	if err != nil {
		hr.ctlr.Log.Error().Err(err).Str("config", hr.configPath).
			Msg("failed to reload config, retry writing it.")

		// a load that failed on its credentials file decoded where that file
		// should be, so fingerprint it: its arrival then retries the config,
		// which baselining alone would never notice
		hr.pendingLdapPath = ldapCredentialsPath(newConfig)
		hr.pendingLdapInfo = statOrNil(hr.pendingLdapPath)

		// baseline the bad file so the poll does not retry every tick; the
		// next actual change retries
		hr.configInfo = configInfo
		hr.ldapInfo = ldapInfo

		return
	}

	ldapInfo = hr.followLdapCredentials(ldapCredentialsPath(newConfig), ldapInfo)

	// stop background tasks gracefully
	hr.ctlr.StopBackgroundTasks()

	// load new config
	hr.ctlr.LoadNewConfig(newConfig)

	// start background tasks based on new loaded config
	hr.ctlr.StartBackgroundTasks()

	hr.warnNonReloadableChanges(newConfig)

	hr.configInfo = configInfo
	hr.ldapInfo = ldapInfo
	hr.pendingLdapPath = ""
	hr.pendingLdapInfo = nil
}

// ldapCredentialsPath returns the credentials file a config refers to, which is
// decoded even by a load that then failed to read it.
func ldapCredentialsPath(conf *config.Config) string {
	if conf.HTTP.Auth == nil || conf.HTTP.Auth.LDAP == nil {
		return ""
	}

	return conf.HTTP.Auth.LDAP.CredentialsFile
}

// followLdapCredentials moves the watch and the fingerprint onto newPath when
// the config points somewhere else: moved, newly added, or removed with LDAP.
func (hr *HotReloader) followLdapCredentials(newPath string, ldapInfo os.FileInfo) os.FileInfo {
	oldPath := hr.ldapCredentialsPath
	if newPath == oldPath {
		return ldapInfo
	}

	if oldPath != "" && hr.watcher != nil {
		if err := hr.watcher.Remove(oldPath); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
			hr.ctlr.Log.Error().Err(err).Msg("failed to remove old watch for the credentials file")
		}
	}

	hr.ldapCredentialsPath = newPath

	if newPath != "" && hr.watcher != nil {
		if err := hr.watcher.Add(newPath); err != nil {
			hr.ctlr.Log.Error().Err(err).Str("ldap-credentials-file", newPath).
				Msg("failed to watch ldap credentials file, relying on stat-based polling")
		}
	}

	return statOrNil(newPath)
}

// warnNonReloadableChanges logs config fields that still differ between the
// file and the effective configuration after a reload: they need a restart.
func (hr *HotReloader) warnNonReloadableChanges(newConfig *config.Config) {
	// compared unmasked: sanitizing both sides turns a rotated secret into the
	// same mask on each and hides a change that needs a restart. Only the field
	// paths are logged, never the values.
	effective, err := configAsMap(hr.ctlr.Config.Copy())
	if err != nil {
		return
	}

	desired, err := configAsMap(newConfig)
	if err != nil {
		return
	}

	fields := diffConfigPaths("", effective, desired)
	if len(fields) > 0 {
		hr.ctlr.Log.Warn().Strs("fields", fields).
			Msg("config changes are outside the reloadable set and need a restart to take effect")
	}
}

func configAsMap(cfg *config.Config) (map[string]any, error) {
	buf, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// diffConfigPaths returns the dotted paths whose values differ between two
// JSON object trees; nested objects recurse, anything else compares wholesale.
func diffConfigPaths(prefix string, effective, desired map[string]any) []string {
	keys := make(map[string]struct{})
	for key := range effective {
		keys[key] = struct{}{}
	}

	for key := range desired {
		keys[key] = struct{}{}
	}

	paths := []string{}

	for _, key := range slices.Sorted(maps.Keys(keys)) {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		effectiveVal, desiredVal := effective[key], desired[key]

		effectiveMap, effectiveIsMap := effectiveVal.(map[string]any)

		desiredMap, desiredIsMap := desiredVal.(map[string]any)
		if effectiveIsMap && desiredIsMap {
			paths = append(paths, diffConfigPaths(path, effectiveMap, desiredMap)...)

			continue
		}

		if !reflect.DeepEqual(effectiveVal, desiredVal) {
			paths = append(paths, path)
		}
	}

	return paths
}

// checkFilesChanged reports whether the config or LDAP credentials file differs
// from the baseline fingerprint recorded at the last successful reload.
// Identity (os.SameFile) catches atomic-rename replacements even when the new
// file preserves the old timestamp; size catches same-inode rewrites within one
// coarse-timestamp granule; mtime catches plain in-place edits.
func (hr *HotReloader) checkFilesChanged() bool {
	return fileChanged(hr.configPath, hr.configInfo) ||
		fileChanged(hr.ldapCredentialsPath, hr.ldapInfo) ||
		fileChanged(hr.pendingLdapPath, hr.pendingLdapInfo)
}

func fileChanged(path string, prev os.FileInfo) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		// Transient during atomic replacements; the next tick sees the new file.
		return false
	}

	if prev == nil {
		return true
	}

	return !os.SameFile(prev, info) || prev.Size() != info.Size() || !prev.ModTime().Equal(info.ModTime())
}

func (hr *HotReloader) getDebounceChannel() <-chan time.Time {
	if hr.debounceTimer == nil {
		return nil
	}

	return hr.debounceTimer.C
}

// cancelPendingReload disarms a debounce that is already scheduled, so a reload
// happening now is not repeated by one queued a moment earlier.
func (hr *HotReloader) cancelPendingReload() {
	if hr.debounceTimer == nil {
		return
	}

	// since go1.23 a timer channel is unbuffered and Stop guarantees no value
	// prepared before it can still arrive, so dropping the timer is enough
	hr.debounceTimer.Stop()
	hr.debounceTimer = nil
}

func (hr *HotReloader) scheduleReload() {
	if hr.debounceTimer != nil {
		// Reset carries the same guarantee: the pending tick, if any, is dropped
		hr.debounceTimer.Reset(configEventDebounceInterval)

		return
	}

	hr.debounceTimer = time.NewTimer(configEventDebounceInterval)
}

func (hr *HotReloader) readdWatches() {
	if hr.watcher == nil {
		return
	}

	if err := hr.watcher.Add(hr.configPath); err != nil {
		hr.ctlr.Log.Debug().Err(err).Str("config", hr.configPath).
			Msg("failed to re-add config watch, relying on stat-based polling")
	}

	ldapPath := hr.ldapCredentialsPath

	if ldapPath != "" {
		if err := hr.watcher.Add(ldapPath); err != nil {
			hr.ctlr.Log.Debug().Err(err).Str("ldap-credentials", ldapPath).
				Msg("failed to re-add ldap-credentials watch, relying on stat-based polling")
		}
	}
}

// samePath reports whether a fsnotify event name refers to the watched file.
func samePath(eventName, filePath string) bool {
	if eventName == "" || filePath == "" {
		return false
	}

	return filepath.Clean(eventName) == filepath.Clean(filePath)
}

func statOrNil(path string) os.FileInfo {
	if path == "" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	return info
}
