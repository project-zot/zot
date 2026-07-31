package api

import (
	"bufio"
	"crypto/fips140"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	cpass "github.com/nathanaelle/password"
	"golang.org/x/crypto/bcrypt"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// htpasswdEventDebounceInterval coalesces multiple fsnotify events into one reload.
	// Kubernetes Secret/ConfigMap updates often emit Remove/Create/Rename bursts.
	htpasswdEventDebounceInterval = 150 * time.Millisecond
	// htpasswdStatCheckInterval is the polling interval used when inotify watching is unavailable.
	htpasswdStatCheckInterval = 1 * time.Second
)

var htpasswdFileStat = os.Stat //nolint:gochecknoglobals // test hook for os.Stat

// HTPasswd user auth store
//
// Currently supports only bcrypt hashes.
type HTPasswd struct {
	mu      sync.RWMutex
	credMap map[string]string
	log     log.Logger
}

func NewHTPasswd(log log.Logger) *HTPasswd {
	return &HTPasswd{
		credMap: make(map[string]string),
		log:     log,
	}
}

func (s *HTPasswd) Reload(filePath string) error {
	credMap := make(map[string]string)

	credsFile, err := os.Open(filePath)
	if err != nil {
		s.log.Error().Err(err).Str("htpasswd-file", filePath).Msg("failed to reload htpasswd")

		return err
	}
	defer credsFile.Close()

	scanner := bufio.NewScanner(credsFile)

	for scanner.Scan() {
		user, hash, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			credMap[user] = hash
		}
	}

	if len(credMap) == 0 {
		s.log.Warn().Str("htpasswd-file", filePath).Msg("loaded htpasswd file appears to have zero users")
	} else {
		s.log.Info().Str("htpasswd-file", filePath).Int("users", len(credMap)).Msg("loaded htpasswd file")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.credMap = credMap

	return nil
}

func (s *HTPasswd) Get(username string) (passphraseHash string, present bool) { //nolint: nonamedreturns
	s.mu.RLock()
	defer s.mu.RUnlock()

	passphraseHash, present = s.credMap[username]

	return
}

func (s *HTPasswd) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.credMap = make(map[string]string)
}

func (s *HTPasswd) Authenticate(username, passphrase string) (ok, present bool) { //nolint: nonamedreturns
	passphraseHash, present := s.Get(username)
	if !present {
		return false, false
	}

	// first try bcrypt (although disabled if fips140 mode is enabled)
	if strings.HasPrefix(passphraseHash, "$2a$") || strings.HasPrefix(passphraseHash, "$2b$") ||
		strings.HasPrefix(passphraseHash, "$2y$") {
		if fips140.Enabled() {
			s.log.Warn().Str("username", username).Msg("htpasswd bcrypt failed since fips140 is enabled")

			return false, present
		}

		err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase))
		if err != nil {
			// Log that user's hash has unsupported format. Better than silently return 401.
			s.log.Warn().Err(err).Str("username", username).Msg("htpasswd bcrypt compare failed")

			return false, present
		}

		return true, present // success: bcrypt
	}

	var crypter cpass.Crypter

	if strings.HasPrefix(passphraseHash, "$5$") { //nolint:gocritic // errorslint conflicts with gocritic:IfElseChain
		crypter, ok = cpass.SHA256.CrypterFound(passphraseHash)
	} else if strings.HasPrefix(passphraseHash, "$6$") {
		crypter, ok = cpass.SHA512.CrypterFound(passphraseHash)
	} else {
		s.log.Warn().Str("username", username).Msg("htpasswd entry has unsupported hash type")

		return false, present
	}

	if !ok {
		s.log.Warn().Str("username", username).Msg("htpasswd entry parsing failed")

		return false, present
	}

	if !crypter.Verify([]byte(passphrase)) {
		s.log.Warn().Str("username", username).Msg("htpasswd sha compare failed")

		return false, present
	}

	return true, present // success: sha
}

// HTPasswdWatcher helper which triggers htpasswd reload on file change event.
//
// Can be restarted by calling Run() again after Close(); Close() waits for the
// watcher goroutine to exit, so an immediate Run() after Close() is safe.
// Mirrors TlsConfigWatcher behavior for Kubernetes Secret/ConfigMap mounts that
// replace files via atomic rename/symlink swap (Remove/Create/Rename, not only Write).
type HTPasswdWatcher struct {
	htp *HTPasswd
	log log.Logger

	// mu protects all fields below. No code path blocks while holding it:
	// lock sections are short and never wait on channels, timers or the
	// goroutine, so the single mutex cannot participate in a deadlock cycle.
	mu       sync.Mutex
	filePath string
	watcher  *fsnotify.Watcher
	// done is non-nil while the watcher is running and not yet signaled to stop.
	done chan struct{}
	// stopped is non-nil from Run() until the loop goroutine has fully exited
	// (it is cleared by the loop itself). While set, Run() refuses to start a
	// second generation, so loops can never overlap even if Run() races Close().
	stopped       chan struct{}
	useInotify    bool
	debounceTimer *time.Timer
	// fileInfo is the stat fingerprint of the last successfully loaded file.
	// Polling compares identity (os.SameFile), size and mtime against it, so
	// atomic replacements that preserve the timestamp are still detected.
	fileInfo os.FileInfo
}

// NewHTPasswdWatcher creates a new watcher instance.
func NewHTPasswdWatcher(htp *HTPasswd, filePath string) (*HTPasswdWatcher, error) {
	ret := &HTPasswdWatcher{
		htp:      htp,
		filePath: filePath,
		log:      htp.log,
	}

	return ret, nil
}

// Run starts the watcher goroutine.
// Returns ErrHTPasswdWatcherAlreadyRunning if the watcher is already running.
// If inotify setup fails, the watcher still starts and falls back to stat-based polling.
func (s *HTPasswdWatcher) Run() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// s.stopped stays non-nil until the previous loop goroutine has fully
	// exited, so a Run() racing an in-progress Close() cannot start a second
	// generation that would share the debounce timer and useInotify state.
	if s.done != nil || s.stopped != nil {
		return zerr.ErrHTPasswdWatcherAlreadyRunning
	}

	// Create fresh fsnotify watcher for this run. On failure continue without it,
	// the loop still runs and reloads via stat-based polling.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create fsnotify watcher, falling back to stat-based polling")

		watcher = nil
	}

	useInotify := false

	// Watch the file and its parent directory. Directory watches are required for
	// Kubernetes Secret/ConfigMap mounts, where the file is a symlink and updates
	// atomically retarget ..data without rewriting the watched inode.
	if watcher != nil && s.filePath != "" {
		if err := s.addWatches(watcher, s.filePath); err != nil {
			s.log.Error().Err(err).Str("htpasswd-file", s.filePath).
				Msg("failed to add file to watcher, falling back to stat-based polling")
		} else {
			useInotify = true
		}
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	s.done = done
	s.stopped = stopped
	s.watcher = watcher
	s.useInotify = useInotify

	go s.loop(done, stopped, watcher)

	return nil
}

func (s *HTPasswdWatcher) loop(done chan struct{}, stopped chan struct{}, watcher *fsnotify.Watcher) {
	defer close(stopped)

	defer func() {
		s.mu.Lock()
		// Only clear state if it still belongs to this loop instance.
		// s.stopped is the ownership marker: Close() never clears it, and a new
		// Run() cannot replace it while it is set.
		if s.stopped == stopped {
			s.done = nil
			s.stopped = nil

			if s.watcher != nil {
				s.watcher.Close() //nolint: errcheck
				s.watcher = nil
			}

			s.useInotify = false
		}
		s.mu.Unlock()

		// Logged on every exit path; tests rely on this message to detect termination.
		s.log.Debug().Msg("htpasswd watcher terminating...")
	}()

	// Nil channels block forever in select, which makes the loop safe to run
	// in polling-only mode when fsnotify is unavailable.
	var eventsCh chan fsnotify.Event

	var errorsCh chan error

	if watcher != nil {
		eventsCh = watcher.Events
		errorsCh = watcher.Errors
	}

	statTicker := time.NewTicker(htpasswdStatCheckInterval)
	defer statTicker.Stop()

	for {
		select {
		case <-done:
			return

		case event, ok := <-eventsCh:
			if !ok {
				s.log.Debug().Msg("htpasswd watcher events channel closed")

				return
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}

			filePath := s.getFilePath()
			if filePath == "" || !s.eventAffectsWatchedFile(event.Name, filePath) {
				continue
			}

			s.log.Debug().Str("file", event.Name).Str("op", event.Op.String()).
				Msg("htpasswd file change detected")

			if event.Op&(fsnotify.Remove|fsnotify.Rename|fsnotify.Create) != 0 {
				if !s.retryAddWatch(filePath, watcher, done) {
					s.mu.Lock()
					// Only fall back to polling when this path is still current;
					// a concurrent ChangeFile may already own inotify for a new path.
					if s.filePath == filePath {
						s.log.Warn().Str("htpasswd-file", filePath).
							Msg("failed to re-add watch after retries, switching to stat-based polling")
						s.useInotify = false
					}
					s.mu.Unlock()
				}
			}

			select {
			case <-done:
				return
			default:
			}

			s.scheduleReload()

		case <-s.getDebounceChannel():
			s.mu.Lock()
			s.debounceTimer = nil
			s.mu.Unlock()

			select {
			case <-done:
				return
			default:
			}

			s.reloadWatchedFile("debounced file change")

		case <-statTicker.C:
			// Always select the ticker so ChangeFile can flip useInotify off and
			// have polling take effect on the next tick without needing a wake signal.
			s.mu.Lock()
			useInotify := s.useInotify
			s.mu.Unlock()

			if useInotify {
				continue
			}

			if s.checkFileChanged() {
				s.reloadWatchedFile("stat-based polling")
			}

		case err, ok := <-errorsCh:
			if !ok {
				s.log.Debug().Msg("htpasswd watcher errors channel closed")

				return
			}

			// Only react if we're actually watching a file
			if s.getFilePath() != "" {
				s.log.Error().Err(err).Str("htpasswd-file", s.getFilePath()).
					Msg("failed to fsnotify, got error while watching file")

				// Events may have been dropped (e.g. inotify queue overflow),
				// so inotify can no longer be trusted for this run: fall back
				// to stat-based polling and reload to resynchronize.
				s.mu.Lock()
				s.useInotify = false
				s.mu.Unlock()

				s.scheduleReload()
			}
		}
	}
}

func (s *HTPasswdWatcher) getFilePath() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.filePath
}

func (s *HTPasswdWatcher) getDebounceChannel() <-chan time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.debounceTimer == nil {
		return nil
	}

	return s.debounceTimer.C
}

func (s *HTPasswdWatcher) scheduleReload() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.debounceTimer != nil {
		if !s.debounceTimer.Stop() {
			select {
			case <-s.debounceTimer.C:
			default:
			}
		}
		s.debounceTimer.Reset(htpasswdEventDebounceInterval)
		s.log.Debug().Msg("htpasswd debounce timer reset for additional file change event")

		return
	}

	s.debounceTimer = time.NewTimer(htpasswdEventDebounceInterval)
	s.log.Debug().Str("interval", htpasswdEventDebounceInterval.String()).
		Msg("htpasswd debounce timer started for file change events")
}

// addWatches watches filePath and its parent directory as a unit.
// The parent directory watch is required to detect Kubernetes Secret/ConfigMap
// updates, which atomically retarget the ..data symlink instead of writing to
// the watched inode. Either both watches are established or an error is
// returned, so callers never treat partial coverage as working inotify and
// keep the stat-based polling fallback active instead.
func (s *HTPasswdWatcher) addWatches(watcher *fsnotify.Watcher, filePath string) error {
	if err := watcher.Add(filePath); err != nil {
		return err
	}

	dir := filepath.Dir(filePath)

	if err := watcher.Add(dir); err != nil {
		// Roll back the file watch so callers and retries start from a clean state
		if rmErr := watcher.Remove(filePath); rmErr != nil && !errors.Is(rmErr, fsnotify.ErrNonExistentWatch) {
			s.log.Debug().Err(rmErr).Str("htpasswd-file", filePath).
				Msg("failed to remove htpasswd file watch during rollback")
		}

		return err
	}

	return nil
}

// eventAffectsWatchedFile reports whether a fsnotify event is relevant for the
// watched htpasswd file. Since the parent directory is watched too, events for
// unrelated sibling files must be filtered out: only the exact file path and
// Kubernetes ..data symlink swaps in the same directory trigger a reload.
func (s *HTPasswdWatcher) eventAffectsWatchedFile(eventName, filePath string) bool {
	if eventName == "" || filePath == "" {
		return false
	}

	eventName = filepath.Clean(eventName)
	filePath = filepath.Clean(filePath)

	if eventName == filePath {
		return true
	}

	// Kubernetes mounts swap the ..data (or ..data_tmp) symlink under the mount directory.
	if strings.HasPrefix(filepath.Base(eventName), "..data") {
		return filepath.Dir(eventName) == filepath.Dir(filePath)
	}

	return false
}

// retryAddWatch re-establishes watches after the file is removed/renamed.
// It blocks the watcher loop for up to ~750ms total; that is acceptable since
// fsnotify buffers events in the meantime and htpasswd changes are infrequent.
// Returns false only when retries are exhausted for a path that is still current.
// If ChangeFile switches the watched path mid-retry, returns true without touching
// watches or useInotify, so it cannot clobber the new path's state.
//
// The path check, addWatches and useInotify update happen under s.mu as one unit
// (mirroring ChangeFile): re-adding watches without the lock could race with a
// concurrent ChangeFile to a sibling file and remove the shared parent-dir watch.
func (s *HTPasswdWatcher) retryAddWatch(file string, watcher *fsnotify.Watcher, done <-chan struct{}) bool {
	for attempt := range 5 {
		select {
		case <-done:
			return false
		case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
		}

		s.mu.Lock()

		if s.filePath != file {
			// Concurrent ChangeFile moved us to a different path; abandon this retry.
			s.mu.Unlock()

			return true
		}

		if err := s.addWatches(watcher, file); err == nil {
			s.useInotify = true
			s.mu.Unlock()

			s.log.Debug().Str("htpasswd-file", file).Int("attempt", attempt+1).
				Msg("re-added watch after file removal/rename")

			return true
		}

		s.mu.Unlock()

		s.log.Debug().Str("htpasswd-file", file).Int("attempt", attempt+1).
			Msg("retrying watch add after failure")
	}

	return false
}

func (s *HTPasswdWatcher) reloadWatchedFile(reason string) {
	// Hold s.mu for the entire reload so it serializes with ChangeFile:
	// otherwise an in-flight reload of the previous path could overwrite the
	// credentials and mod-time baseline a concurrent ChangeFile just installed,
	// leaving stale users loaded indefinitely.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.filePath == "" {
		return
	}

	s.log.Info().Str("htpasswd-file", s.filePath).Str("reason", reason).
		Msg("htpasswd file changed, trying to reload config")

	// Sample the fingerprint before reading the file: if a replacement lands
	// mid-read, the stale baseline makes the next poll detect and reload it,
	// instead of recording the new fingerprint against the old content.
	info := s.statFile(s.filePath)

	if err := s.htp.Reload(s.filePath); err != nil {
		s.log.Warn().Err(err).Str("htpasswd-file", s.filePath).Msg("failed to reload file")

		return
	}

	s.fileInfo = info
}

// checkFileChanged reports whether the watched file differs from the baseline
// fingerprint recorded at the last successful reload. Identity (os.SameFile)
// catches atomic-rename replacements even when the new file preserves the old
// timestamp; size catches same-inode rewrites within one coarse-timestamp
// granule; mtime catches plain in-place edits. An in-place rewrite with equal
// size inside the same timestamp granule remains undetectable without hashing,
// and is covered by inotify in all but the polling-only degraded mode.
func (s *HTPasswdWatcher) checkFileChanged() bool {
	filePath := s.getFilePath()
	if filePath == "" {
		return false
	}

	info, err := htpasswdFileStat(filePath)
	if err != nil {
		s.log.Debug().Err(err).Str("htpasswd-file", filePath).
			Msg("failed to stat htpasswd file during polling")

		return false
	}

	s.mu.Lock()
	prev := s.fileInfo
	s.mu.Unlock()

	// No baseline yet: reload to establish one.
	if prev == nil {
		return true
	}

	if !os.SameFile(prev, info) || prev.Size() != info.Size() || !prev.ModTime().Equal(info.ModTime()) {
		s.log.Debug().Str("htpasswd-file", filePath).
			Msg("htpasswd file modification detected via stat")

		return true
	}

	return false
}

// ChangeFile changes monitored file. Empty string clears store.
func (s *HTPasswdWatcher) ChangeFile(filePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clearing the store works the same whether or not the watcher is running
	if filePath == "" {
		if s.watcher != nil && s.filePath != "" {
			s.removeWatchesLocked(s.filePath)
		}

		s.filePath = ""
		s.fileInfo = nil
		s.useInotify = false
		s.htp.Clear()

		return nil
	}

	// Sample the fingerprint before reading, so a replacement landing mid-read
	// is caught by the next poll instead of being masked by a post-read baseline.
	info := s.statFile(filePath)

	// Validate and load the new file before touching any state, so a bad path
	// leaves the previous configuration fully intact
	if err := s.htp.Reload(filePath); err != nil {
		return err
	}

	// Use s.done (not s.watcher) to detect a running watcher: in polling-only
	// mode the loop is running but s.watcher is nil.
	if s.done != nil && s.watcher != nil {
		if s.filePath != "" {
			s.removeWatchesLocked(s.filePath)
		}

		if err := s.addWatches(s.watcher, filePath); err != nil {
			// Degrade to stat-based polling rather than failing the change
			s.log.Warn().Err(err).Str("htpasswd-file", filePath).
				Msg("failed to watch htpasswd file, falling back to stat-based polling")
			s.useInotify = false
		} else {
			s.useInotify = true
		}
	}

	s.filePath = filePath
	s.fileInfo = info

	return nil
}

// removeWatchesLocked removes file and parent-dir watches; caller must hold s.mu.
func (s *HTPasswdWatcher) removeWatchesLocked(filePath string) {
	if s.watcher == nil || filePath == "" {
		return
	}

	if err := s.watcher.Remove(filePath); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
		s.log.Debug().Err(err).Str("htpasswd-file", filePath).Msg("failed to remove htpasswd file watch")
	}

	dir := filepath.Dir(filePath)
	if dir == "" || dir == "." || dir == filePath {
		return
	}

	if err := s.watcher.Remove(dir); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
		s.log.Debug().Err(err).Str("dir", dir).Msg("failed to remove htpasswd directory watch")
	}
}

// statFile returns the file's current stat fingerprint, or nil if stat fails.
// A nil baseline is safe: the next poll tick treats it as changed and triggers
// a redundant reload, which self-corrects the baseline.
func (s *HTPasswdWatcher) statFile(filePath string) os.FileInfo {
	info, err := htpasswdFileStat(filePath)
	if err != nil {
		s.log.Warn().Err(err).Str("htpasswd-file", filePath).
			Msg("failed to stat htpasswd file")

		return nil
	}

	return info
}

// Close stops the watcher goroutine and waits for it to finish, so Run() can be
// called again immediately after Close() returns without overlapping reloads.
// Safe to call multiple times and when the watcher is not running.
func (s *HTPasswdWatcher) Close() error {
	// Capture and reset watcher state in one critical section. Captures are nil
	// when not running, which also makes concurrent and repeated Close() calls
	// safe no-ops. s.stopped is intentionally NOT cleared here: the loop clears
	// it on exit, and while it is set Run() refuses to start a new generation,
	// so a Run() racing this Close() cannot overlap the draining loop.
	s.mu.Lock()

	if s.debounceTimer != nil {
		s.debounceTimer.Stop()
		s.debounceTimer = nil
	}

	capturedWatcher := s.watcher
	capturedDone := s.done
	capturedStopped := s.stopped
	s.done = nil
	s.watcher = nil
	s.useInotify = false
	s.mu.Unlock()

	// Close fsnotify watcher to terminate the goroutine promptly
	if capturedWatcher != nil {
		_ = capturedWatcher.Close()
	}

	// Signal the goroutine to exit via the done channel
	if capturedDone != nil {
		close(capturedDone)
	}

	// Wait for the goroutine to finish (no locks held here) so in-flight
	// reloads cannot overlap a new Run().
	if capturedStopped != nil {
		<-capturedStopped
	}

	return nil
}
