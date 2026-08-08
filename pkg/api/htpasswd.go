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
// Can be restarted by calling Run() again after Close(); Close() tears down
// state synchronously, so an immediate Run() after Close() is safe.
// Mirrors TlsConfigWatcher behavior for Kubernetes Secret/ConfigMap mounts that
// replace files via atomic rename/symlink swap (Remove/Create/Rename, not only Write).
type HTPasswdWatcher struct {
	htp           *HTPasswd
	filePath      string
	watcher       *fsnotify.Watcher
	done          chan struct{}
	log           log.Logger
	mu            sync.Mutex
	useInotify    bool
	debounceTimer *time.Timer
	debounceMutex sync.Mutex
	fileModTime   time.Time
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

	if s.done != nil {
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
	s.done = done
	s.watcher = watcher
	s.useInotify = useInotify

	go s.loop(done, watcher)

	return nil
}

func (s *HTPasswdWatcher) loop(done chan struct{}, watcher *fsnotify.Watcher) {
	defer func() {
		s.mu.Lock()
		// Only clear state if it still belongs to this loop instance.
		// Close() may have already cleared it, or a new Run() may have replaced it.
		if s.done == done {
			s.done = nil

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
		s.mu.Lock()
		useInotify := s.useInotify
		s.mu.Unlock()

		var statCh <-chan time.Time
		if !useInotify {
			statCh = statTicker.C
		}

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
					s.log.Warn().Str("htpasswd-file", filePath).
						Msg("failed to re-add watch after retries, switching to stat-based polling")
					s.disableUseInotify()
				}
			}

			select {
			case <-done:
				return
			default:
			}

			s.scheduleReload()

		case <-s.getDebounceChannel():
			s.debounceMutex.Lock()
			s.debounceTimer = nil
			s.debounceMutex.Unlock()

			select {
			case <-done:
				return
			default:
			}

			s.reloadWatchedFile("debounced file change")

		case <-statCh:
			if s.checkFileModTime() {
				s.reloadWatchedFile("stat-based polling")
			}

		case err, ok := <-errorsCh:
			if !ok {
				s.log.Debug().Msg("htpasswd watcher errors channel closed")

				return
			}

			// Only log errors if we're actually watching a file
			if s.getFilePath() != "" {
				s.log.Error().Err(err).Str("htpasswd-file", s.getFilePath()).
					Msg("failed to fsnotify, got error while watching file")
			}
		}
	}
}

func (s *HTPasswdWatcher) getFilePath() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.filePath
}

func (s *HTPasswdWatcher) disableUseInotify() {
	s.mu.Lock()
	s.useInotify = false
	s.mu.Unlock()
}

func (s *HTPasswdWatcher) getDebounceChannel() <-chan time.Time {
	s.debounceMutex.Lock()
	defer s.debounceMutex.Unlock()

	if s.debounceTimer == nil {
		return nil
	}

	return s.debounceTimer.C
}

func (s *HTPasswdWatcher) scheduleReload() {
	s.debounceMutex.Lock()
	defer s.debounceMutex.Unlock()

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
func (s *HTPasswdWatcher) retryAddWatch(file string, watcher *fsnotify.Watcher, done <-chan struct{}) bool {
	for attempt := range 5 {
		select {
		case <-done:
			return false
		case <-time.After(time.Duration(50*(attempt+1)) * time.Millisecond):
		}

		if err := s.addWatches(watcher, file); err == nil {
			s.log.Debug().Str("htpasswd-file", file).Int("attempt", attempt+1).
				Msg("re-added watch after file removal/rename")

			s.mu.Lock()
			s.useInotify = true
			s.mu.Unlock()

			return true
		}

		s.log.Debug().Str("htpasswd-file", file).Int("attempt", attempt+1).
			Msg("retrying watch add after failure")
	}

	return false
}

func (s *HTPasswdWatcher) reloadWatchedFile(reason string) {
	filePath := s.getFilePath()
	if filePath == "" {
		return
	}

	s.log.Info().Str("htpasswd-file", filePath).Str("reason", reason).
		Msg("htpasswd file changed, trying to reload config")

	if err := s.htp.Reload(filePath); err != nil {
		s.log.Warn().Err(err).Str("htpasswd-file", filePath).Msg("failed to reload file")

		return
	}

	s.updateFileModTime(filePath)
}

func (s *HTPasswdWatcher) updateFileModTime(filePath string) {
	info, err := htpasswdFileStat(filePath)
	if err != nil {
		s.log.Warn().Err(err).Str("htpasswd-file", filePath).
			Msg("failed to stat htpasswd file after reload")

		return
	}

	s.mu.Lock()
	s.fileModTime = info.ModTime()
	s.mu.Unlock()
}

func (s *HTPasswdWatcher) checkFileModTime() bool {
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
	modTime := s.fileModTime
	s.mu.Unlock()

	if info.ModTime().After(modTime) {
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
		s.fileModTime = time.Time{}
		s.useInotify = false
		s.htp.Clear()

		return nil
	}

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
	s.updateFileModTimeLocked(filePath)

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

// updateFileModTimeLocked updates mod time; caller must hold s.mu.
func (s *HTPasswdWatcher) updateFileModTimeLocked(filePath string) {
	info, err := htpasswdFileStat(filePath)
	if err != nil {
		s.log.Warn().Err(err).Str("htpasswd-file", filePath).
			Msg("failed to stat htpasswd file after reload")

		return
	}

	s.fileModTime = info.ModTime()
}

// Close stops the watcher goroutine and tears down its state synchronously,
// so Run() can be called again immediately after Close() returns.
// Safe to call multiple times and when the watcher is not running.
func (s *HTPasswdWatcher) Close() error {
	// Clean up any pending debounce timer
	s.debounceMutex.Lock()
	if s.debounceTimer != nil {
		s.debounceTimer.Stop()
		s.debounceTimer = nil
	}
	s.debounceMutex.Unlock()

	// Atomically capture and reset watcher state so a subsequent Run() does not
	// race with the goroutine's own cleanup. Captures are nil when not running,
	// which also makes concurrent and repeated Close() calls safe no-ops.
	s.mu.Lock()
	capturedWatcher := s.watcher
	capturedDone := s.done
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

	return nil
}
