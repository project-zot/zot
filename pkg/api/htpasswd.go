package api

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/bcrypt"

	"zotregistry.dev/zot/v2/pkg/log"
)

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

	err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase))
	ok = err == nil

	if err != nil && !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		// Log that user's hash has unsupported format. Better than silently return 401.
		s.log.Warn().Err(err).Str("username", username).Msg("htpasswd bcrypt compare failed")
	}

	return
}

// HTPasswdWatcher helper which triggers htpasswd reload on file change event.
//
// Can be restarted by calling Run() again after Close().
type HTPasswdWatcher struct {
	htp      *HTPasswd
	filePath string
	watcher  *fsnotify.Watcher
	ctx      context.Context //nolint:containedctx // Context is needed for watcher lifecycle management
	cancel   context.CancelFunc
	log      log.Logger
	mu       sync.Mutex
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
func (s *HTPasswdWatcher) Run() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ctx != nil {
		return // Already running
	}

	// Create fresh fsnotify watcher for this run
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.log.Error().Err(err).Msg("failed to create fsnotify watcher")

		return
	}

	// Only add file to watcher if we have a file to watch
	if s.filePath != "" {
		err = watcher.Add(s.filePath)
		if err != nil {
			s.log.Error().Err(err).Str("htpasswd-file", s.filePath).Msg("failed to add file to watcher")
			watcher.Close() //nolint: errcheck

			return
		}
	}

	// Create context and start goroutine
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	s.ctx = ctx
	s.cancel = cancel
	s.watcher = watcher

	go func() {
		defer func() {
			s.mu.Lock()
			defer s.mu.Unlock()

			// Clean up watcher
			if s.watcher != nil {
				s.watcher.Close() //nolint: errcheck
				s.watcher = nil
			}

			// Clear context to indicate not running
			s.ctx = nil
			s.cancel = nil
		}()

		for {
			select {
			case <-ctx.Done():
				s.log.Debug().Msg("htpasswd watcher terminating...")

				return

			case ev := <-watcher.Events:
				if ev.Op != fsnotify.Write {
					continue
				}

				s.log.Info().Str("htpasswd-file", s.filePath).Msg("htpasswd file changed, trying to reload config")

				err := s.htp.Reload(s.filePath)
				if err != nil {
					s.log.Warn().Err(err).Str("htpasswd-file", s.filePath).Msg("failed to reload file")
				}

			case err := <-watcher.Errors:
				// Only log errors if we're actually watching a file
				if s.filePath != "" {
					s.log.Error().Err(err).Str("htpasswd-file", s.filePath).Msg("failed to fsnotfy, got error while watching file")
				}
			}
		}
	}()
}

// ChangeFile changes monitored file. Empty string clears store.
func (s *HTPasswdWatcher) ChangeFile(filePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If watcher is not running, just update the filePath for when Run() is called
	if s.watcher == nil {
		s.filePath = filePath
		if filePath == "" {
			s.htp.Clear()
		} else {
			return s.htp.Reload(filePath)
		}

		return nil
	}

	// Remove old file if it exists
	if s.filePath != "" {
		if err := s.watcher.Remove(s.filePath); err != nil && !errors.Is(err, fsnotify.ErrNonExistentWatch) {
			// Ignore "can't remove non-existent watch" errors as they can happen
			// due to race conditions or files being removed externally
			return err
		}
	}

	if filePath == "" {
		s.filePath = filePath
		s.htp.Clear()

		return nil
	}

	err := s.watcher.Add(filePath)
	if err != nil {
		return err
	}

	s.filePath = filePath

	return s.htp.Reload(filePath)
}

func (s *HTPasswdWatcher) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ctx == nil {
		return nil // Already closed/not running
	}

	// Cancel context to signal goroutine to stop
	if s.cancel != nil {
		s.cancel()
	}

	// The goroutine will clean up s.ctx, s.cancel, and s.watcher in its defer
	// We just need to wait for it to finish by checking if s.ctx becomes nil
	// This is safe because the goroutine sets s.ctx = nil in its defer

	return nil
}
