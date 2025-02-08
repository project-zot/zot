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

	"zotregistry.dev/zot/pkg/log"
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
// Cannot be restarted.
type HTPasswdWatcher struct {
	htp      *HTPasswd
	filePath string
	watcher  *fsnotify.Watcher
	cancel   context.CancelFunc
	log      log.Logger
}

// NewHTPasswdWatcher create and start watcher.
func NewHTPasswdWatcher(htp *HTPasswd, filePath string) (*HTPasswdWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if filePath != "" {
		err = watcher.Add(filePath)
		if err != nil {
			return nil, errors.Join(err, watcher.Close())
		}
	}

	// background event processor job context
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)

	ret := &HTPasswdWatcher{
		htp:      htp,
		filePath: filePath,
		watcher:  watcher,
		cancel:   cancel,
		log:      htp.log,
	}

	go func() {
		defer ret.watcher.Close() //nolint: errcheck

		for {
			select {
			case ev := <-ret.watcher.Events:
				if ev.Op != fsnotify.Write {
					continue
				}

				ret.log.Info().Str("htpasswd-file", ret.filePath).Msg("htpasswd file changed, trying to reload config")

				err := ret.htp.Reload(ret.filePath)
				if err != nil {
					ret.log.Warn().Err(err).Str("htpasswd-file", ret.filePath).Msg("failed to reload file")
				}

			case err := <-ret.watcher.Errors:
				ret.log.Error().Err(err).Str("htpasswd-file", ret.filePath).Msg("failed to fsnotfy, got error while watching file")

			case <-ctx.Done():
				ret.log.Debug().Msg("htpasswd watcher terminating...")

				return
			}
		}
	}()

	return ret, nil
}

// ChangeFile changes monitored file. Empty string clears store.
func (s *HTPasswdWatcher) ChangeFile(filePath string) error {
	if s.filePath != "" {
		err := s.watcher.Remove(s.filePath)
		if err != nil {
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
	s.cancel()

	return nil
}
