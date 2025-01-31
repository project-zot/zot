package api

import (
	"bufio"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"zotregistry.dev/zot/pkg/log"
)

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
		s.log.Error().Err(err).Str("credsFile", filePath).Msg("failed to reload htpasswd")

		return err
	}
	defer credsFile.Close()

	scanner := bufio.NewScanner(credsFile)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			tokens := strings.Split(scanner.Text(), ":")
			credMap[tokens[0]] = tokens[1]
		}
	}

	if len(credMap) == 0 {
		s.log.Warn().Str("credsFile", filePath).Msg("loaded htpasswd file appears to have zero users")
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

	return
}
