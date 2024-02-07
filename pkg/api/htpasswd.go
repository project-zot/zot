package api

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/storage/constants"
)

const (
	htpasswdValidTokensNumber = 2
)

type HtpasswdClient struct {
	credMap  credMap
	credFile credFile
}

type credFile struct {
	path string
	rw   *sync.RWMutex
}

type credMap struct {
	m  map[string]string
	rw *sync.RWMutex
}

func NewHtpasswdClient(filepath string) *HtpasswdClient {
	return &HtpasswdClient{
		credFile: credFile{
			path: filepath,
			rw:   &sync.RWMutex{},
		},
		credMap: credMap{
			m:  make(map[string]string),
			rw: &sync.RWMutex{},
		},
	}
}

// Init initializes the HtpasswdClient.
// It performs the credFile read using the filename specified in NewHtpasswdClient
// and caches all user passwords.
func (hc *HtpasswdClient) Init() error {
	credsFile, err := os.Open(hc.credFile.path)
	if err != nil {
		return fmt.Errorf("error occurred while opening creds-credFile: %w", err)
	}
	defer credsFile.Close()

	hc.credMap.rw.Lock()
	defer hc.credMap.rw.Unlock()

	scanner := bufio.NewScanner(credsFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			tokens := strings.Split(line, ":")
			if len(tokens) == htpasswdValidTokensNumber {
				hc.credMap.m[tokens[0]] = tokens[1]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error occurred while reading creds-credFile: %w", err)
	}

	return nil
}

// Get returns the password associated with the login and a bool
// indicating whether the login was found.
// It does not check whether the user's password is correct.
func (hc *HtpasswdClient) Get(login string) (string, bool) {
	return hc.credMap.Get(login)
}

// Set sets the new password. It does not perform any checks,
// the only error is possible is encryption error.
func (hc *HtpasswdClient) Set(login, password string) error {
	passphrase, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error occurred while cheking passwords: %w", err)
	}

	return hc.credMap.Set(login, string(passphrase))
}

// CheckPassword checks whether the user has a specified password.
// It returns an error if the user is not found or passwords do not match,
// and returns the nil on passwords match.
func (hc *HtpasswdClient) CheckPassword(login, password string) error {
	passwordHash, ok := hc.Get(login)
	if !ok {
		return zerr.ErrBadUser
	}

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return zerr.ErrPasswordsDoNotMatch
	}

	return nil
}

// ChangePassword changes the user password.
// It accepts user login, his supposed old password for verification and new password.
func (hc *HtpasswdClient) ChangePassword(login, supposedOldPassword, newPassword string) error {
	if len(newPassword) == 0 {
		return zerr.ErrPasswordIsEmpty
	}

	oldPassphrase, ok := hc.credMap.Get(login)
	if !ok {
		return zerr.ErrBadUser
	}

	// given old password must match actual old password
	if err := bcrypt.CompareHashAndPassword([]byte(oldPassphrase), []byte(supposedOldPassword)); err != nil {
		return zerr.ErrOldPasswordIsWrong
	}

	// if passwords match, no need to update credFile and map, return nil as if operation is successful
	if err := bcrypt.CompareHashAndPassword([]byte(oldPassphrase), []byte(newPassword)); err == nil {
		return nil
	}

	// encrypt new password
	newPassphrase, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error occurred while encrypting new password: %w", err)
	}

	file, err := os.ReadFile(hc.credFile.path)
	if err != nil {
		return fmt.Errorf("error occurred while reading creds-credFile: %w", err)
	}

	// read passwords line by line to find the corresponding login
	lines := strings.Split(string(file), "\n")
	for i, line := range lines {
		if tokens := strings.Split(line, ":"); len(tokens) == htpasswdValidTokensNumber {
			if tokens[0] == login {
				lines[i] = tokens[0] + ":" + string(newPassphrase)

				break
			}
		}
	}

	// write new content to temporary credFile
	// and replace the old credFile with temporary, so the operation is atomic
	output := []byte(strings.Join(lines, "\n"))

	tmpfile, err := os.CreateTemp(filepath.Dir(hc.credFile.path), "htpasswd-*.tmp")
	if err != nil {
		return fmt.Errorf("error occurred when creating temp htpasswd credFile: %w", err)
	}

	if _, err := tmpfile.Write(output); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())

		return fmt.Errorf("error occurred when writing to temp htpasswd credFile: %w", err)
	}

	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())

		return fmt.Errorf("error occurred when closing temp htpasswd credFile: %w", err)
	}

	if err := os.Rename(tmpfile.Name(), hc.credFile.path); err != nil {
		return fmt.Errorf("error occurred while replacing htpasswd credFile with new credFile: %w", err)
	}

	err = os.WriteFile(hc.credFile.path, output, constants.DefaultDirPerms)
	if err != nil {
		return fmt.Errorf("error occurred while writing to creds-credFile: %w", err)
	}

	// set to credMap only if all credFile operations are successful to prevent collisions
	return hc.credMap.Set(login, string(newPassphrase))
}

func (c credMap) Set(login, passphrase string) error {
	c.rw.Lock()
	c.m[login] = passphrase
	c.rw.Unlock()

	return nil
}

func (c credMap) Get(login string) (string, bool) {
	c.rw.RLock()
	defer c.rw.RUnlock()
	passphrase, ok := c.m[login]

	return passphrase, ok
}
