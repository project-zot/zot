package common

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

var ErrNoGoModFileFound = errors.New("no go.mod file found in parent directories")

func GetProjectRootDir() (string, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(workDir, "go.mod")

		_, err := os.Stat(goModPath)
		if err == nil {
			return workDir, nil
		}

		if workDir == filepath.Dir(workDir) {
			return "", ErrNoGoModFileFound
		}

		workDir = filepath.Dir(workDir)
	}
}

func CopyFile(sourceFilePath, destFilePath string) error {
	destFile, err := os.Create(destFilePath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func CopyFiles(sourceDir, destDir string) error {
	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.Stat failed: %w", err)
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return fmt.Errorf("CopyFiles os.MkdirAll failed: %w", err)
	}

	files, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.ReadDir failed: %w", err)
	}

	for _, file := range files {
		sourceFilePath := path.Join(sourceDir, file.Name())
		destFilePath := path.Join(destDir, file.Name())

		if file.IsDir() {
			if strings.HasPrefix(file.Name(), "_") {
				// Some tests create the trivy related folders under test/_trivy
				continue
			}

			if err = CopyFiles(sourceFilePath, destFilePath); err != nil {
				return err
			}
		} else {
			sourceFile, err := os.Open(sourceFilePath)
			if err != nil {
				return fmt.Errorf("CopyFiles os.Open failed: %w", err)
			}
			defer sourceFile.Close()

			destFile, err := os.Create(destFilePath)
			if err != nil {
				return fmt.Errorf("CopyFiles os.Create failed: %w", err)
			}
			defer destFile.Close()

			if _, err = io.Copy(destFile, sourceFile); err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
		}
	}

	return nil
}

func CopyTestKeysAndCerts(destDir string) error {
	files := []string{
		"ca.crt", "ca.key", "client.cert", "client.csr",
		"client.key", "server.cert", "server.csr", "server.key",
	}

	rootPath, err := GetProjectRootDir()
	if err != nil {
		return err
	}

	sourceDir := filepath.Join(rootPath, "test/data")

	sourceMeta, err := os.Stat(sourceDir)
	if err != nil {
		return fmt.Errorf("CopyFiles os.Stat failed: %w", err)
	}

	if err := os.MkdirAll(destDir, sourceMeta.Mode()); err != nil {
		return err
	}

	for _, file := range files {
		err = CopyFile(filepath.Join(sourceDir, file), filepath.Join(destDir, file))
		if err != nil {
			return err
		}
	}

	return nil
}

func WriteFileWithPermission(path string, data []byte, perm fs.FileMode, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}

	flag := os.O_WRONLY | os.O_CREATE

	if overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}

	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		file.Close()

		return err
	}

	return file.Close()
}

func ReadLogFileAndSearchString(logPath string, stringToMatch string, timeout time.Duration) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Contains(string(content), stringToMatch) {
				return true, nil
			}
		}
	}
}

func ReadLogFileAndCountStringOccurence(logPath string, stringToMatch string,
	timeout time.Duration, count int,
) (bool, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
			content, err := os.ReadFile(logPath)
			if err != nil {
				return false, err
			}

			if strings.Count(string(content), stringToMatch) >= count {
				return true, nil
			}
		}
	}
}

func GetBcryptCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s\n", username, string(hash))

	return usernameAndHash
}

const (
	PrefixCryptSha256 = "$5$"
	PrefixCryptSha512 = "$6$"
	Separator         = "$"
)

// generateSecureRandomString should only be used in tests with length = 16.
func generateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func shaCrypt(password string, rounds string, salt string, prefix string) string {
	var ret string

	var strb strings.Builder

	strb.WriteString(prefix)

	if len(rounds) > 0 {
		strb.WriteString(rounds)
		strb.WriteString(Separator)
	}

	strb.WriteString(salt)
	totalSalt := strb.String()

	var err error

	switch prefix {
	case PrefixCryptSha256:
		crypter := crypt.SHA256.New()
		ret, err = crypter.Generate([]byte(password), []byte(totalSalt))
	case PrefixCryptSha512:
		crypter := crypt.SHA512.New()
		ret, err = crypter.Generate([]byte(password), []byte(totalSalt))
	default:
		panic("unsupported password hash")
	}

	if err != nil {
		panic(err)
	}

	return ret
}

func GetSHA256CredString(username, password string) string {
	saltstr, err := generateSecureRandomString(16)
	if err != nil {
		panic(err)
	}

	hash := shaCrypt(password, "rounds=5000", saltstr, PrefixCryptSha256)

	usernameAndHash := fmt.Sprintf("%s:%s\n", username, hash)

	return usernameAndHash
}

func GetSHA512CredString(username, password string) string {
	saltstr, err := generateSecureRandomString(16)
	if err != nil {
		panic(err)
	}

	hash := shaCrypt(password, "rounds=5000", saltstr, PrefixCryptSha512)

	usernameAndHash := fmt.Sprintf("%s:%s\n", username, hash)

	return usernameAndHash
}

func MakeTempFile(tb testing.TB, filename string) *os.File {
	tb.Helper()
	tempDir := tb.TempDir()
	file, err := os.Create(filepath.Join(tempDir, filename))
	if err != nil {
		panic(err)
	}

	return file
}

// MakeTempFilePath creates an empty temporary file and returns its path.
func MakeTempFilePath(tb testing.TB, filename string) string {
	tb.Helper()

	return filepath.Join(tb.TempDir(), filename)
}

// MakeTempFileWithContent creates a temporary file with the given filename and content, and returns its path.
func MakeTempFileWithContent(tb testing.TB, filename, content string) string {
	tb.Helper()
	tmpfile := MakeTempFile(tb, filename)
	path := tmpfile.Name()
	tmpfile.Close() // Close immediately, we'll write using os.WriteFile
	if err := os.WriteFile(path, []byte(content), 0o0600); err != nil {
		panic(err)
	}

	return path
}

func MakeHtpasswdFileFromString(tb testing.TB, fileContent string) string {
	tb.Helper()
	tempDir := tb.TempDir()
	htpasswdFile, err := os.Create(filepath.Join(tempDir, "htpasswd"))
	if err != nil {
		panic(err)
	}

	content := []byte(fileContent)
	if err := os.WriteFile(htpasswdFile.Name(), content, 0o600); err != nil { //nolint:mnd
		panic(err)
	}

	return htpasswdFile.Name()
}
