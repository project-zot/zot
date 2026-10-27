//go:build search

// Package trivycache copies Trivy databases downloaded once per test process into a
// store root. The caller supplies the downloader, so this package does not import
// the scanner.
package trivycache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// FreshUpdateLimit is long enough for a metadata read of a database that was
// just downloaded, and shorter than a real pull of either database.
const FreshUpdateLimit = 30 * time.Second

var (
	errJavaDBMissing = errors.New("cached trivy java database is missing")     //nolint:gochecknoglobals
	errNilDownloader = errors.New("trivy test database downloader is not set") //nolint:gochecknoglobals
)

// Downloader fills cacheRoot with both Trivy databases.
type Downloader interface {
	Download(cacheRoot string) error
}

// Cache copies databases from one process-wide download into a store root.
type Cache struct {
	downloader Downloader
	store      *dbStore
}

// New returns a cache that copies databases downloaded by downloader.
// Caches in one process share a single download.
func New(downloader Downloader) *Cache {
	return &Cache{downloader: downloader, store: &sharedStore}
}

// Cleanup removes the process-wide database directory.
// Call it from TestMain after the tests finish. Tests in the same process still need that directory.
func Cleanup() {
	sharedStore.remove()
}

// Install copies a vulnerability database downloaded once per test process into
// storeRoot/_trivy. When includeJava is set, the Java database is copied too.
func Install(t *testing.T, storeRoot string, includeJava bool, downloader Downloader) {
	t.Helper()
	New(downloader).Install(t, storeRoot, includeJava)
}

// Install copies the vulnerability database into storeRoot/_trivy.
// When includeJava is set, the Java database is copied too.
func (cache *Cache) Install(t *testing.T, storeRoot string, includeJava bool) {
	t.Helper()

	cacheRoot, err := cache.store.prepare(cache.downloader)
	if err != nil {
		t.Fatalf("download trivy test databases: %v", err)
	}

	if err := installFrom(cacheRoot, storeRoot, includeJava); err != nil {
		t.Fatalf("install cached trivy database: %v", err)
	}
}

// sharedStore holds the one downloaded database for this process.
var sharedStore dbStore //nolint:gochecknoglobals

type dbStore struct {
	mu  sync.Mutex
	dir string
	err error
}

func (dbs *dbStore) prepare(downloader Downloader) (string, error) {
	dbs.mu.Lock()
	defer dbs.mu.Unlock()

	if dbs.dir != "" || dbs.err != nil {
		return dbs.dir, dbs.err
	}

	if downloader == nil {
		dbs.err = errNilDownloader

		return "", dbs.err
	}

	root, err := os.MkdirTemp("", "trivy-zot-test-db-")
	if err != nil {
		dbs.err = err

		return "", err
	}

	if err := downloader.Download(root); err != nil {
		_ = os.RemoveAll(root)
		dbs.err = err

		return "", err
	}

	dbs.dir = root

	return root, nil
}

func (dbs *dbStore) remove() {
	dbs.mu.Lock()
	defer dbs.mu.Unlock()

	if dbs.dir == "" {
		return
	}

	_ = os.RemoveAll(dbs.dir)
	dbs.dir = ""
}

func installFrom(cacheRoot, storeRoot string, includeJava bool) error {
	if err := copyDir(filepath.Join(storeRoot, "_trivy", "db"), filepath.Join(cacheRoot, "_trivy", "db")); err != nil {
		return fmt.Errorf("install cached trivy vulnerability database: %w", err)
	}

	if !includeJava {
		return nil
	}

	javaSrc := filepath.Join(cacheRoot, "_trivy", "java-db")

	info, err := os.Stat(javaSrc)
	if err != nil {
		return fmt.Errorf("stat trivy java database: %w", err)
	}

	if !info.IsDir() {
		return errJavaDBMissing
	}

	if err := copyDir(filepath.Join(storeRoot, "_trivy", "java-db"), javaSrc); err != nil {
		return fmt.Errorf("install cached trivy java database: %w", err)
	}

	return nil
}

func copyDir(dst, src string) error {
	return filepath.WalkDir(src, func(srcPath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, srcPath)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		return copyFile(target, srcPath)
	})
}

func copyFile(dst, src string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		_ = source.Close()

		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		_ = source.Close()

		return err
	}

	_, copyErr := io.Copy(out, source)
	closeInErr := source.Close()
	closeOutErr := out.Close()

	if copyErr != nil {
		return copyErr
	}

	if closeInErr != nil {
		return closeInErr
	}

	return closeOutErr
}
