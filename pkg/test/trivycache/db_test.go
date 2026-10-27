//go:build search

package trivycache //nolint:testpackage // tests cover unexported copy and install helpers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallFromCopiesDatabases(t *testing.T) {
	cacheRoot := t.TempDir()
	storeRoot := t.TempDir()

	writeFile(t, filepath.Join(cacheRoot, "_trivy", "db", "trivy.db"), "vuln")
	writeFile(t, filepath.Join(cacheRoot, "_trivy", "java-db", "trivy-java.db"), "java")

	if err := installFrom(cacheRoot, storeRoot, false); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(storeRoot, "_trivy", "java-db", "trivy-java.db")); !os.IsNotExist(err) {
		t.Fatalf("java database copied when includeJava is false: %v", err)
	}

	if err := installFrom(cacheRoot, storeRoot, true); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(storeRoot, "_trivy", "db", "trivy.db"))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "vuln" {
		t.Fatalf("vulnerability database contents %q", got)
	}

	got, err = os.ReadFile(filepath.Join(storeRoot, "_trivy", "java-db", "trivy-java.db"))
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "java" {
		t.Fatalf("java database contents %q", got)
	}
}

func TestInstallFromMissingJavaDatabase(t *testing.T) {
	cacheRoot := t.TempDir()
	storeRoot := t.TempDir()

	writeFile(t, filepath.Join(cacheRoot, "_trivy", "db", "trivy.db"), "vuln")

	err := installFrom(cacheRoot, storeRoot, true)
	if err == nil {
		t.Fatal("expected missing java database to fail")
	}
}

func TestInstallFromJavaDatabaseNotDirectory(t *testing.T) {
	cacheRoot := t.TempDir()
	storeRoot := t.TempDir()

	writeFile(t, filepath.Join(cacheRoot, "_trivy", "db", "trivy.db"), "vuln")
	writeFile(t, filepath.Join(cacheRoot, "_trivy", "java-db"), "not-a-directory")

	err := installFrom(cacheRoot, storeRoot, true)
	if err == nil {
		t.Fatal("expected a file in place of the java database to fail")
	}
}

func TestCopyDirMissingSource(t *testing.T) {
	err := copyDir(t.TempDir(), filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected missing source to fail")
	}
}

func TestStoreDownloadsOnce(t *testing.T) {
	dbs := &dbStore{}
	downloader := &countingDownloader{}

	first, err := dbs.prepare(downloader)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(first)
	})

	second, err := dbs.prepare(downloader)
	if err != nil {
		t.Fatal(err)
	}

	if first != second {
		t.Fatalf("second prepare used %s, want %s", second, first)
	}

	if downloader.calls != 1 {
		t.Fatalf("download calls = %d, want 1", downloader.calls)
	}
}

func TestStoreRemovesDirectoryWhenDownloadFails(t *testing.T) {
	dbs := &dbStore{}
	downloader := &failingDownloader{err: errDownloadFailed}

	_, err := dbs.prepare(downloader)
	if !errors.Is(err, errDownloadFailed) {
		t.Fatalf("got %v", err)
	}

	if _, statErr := os.Stat(downloader.root); !os.IsNotExist(statErr) {
		t.Fatalf("failed download left %s: %v", downloader.root, statErr)
	}
}

func TestStoreRemoveDeletesDirectory(t *testing.T) {
	dbs := &dbStore{}
	root, err := dbs.prepare(&countingDownloader{})
	if err != nil {
		t.Fatal(err)
	}

	dbs.remove()

	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup left %s: %v", root, statErr)
	}
}

func TestStoreRequiresDownloader(t *testing.T) {
	dbs := &dbStore{}

	_, err := dbs.prepare(nil)
	if !errors.Is(err, errNilDownloader) {
		t.Fatalf("got %v", err)
	}

	_, err = dbs.prepare(&countingDownloader{})
	if !errors.Is(err, errNilDownloader) {
		t.Fatalf("second prepare got %v", err)
	}
}

var errDownloadFailed = errors.New("download failed") //nolint:gochecknoglobals

type failingDownloader struct {
	root string
	err  error
}

func (d *failingDownloader) Download(cacheRoot string) error {
	d.root = cacheRoot

	return d.err
}

type countingDownloader struct {
	calls int
}

func (d *countingDownloader) Download(cacheRoot string) error {
	d.calls++

	return os.WriteFile(filepath.Join(cacheRoot, "marker"), []byte("ok"), 0o600)
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
