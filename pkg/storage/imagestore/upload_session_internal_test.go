package imagestore

import (
	"context"
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type missingUploadDriver struct {
	storageTypes.Driver
}

func (*missingUploadDriver) Name() string {
	return constants.LocalStorageDriverName
}

type successfulDeleteDriver struct {
	storageTypes.Driver
	deleted bool
}

func (*successfulDeleteDriver) Name() string {
	return constants.LocalStorageDriverName
}

type successfulDeleteWriter struct {
	driver *successfulDeleteDriver
}

func (d *successfulDeleteDriver) Writer(string, bool) (driver.FileWriter, error) {
	return &successfulDeleteWriter{driver: d}, nil
}

func (d *successfulDeleteDriver) Stat(string) (driver.FileInfo, error) {
	if d.deleted {
		return nil, errclass.MarkMissing(errors.New("missing upload")) //nolint:err113 // test driver
	}

	return nil, nil //nolint:nilnil // test driver
}

func (w *successfulDeleteWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (w *successfulDeleteWriter) Close() error {
	return nil
}

func (w *successfulDeleteWriter) Size() int64 {
	return 0
}

func (w *successfulDeleteWriter) Cancel(context.Context) error {
	w.driver.deleted = true

	return nil
}

func (w *successfulDeleteWriter) Commit(context.Context) error {
	return nil
}

func (d *missingUploadDriver) Stat(string) (driver.FileInfo, error) {
	return nil, errclass.MarkMissing(errors.New("missing upload")) //nolint:err113 // test driver
}

func TestCleanupUploadSessionIfMissingRemovesEntry(t *testing.T) {
	root := t.TempDir()
	store := &ImageStore{rootDir: root, storeDriver: &missingUploadDriver{}}
	src := path.Join(root, "repo", constants.BlobUploadDir, "missing")
	session := store.uploads.get(src)

	store.cleanupUploadSessionIfMissing(src, session)

	store.uploads.lock.Lock()
	_, exists := store.uploads.sessions[src]
	store.uploads.lock.Unlock()
	if exists {
		t.Fatal("missing upload session was retained in the registry")
	}
}

func TestInvalidUploadIDDoesNotRegisterSession(t *testing.T) {
	root := t.TempDir()
	store := &ImageStore{rootDir: root, storeDriver: &missingUploadDriver{}}
	uuids := []string{
		strings.Repeat("x", maxUploadSessionIDLength+1),
		"missing\x00one",
	}

	for _, uuid := range uuids {
		if err := store.DeleteBlobUpload("repo", uuid); !errors.Is(err, zerr.ErrUploadNotFound) {
			t.Fatalf("DeleteBlobUpload(%q) error = %v, want ErrUploadNotFound", uuid, err)
		}

		store.uploads.lock.Lock()
		_, exists := store.uploads.sessions[store.BlobUploadPath("repo", uuid)]
		store.uploads.lock.Unlock()
		if exists {
			t.Fatalf("invalid upload ID %q was retained in the registry", uuid)
		}
	}
}

func TestOverlongRepositoryPathDoesNotRegisterSession(t *testing.T) {
	root := t.TempDir()
	store := &ImageStore{rootDir: root, storeDriver: &missingUploadDriver{}}
	repo := strings.Repeat("r", maxStoragePathComponentLength+1)
	uuid := "upload"

	if err := store.DeleteBlobUpload(repo, uuid); !errors.Is(err, zerr.ErrUploadNotFound) {
		t.Fatalf("DeleteBlobUpload error = %v, want ErrUploadNotFound", err)
	}

	src := store.BlobUploadPath(repo, uuid)
	store.uploads.lock.Lock()
	_, exists := store.uploads.sessions[src]
	store.uploads.lock.Unlock()
	if exists {
		t.Fatal("overlong repository path was retained in the registry")
	}
}

func TestOverlongUploadPathDoesNotRegisterSession(t *testing.T) {
	root := t.TempDir()
	store := &ImageStore{rootDir: root, storeDriver: &missingUploadDriver{}}
	component := strings.Repeat("r", 240)
	repo := strings.TrimSuffix(strings.Repeat(component+"/", 18), "/")
	uuid := "upload"

	if err := store.DeleteBlobUpload(repo, uuid); !errors.Is(err, zerr.ErrUploadNotFound) {
		t.Fatalf("DeleteBlobUpload error = %v, want ErrUploadNotFound", err)
	}

	src := store.BlobUploadPath(repo, uuid)
	store.uploads.lock.Lock()
	_, exists := store.uploads.sessions[src]
	store.uploads.lock.Unlock()
	if exists {
		t.Fatal("overlong upload path was retained in the registry")
	}
}

func TestSuccessfulIdleDeleteRemovesSession(t *testing.T) {
	driver := &successfulDeleteDriver{}
	store := &ImageStore{rootDir: t.TempDir(), storeDriver: driver}
	src := store.BlobUploadPath("repo", "upload")
	store.uploads.get(src)

	deleted, err := store.DeleteBlobUploadIfIdle("repo", "upload")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted || !driver.deleted {
		t.Fatalf("idle delete result = (%t, %t), want (true, true)", deleted, driver.deleted)
	}

	store.uploads.lock.Lock()
	_, exists := store.uploads.sessions[src]
	store.uploads.lock.Unlock()
	if exists {
		t.Fatal("successfully deleted upload session was retained in the registry")
	}
}
