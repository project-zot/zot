package imagestore

import (
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

func TestOversizedUploadIDDoesNotRegisterSession(t *testing.T) {
	root := t.TempDir()
	store := &ImageStore{rootDir: root, storeDriver: &missingUploadDriver{}}
	uuid := strings.Repeat("x", maxUploadSessionIDLength+1)

	if err := store.DeleteBlobUpload("repo", uuid); !errors.Is(err, zerr.ErrUploadNotFound) {
		t.Fatalf("DeleteBlobUpload error = %v, want ErrUploadNotFound", err)
	}

	store.uploads.lock.Lock()
	_, exists := store.uploads.sessions[store.BlobUploadPath("repo", uuid)]
	store.uploads.lock.Unlock()
	if exists {
		t.Fatal("oversized upload ID was retained in the registry")
	}
}
