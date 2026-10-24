package imagestore

import (
	"errors"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"

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
