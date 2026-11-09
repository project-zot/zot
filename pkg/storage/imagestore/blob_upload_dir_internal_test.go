package imagestore

import (
	"context"
	"errors"
	"testing"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// prunedDirDriver fails EnsureDir as missing a set number of times, as when GC
// removes the empty namespace directory while MkdirAll creates .uploads.
type prunedDirDriver struct {
	storageTypes.Driver
	missing int
	calls   int
}

func (*prunedDirDriver) Name() string {
	return constants.LocalStorageDriverName
}

func (d *prunedDirDriver) EnsureDir(string) error {
	d.calls++
	if d.calls <= d.missing {
		return errclass.MarkMissing(errors.New("namespace directory removed")) //nolint:err113 // test driver
	}

	return nil
}

func TestPrepareBlobUploadDirRetriesAfterNamespacePrune(t *testing.T) {
	drv := &prunedDirDriver{missing: 1}
	store := &ImageStore{rootDir: t.TempDir(), storeDriver: drv, log: log.NewTestLogger()}

	if err := store.prepareBlobUploadDir(context.Background(), "repo"); err != nil {
		t.Fatalf("upload directory was not created after the namespace was pruned: %v", err)
	}

	if drv.calls != 2 {
		t.Fatalf("expected 2 EnsureDir calls, got %d", drv.calls)
	}
}

func TestPrepareBlobUploadDirStopsRetrying(t *testing.T) {
	drv := &prunedDirDriver{missing: maxBlobUploadDirAttempts}
	store := &ImageStore{rootDir: t.TempDir(), storeDriver: drv, log: log.NewTestLogger()}

	err := store.prepareBlobUploadDir(context.Background(), "repo")
	if !errclass.IsStorageObjectMissing(err) {
		t.Fatalf("expected the missing error after %d attempts, got %v", maxBlobUploadDirAttempts, err)
	}

	if drv.calls != maxBlobUploadDirAttempts {
		t.Fatalf("expected %d EnsureDir calls, got %d", maxBlobUploadDirAttempts, drv.calls)
	}
}
