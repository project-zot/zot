package imagestore

import (
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// What the external tests of this package need and cannot reach through storageTypes.ImageStore.

// BlobLifecycle lets external tests wrap a store's blob lifecycle to inject failures.
type BlobLifecycle = blobLifecycle

// WrapLifecycle replaces the blob lifecycle of store, created by NewImageStore, with wrap's result.
func WrapLifecycle(store storageTypes.ImageStore, wrap func(BlobLifecycle) BlobLifecycle) {
	imgStore, _ := store.(*ImageStore)
	imgStore.lifecycle = wrap(imgStore.lifecycle)
}

// UpgradeToGlobalBlobstore runs the upgrade NewImageStore runs, so a test can run it again
// after changing the store.
func UpgradeToGlobalBlobstore(store storageTypes.ImageStore) error {
	imgStore, _ := store.(*ImageStore)

	return imgStore.upgradeToGlobalBlobstore()
}
