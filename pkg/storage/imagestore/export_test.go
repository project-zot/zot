package imagestore

import (
	"time"

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

// SetLinkerClaimWait shortens how long a push to a remote store waits for a reclaim claim to clear.
func SetLinkerClaimWait(store storageTypes.ImageStore, wait time.Duration) {
	imgStore, _ := store.(*ImageStore)
	lifecycle, _ := imgStore.lifecycle.(*remoteSharedBlobLifecycle)
	lifecycle.claimWait = wait
}

// FinishDedupeWalk marks the startup dedupe walk done, as its OnRunComplete does, for tests that
// run single digests through RunDedupeForDigest instead of the whole walk.
func FinishDedupeWalk(store storageTypes.ImageStore) {
	imgStore, _ := store.(*ImageStore)
	imgStore.dedupeRebuildDone.Store(true)
	imgStore.blobRefsRebuilt.Store(true)
}
