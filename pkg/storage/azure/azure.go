package azure

import (
	// Add azure support.
	"github.com/distribution/distribution/v3/registry/storage/driver"
	// Load azure driver.
	_ "github.com/distribution/distribution/v3/registry/storage/driver/azure"

	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// NewImageStore returns a new image store backed by Azure Blob Storage.
// see https://github.com/distribution/distribution/tree/main/registry/storage/driver/azure
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, cacheDir string, dedupe, commit bool, log zlog.Logger,
	metrics monitoring.MetricServer, linter common.Lint, store driver.StorageDriver,
	cacheDriver storageTypes.Cache, compat []compat.MediaCompatibility, recorder events.Recorder,
) storageTypes.ImageStore {
	return imagestore.NewImageStore(
		rootDir,
		cacheDir,
		dedupe,
		commit,
		log,
		metrics,
		linter,
		New(store),
		cacheDriver,
		compat,
		recorder,
	)
}
