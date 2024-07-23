package s3

import (
	// Add s3 support.
	"github.com/docker/distribution/registry/storage/driver"
	// Load s3 driver.
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage/cache"
	common "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/imagestore"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

// NewObjectStorage returns a new image store backed by cloud storages.
// see https://github.com/docker/docker.github.io/tree/master/registry/storage-drivers
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, cacheDir string, dedupe, commit bool, log zlog.Logger,
	metrics monitoring.MetricServer, linter common.Lint, store driver.StorageDriver, cacheDriver cache.Cache,
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
	)
}
