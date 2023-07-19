package local

import (
	"time"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/cache"
	common "zotregistry.io/zot/pkg/storage/common"
	"zotregistry.io/zot/pkg/storage/imagestore"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

// NewImageStore returns a new image store backed by a file storage.
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, gc bool, gcReferrers bool, gcDelay time.Duration,
	untaggedImageRetentionDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer, linter common.Lint, cacheDriver cache.Cache,
) storageTypes.ImageStore {
	return imagestore.NewImageStore(
		rootDir,
		rootDir,
		gc,
		gcReferrers,
		gcDelay,
		untaggedImageRetentionDelay,
		dedupe,
		commit,
		log,
		metrics,
		linter,
		New(commit),
		cacheDriver,
	)
}
