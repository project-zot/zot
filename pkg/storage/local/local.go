package local

import (
	"zotregistry.dev/zot/pkg/compat"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	common "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/imagestore"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

// NewImageStore returns a new image store backed by a file storage.
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, dedupe, commit bool, log zlog.Logger,
	metrics monitoring.MetricServer, linter common.Lint, cacheDriver storageTypes.Cache,
	compat []compat.MediaCompatibility, recorder events.Recorder,
) storageTypes.ImageStore {
	return imagestore.NewImageStore(
		rootDir,
		rootDir,
		dedupe,
		commit,
		log,
		metrics,
		linter,
		New(commit),
		cacheDriver,
		compat,
		recorder,
	)
}
