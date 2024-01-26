//go:build !sync
// +build !sync

package extensions

import (
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/sync"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
)

// EnableSyncExtension ...
func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, log log.Logger,
) (*sync.BaseOnDemand, error) {
	log.Warn().Msg("skipping enabling sync extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")

	return nil, nil //nolint: nilnil
}
