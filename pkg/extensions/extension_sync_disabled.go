//go:build !sync
// +build !sync

package extensions

import (
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

// EnableSyncExtension ...
func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, log log.Logger,
) (*sync.BaseOnDemand, error) {
	log.Warn().Msg("skipping enabling sync extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")

	return nil, nil //nolint: nilnil
}
