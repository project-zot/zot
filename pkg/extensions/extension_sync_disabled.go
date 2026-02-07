//go:build !sync

package extensions

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// EnableSyncExtension ...
func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, sm sync.StreamManager, log log.Logger,
) (*sync.BaseOnDemand, error) {
	log.Warn().Msg("skipping enabling sync extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")

	return nil, nil //nolint: nilnil
}
