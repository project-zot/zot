//go:build !scrub
// +build !scrub

package extensions

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// EnableScrubExtension ...
func EnableScrubExtension(config *config.Config, log log.Logger, storeController storage.StoreController,
	sch *scheduler.Scheduler,
) {
	log.Warn().Msg("skipping enabling scrub extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
