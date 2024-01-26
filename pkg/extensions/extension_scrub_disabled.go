//go:build !scrub
// +build !scrub

package extensions

import (
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
)

// EnableScrubExtension ...
func EnableScrubExtension(config *config.Config, log log.Logger, storeController storage.StoreController,
	sch *scheduler.Scheduler,
) {
	log.Warn().Msg("skipping enabling scrub extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
