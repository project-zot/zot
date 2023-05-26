//go:build !search
// +build !search

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

type CveInfo interface{}

func GetCVEInfo(config *config.Config, storeController storage.StoreController,
	repoDB metaTypes.RepoDB, log log.Logger,
) CveInfo {
	return nil
}

func IsBuiltWithSearchExtension() bool {
	return false
}

// EnableSearchExtension ...
func EnableSearchExtension(config *config.Config, storeController storage.StoreController,
	repoDB metaTypes.RepoDB, scheduler *scheduler.Scheduler, cveInfo CveInfo, log log.Logger,
) {
	log.Warn().Msg("skipping enabling search extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupSearchRoutes ...
func SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	repoDB metaTypes.RepoDB, cveInfo CveInfo, log log.Logger,
) {
	log.Warn().Msg("skipping setting up search routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
