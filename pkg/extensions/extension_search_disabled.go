//go:build !search
// +build !search

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
)

type CveScanner interface{}

func GetCveScanner(config *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) CveScanner {
	return nil
}

func IsBuiltWithSearchExtension() bool {
	return false
}

// EnableSearchExtension ...
func EnableSearchExtension(config *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, scheduler *scheduler.Scheduler, cveScanner CveScanner, log log.Logger,
) {
	log.Warn().Msg("skipping enabling search extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupSearchRoutes ...
func SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, cveScanner CveScanner, log log.Logger,
) {
	log.Warn().Msg("skipping setting up search routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
