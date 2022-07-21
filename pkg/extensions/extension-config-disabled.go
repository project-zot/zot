//go:build !config
// +build !config

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func SetupConfigRoutes(config *config.Config, configPath string, router *mux.Router,
	storeController storage.StoreController, log log.Logger,
) {
	log.Warn().Msg("skipping enabling config extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
