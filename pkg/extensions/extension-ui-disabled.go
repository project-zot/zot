//go:build !search && !ui_base
// +build !search,!ui_base

package extensions

import (
	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func SetupUIRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	log log.Logger,
) {
	log.Warn().Msg("skipping setting up ui routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
