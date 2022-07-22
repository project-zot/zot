//go:build !search
// +build !search

package extensions

import (
	"github.com/gorilla/mux"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// EnableSearchExtension ...
func EnableSearchExtension(config *config.Config, log log.Logger, storeController storage.StoreController) {
	log.Warn().Msg("skipping enabling search extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupSearchRoutes ...
func SetupSearchRoutes(conf *config.Config, router *mux.Router,
	storeController storage.StoreController, authFunc mux.MiddlewareFunc, log log.Logger,
) {
	log.Warn().Msg("skipping setting up search routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// GetExtensions...
func GetExtensions(config *config.Config) distext.ExtensionList {
	return distext.ExtensionList{}
}
