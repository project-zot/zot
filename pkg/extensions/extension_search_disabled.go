//go:build !search && !ui_base
// +build !search,!ui_base

package extensions

import (
	"github.com/gorilla/mux"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
)

// EnableSearchExtension ...
func EnableSearchExtension(config *config.Config, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling search extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupSearchRoutes ...
func SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	repoDB repodb.RepoDB, authFunc mux.MiddlewareFunc, log log.Logger,
) {
	log.Warn().Msg("skipping setting up search routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// GetExtensions...
func GetExtensions(config *config.Config) distext.ExtensionList {
	return distext.ExtensionList{}
}
