//go:build !mcp
// +build !mcp

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

func IsBuiltWithMCPExtension() bool {
	return false
}

func SetupMCPRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	log.Warn().Msg("skipping setting up MCP routes because given zot binary " +
		"doesn't include this feature, please build a binary that does so")
}
