//go:build !quota

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

func SetupQuotaRoutes(
	conf *config.Config,
	router *mux.Router,
	metaDB mTypes.MetaDB,
	log log.Logger,
) {
}
