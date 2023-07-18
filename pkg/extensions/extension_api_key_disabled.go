//go:build !apikey
// +build !apikey

package extensions

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
)

func SetupAPIKeyRoutes(config *config.Config, router *mux.Router, metaDB mTypes.MetaDB,
	cookieStore sessions.Store, log log.Logger,
) {
	log.Warn().Msg("skipping setting up API key routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
