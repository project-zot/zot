//go:build !apikey
// +build !apikey

package extensions

import (
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
)

func SetupAPIKeyRoutes(config *config.Config, router *mux.Router, repoDB repodb.RepoDB,
	cookieStore sessions.Store, log log.Logger,
) {
	log.Warn().Msg("skipping setting up API key routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
