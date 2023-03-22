//go:build !userprefs
// +build !userprefs

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

func SetupUserPreferencesRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	repoDB repodb.RepoDB, cveInfo CveInfo, log log.Logger,
) {
	log.Warn().Msg("userprefs extension is disabled because given zot binary doesn't" +
		"include this feature please build a binary that does so")
}
