//go:build !userprefs
// +build !userprefs

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

func IsBuiltWithUserPrefsExtension() bool {
	return false
}

func SetupUserPreferencesRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB metaTypes.MetaDB, cveInfo CveInfo, log log.Logger,
) {
	log.Warn().Msg("userprefs extension is disabled because given zot binary doesn't" +
		"include this feature please build a binary that does so")
}
