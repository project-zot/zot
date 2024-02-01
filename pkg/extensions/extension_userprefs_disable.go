//go:build !userprefs
// +build !userprefs

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

func IsBuiltWithUserPrefsExtension() bool {
	return false
}

func SetupUserPreferencesRoutes(config *config.Config, router *mux.Router,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	log.Warn().Msg("userprefs extension is disabled because given zot binary doesn't " +
		"include this feature please build a binary that does so")
}
