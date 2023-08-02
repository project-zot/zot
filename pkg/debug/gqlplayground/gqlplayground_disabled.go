//go:build !debug
// +build !debug

package debug

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// SetupGQLPlaygroundRoutes ...
func SetupGQLPlaygroundRoutes(router *mux.Router,
	storeController storage.StoreController, log log.Logger,
) {
	log.Warn().Msg("skipping enabling graphql playground extension because given zot binary " +
		"doesn't include this feature, please build a binary that does so")
}
