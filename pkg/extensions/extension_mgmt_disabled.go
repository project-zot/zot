//go:build !mgmt
// +build !mgmt

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
)

func IsBuiltWithMGMTExtension() bool {
	return false
}

func SetupMgmtRoutes(config *config.Config, router *mux.Router, log log.Logger) {
	log.Warn().Msg("skipping setting up mgmt routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
