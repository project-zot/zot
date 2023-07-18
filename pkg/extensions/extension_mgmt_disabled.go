//go:build !mgmt
// +build !mgmt

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

func IsBuiltWithMGMTExtension() bool {
	return false
}

func SetupMgmtRoutes(config *config.Config, router *mux.Router, log log.Logger) {
	log.Warn().Msg("skipping setting up mgmt routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

func EnablePeriodicSignaturesVerification(config *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	log.Warn().Msg("skipping adding to the scheduler a generator for updating signatures validity because " +
		"given binary doesn't include this feature, please build a binary that does so")
}
