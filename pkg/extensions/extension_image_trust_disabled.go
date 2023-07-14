//go:build !imagetrust
// +build !imagetrust

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
)

func IsBuiltWithImageTrustExtension() bool {
	return false
}

func SetupImageTrustRoutes(config *config.Config, router *mux.Router, log log.Logger) {
	log.Warn().Msg("skipping setting up image trust routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

func EnableImageTrustVerification(config *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	log.Warn().Msg("skipping adding to the scheduler a generator for updating signatures validity because " +
		"given binary doesn't include this feature, please build a binary that does so")
}
