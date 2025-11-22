//go:build !profile

package pprof

import (
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log" //nolint:goimports
)

func SetupPprofRoutes(conf *config.Config, router *mux.Router, authFunc mux.MiddlewareFunc,
	log log.Logger,
) {
	log.Warn().Msg("skipping enabling pprof extension because given zot binary " +
		"doesn't include this feature, please build a binary that does so")
}
