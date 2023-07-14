//go:build !metrics
// +build !metrics

package extensions

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
)

// EnableMetricsExtension ...
func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling metrics extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupMetricsRoutes ...
func SetupMetricsRoutes(conf *config.Config, router *mux.Router,
	authFunc mux.MiddlewareFunc, log log.Logger,
) {
	log.Warn().Msg("skipping setting up metrics routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
