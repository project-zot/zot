//go:build !metrics
// +build !metrics

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

// EnableMetricsExtension ...
func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling metrics extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupMetricsRoutes ...
func SetupMetricsRoutes(conf *config.Config, router *mux.Router,
	authnFunc, authzFunc mux.MiddlewareFunc, log log.Logger, metrics monitoring.MetricServer,
) {
	getMetrics := func(w http.ResponseWriter, r *http.Request) {
		m := metrics.ReceiveMetrics()
		zcommon.WriteJSON(w, http.StatusOK, m)
	}

	extRouter := router.PathPrefix("/metrics").Subrouter()
	extRouter.Use(authnFunc)
	extRouter.Use(authzFunc)
	extRouter.Methods("GET").Handler(http.HandlerFunc(getMetrics))
}
