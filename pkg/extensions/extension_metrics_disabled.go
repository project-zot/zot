//go:build !metrics
// +build !metrics

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
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

	router.Use(authnFunc)
	router.Use(authzFunc)
	router.HandleFunc("/metrics", getMetrics).Methods("GET")
}
