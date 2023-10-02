//go:build !metrics
// +build !metrics

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
)

// EnableMetricsExtension ...
func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling metrics extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SetupMetricsRoutes ...
func SetupMetricsRoutes(conf *config.Config, router *mux.Router,
	authFunc mux.MiddlewareFunc, log log.Logger, metrics monitoring.MetricServer,
) {
	getMetrics := func(w http.ResponseWriter, r *http.Request) {
		m := metrics.ReceiveMetrics()
		zcommon.WriteJSON(w, http.StatusOK, m)
	}

	router.Use(authFunc)
	router.HandleFunc("/metrics", getMetrics).Methods("GET")
}
