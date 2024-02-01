//go:build metrics
// +build metrics

package extensions

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
)

func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	if config.IsMetricsEnabled() &&
		config.Extensions.Metrics.Prometheus != nil {
		if config.Extensions.Metrics.Prometheus.Path == "" {
			config.Extensions.Metrics.Prometheus.Path = "/metrics"

			log.Warn().Msg("prometheus instrumentation path not set, changing to '/metrics'.")
		}
	} else {
		log.Info().Msg("metrics config not provided, skipping metrics config update")
	}
}

func SetupMetricsRoutes(config *config.Config, router *mux.Router,
	authnFunc, authzFunc mux.MiddlewareFunc, log log.Logger, metrics monitoring.MetricServer,
) {
	log.Info().Msg("setting up metrics routes")

	if config.IsMetricsEnabled() {
		extRouter := router.PathPrefix(config.Extensions.Metrics.Prometheus.Path).Subrouter()
		extRouter.Use(authnFunc)
		extRouter.Use(authzFunc)
		extRouter.Methods("GET").Handler(promhttp.Handler())
	}
}
