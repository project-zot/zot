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
	// Get extensions config safely
	extensionsConfig := config.GetExtensionsConfig()
	if extensionsConfig.IsMetricsEnabled() {
		prometheusConfig := extensionsConfig.GetMetricsPrometheusConfig()
		if prometheusConfig != nil && prometheusConfig.Path == "" {
			// Note: This modifies the config during initialization
			extensionsConfig.SetMetricsPrometheusPath("/metrics")

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

	// Get extensions config safely
	extensionsConfig := config.GetExtensionsConfig()
	if extensionsConfig.IsMetricsEnabled() {
		prometheusConfig := extensionsConfig.GetMetricsPrometheusConfig()
		if prometheusConfig != nil {
			extRouter := router.PathPrefix(prometheusConfig.Path).Subrouter()
			extRouter.Use(authnFunc)
			extRouter.Use(authzFunc)
			extRouter.Methods("GET").Handler(promhttp.Handler())
		}
	}
}
