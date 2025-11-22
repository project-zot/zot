//go:build metrics

package extensions

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	// Get extensions config safely
	extensionsConfig := config.CopyExtensionsConfig()
	if extensionsConfig.IsMetricsEnabled() {
		log.Info().Msg("metrics extension enabled")
	} else {
		log.Info().Msg("metrics config not provided, skipping metrics config update")
	}
}

func SetupMetricsRoutes(config *config.Config, router *mux.Router,
	authnFunc, authzFunc mux.MiddlewareFunc, log log.Logger, metrics monitoring.MetricServer,
) {
	log.Info().Msg("setting up metrics routes")

	// Get extensions config safely
	extensionsConfig := config.CopyExtensionsConfig()
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
