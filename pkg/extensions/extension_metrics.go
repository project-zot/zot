//go:build metrics
// +build metrics

package extensions

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
)

func EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
	if config.Extensions.Metrics != nil &&
		*config.Extensions.Metrics.Enable &&
		config.Extensions.Metrics.Prometheus != nil {
		if config.Extensions.Metrics.Prometheus.Path == "" {
			config.Extensions.Metrics.Prometheus.Path = "/metrics"

			log.Warn().Msg("Prometheus instrumentation Path not set, changing to '/metrics'.")
		}
	} else {
		log.Info().Msg("Metrics config not provided, skipping Metrics config update")
	}
}

func SetupMetricsRoutes(config *config.Config, router *mux.Router,
	authFunc mux.MiddlewareFunc, log log.Logger,
) {
	log.Info().Msg("setting up metrics routes")

	if config.Extensions.Metrics != nil && *config.Extensions.Metrics.Enable {
		extRouter := router.PathPrefix(config.Extensions.Metrics.Prometheus.Path).Subrouter()
		extRouter.Use(authFunc)
		extRouter.Methods("GET").Handler(promhttp.Handler())
	}
}
