//go:build extended
// +build extended

package extensions

import (
	"context"
	goSync "sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/storage"

	"zotregistry.io/zot/pkg/extensions/scrub"
	"zotregistry.io/zot/pkg/extensions/search"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
)

func (e *Extensions) EnableSyncExtension(ctx context.Context, config *config.Config, wg *goSync.WaitGroup,
	storeController storage.StoreController, log log.Logger,
) {
	if config.Extensions.Sync != nil && *config.Extensions.Sync.Enable {
		if err := sync.Run(ctx, *config.Extensions.Sync, storeController, wg, log); err != nil {
			log.Error().Err(err).Msg("Error encountered while setting up syncing")
		}
	} else {
		log.Info().Msg("Sync registries config not provided or disabled, skipping sync")
	}
}

func (e *Extensions) SyncOneImage(config *config.Config, storeController storage.StoreController,
	repoName, reference string, isArtifact bool, log log.Logger,
) error {
	log.Info().Msgf("syncing image %s:%s", repoName, reference)

	err := sync.OneImage(*config.Extensions.Sync, storeController, repoName, reference, isArtifact, log)

	return err
}

func (e *Extensions) EnableMetricsExtension(config *config.Config, log log.Logger, rootDir string) {
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

func (e *Extensions) EnableScrubExtension(config *config.Config, storeController storage.StoreController,
	log log.Logger,
) {
	if config.Extensions.Scrub != nil &&
		config.Extensions.Scrub.Interval != 0 {
		minScrubInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Scrub.Interval < minScrubInterval {
			config.Extensions.Scrub.Interval = minScrubInterval

			log.Warn().Msg("Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := scrub.Run(log, config.Extensions.Scrub.Interval, storeController)
			if err != nil {
				log.Error().Err(err).Msg("error while trying to scrub")
			}
		}()
	} else {
		log.Info().Msg("Scrub config not provided, skipping scrub")
	}
}

func (e *Extensions) SetupMetricsRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	l log.Logger,
) {
	// fork a new zerolog child to avoid data race
	log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
	log.Info().Msg("setting up metrics routes")

	if config.Extensions.Metrics != nil && *config.Extensions.Metrics.Enable {
		router.PathPrefix(config.Extensions.Metrics.Prometheus.Path).
			Handler(promhttp.Handler())
	}
}

func (e *Extensions) EnableSearchExtension(config *config.Config, log log.Logger, rootDir string) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {

		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {

			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll

		}

		go func() {
			err := DownloadTrivyDB(rootDir, log,

				config.Extensions.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()

	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

var DownloadTrivyDB = func(dbDir string, log log.Logger, updateInterval time.Duration) error {
	for {
		log.Info().Msg("updating the CVE database")

		err := cveinfo.UpdateCVEDb(dbDir, log)
		if err != nil {
			return err
		}

		log.Info().Str("DB update completed, next update scheduled after", updateInterval.String()).Msg("")

		time.Sleep(updateInterval)
	}
}

func (e *Extensions) SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	l log.Logger,
) {
	// fork a new zerolog child to avoid data race
	log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
	log.Info().Msg("setting up search routes")

	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		var resConfig search.Config

		if config.Extensions.Search.CVE != nil {
			resConfig = search.GetResolverConfig(log, storeController, true)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, false)
		}

		router.PathPrefix("/query").Methods("GET", "POST", "OPTIONS").
			Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
	}
}
