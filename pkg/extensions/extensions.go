//go:build extended
// +build extended

package extensions

import (
	goSync "sync"
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/search"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// DownloadTrivyDB ...
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
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

func EnableExtensions(config *config.Config, log log.Logger, rootDir string) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := downloadTrivyDB(rootDir, log,
				config.Extensions.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}

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

// EnableSyncExtension enables sync extension.
func EnableSyncExtension(config *config.Config, wg *goSync.WaitGroup,
	storeController storage.StoreController, log log.Logger) {
	if config.Extensions.Sync != nil && *config.Extensions.Sync.Enable {
		if err := sync.Run(*config.Extensions.Sync, storeController, wg, log); err != nil {
			log.Error().Err(err).Msg("Error encountered while setting up syncing")
		}
	} else {
		log.Info().Msg("Sync registries config not provided, skipping sync")
	}
}

// SetupRoutes ...
func SetupRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	l log.Logger) {
	// fork a new zerolog child to avoid data race
	log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
	log.Info().Msg("setting up extensions routes")

	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		var resConfig search.Config

		if config.Extensions.Search.CVE != nil {
			resConfig = search.GetResolverConfig(log, storeController, true)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, false)
		}

		router.PathPrefix("/query").Methods("GET", "POST").
			Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
	}

	if config.Extensions.Metrics != nil && *config.Extensions.Metrics.Enable {
		router.PathPrefix(config.Extensions.Metrics.Prometheus.Path).
			Handler(promhttp.Handler())
	}
}

// SyncOneImage syncs one image.
func SyncOneImage(config *config.Config, storeController storage.StoreController,
	repoName, reference string, isArtifact bool, log log.Logger) error {
	log.Info().Msgf("syncing image %s:%s", repoName, reference)

	err := sync.OneImage(*config.Extensions.Sync, storeController, repoName, reference, isArtifact, log)

	return err
}
