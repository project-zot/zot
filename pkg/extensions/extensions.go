// +build extended

package extensions

import (
	"github.com/anuvu/zot/pkg/extensions/search"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"

	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"

	"github.com/anuvu/zot/pkg/log"
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

// EnableExtensions ...
func EnableExtensions(extension *ExtensionConfig, log log.Logger, rootDir string) {
	if extension.Search != nil && extension.Search.Enable && extension.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if extension.Search.CVE.UpdateInterval < defaultUpdateInterval {
			extension.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval <= 1, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := downloadTrivyDB(rootDir, log,
				extension.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

// SetupRoutes ...
func SetupRoutes(extension *ExtensionConfig, router *mux.Router, storeController storage.StoreController,
	log log.Logger) {
	log.Info().Msg("setting up extensions routes")

	if extension.Search != nil && extension.Search.Enable {
		var resConfig search.Config

		if extension.Search.CVE != nil {
			resConfig = search.GetResolverConfig(log, storeController, true)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, false)
		}

		router.PathPrefix("/query").Methods("GET", "POST").
			Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
	}
}
