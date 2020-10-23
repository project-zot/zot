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
	if extension.Search != nil && extension.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if extension.Search.CVE.UpdateInterval < defaultUpdateInterval {
			extension.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval <= 1, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			err := downloadTrivyDB(rootDir, log,
				extension.Search.CVE.UpdateInterval)
			if err != nil {
				panic(err)
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

// SetupRoutes ...
func SetupRoutes(router *mux.Router, rootDir string, imgStore *storage.ImageStore, log log.Logger) {
	log.Info().Msg("setting up extensions routes")
	resConfig := search.GetResolverConfig(rootDir, log, imgStore)
	router.PathPrefix("/query").Methods("GET", "POST").
		Handler(gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig)))
}
