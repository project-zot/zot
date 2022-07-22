//go:build search || ui_base
// +build search ui_base

package extensions

import (
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/mux"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/extensions/search"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func EnableSearchExtension(config *config.Config, log log.Logger, rootDir string) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
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
}

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

func SetupSearchRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	authFunc mux.MiddlewareFunc, l log.Logger,
) {
	// fork a new zerolog child to avoid data race
	log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
	log.Info().Msg("setting up search routes")

	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		var resConfig gql_generated.Config

		if config.Extensions.Search.CVE != nil {
			resConfig = search.GetResolverConfig(log, storeController, true)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, false)
		}

		extRouter := router.PathPrefix(constants.ExtSearchPrefix).Subrouter()
		extRouter.Use(authFunc)
		extRouter.Methods("GET", "POST", "OPTIONS").
			Handler(gqlHandler.NewDefaultServer(gql_generated.NewExecutableSchema(resConfig)))
	}
}

func getExtension(name, url, description string, endpoints []string) distext.Extension {
	return distext.Extension{
		Name:        name,
		URL:         url,
		Description: description,
		Endpoints:   endpoints,
	}
}

func GetExtensions(config *config.Config) distext.ExtensionList {
	extensionList := distext.ExtensionList{}

	extensions := make([]distext.Extension, 0)

	if config.Extensions != nil && config.Extensions.Search != nil {
		endpoints := []string{constants.ExtSearchPrefix}
		searchExt := getExtension("_zot",
			"https://github.com/project-zot/zot/tree/main/pkg/extensions/_zot.md",
			"zot registry extension",
			endpoints)

		extensions = append(extensions, searchExt)
	}

	extensionList.Extensions = extensions

	return extensionList
}
