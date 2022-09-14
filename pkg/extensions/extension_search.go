//go:build search
// +build search

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
	"zotregistry.io/zot/pkg/meta"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

// We need this object to be a singleton as read/writes in the CVE DB may
// occur at any time via DB downloads as well as during scanning.
// The library doesn't seem to handle concurrency very well internally.
var cveInfo cveinfo.CveInfo //nolint:gochecknoglobals

func EnableSearchExtension(config *config.Config, storeController storage.StoreController,
	repoDB repodb.RepoDB, log log.Logger,
) {
	if config.Extensions.Search != nil && *config.Extensions.Search.Enable && config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval

			log.Warn().Msg("CVE update interval set to too-short interval < 2h, changing update duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
		}

		dbRepository := ""
		if config.Extensions.Search.CVE.Trivy != nil {
			dbRepository = config.Extensions.Search.CVE.Trivy.DBRepository
		}

		cveInfo = cveinfo.NewCVEInfo(storeController, repoDB, dbRepository, log)

		go func() {
			err := downloadTrivyDB(log, config.Extensions.Search.CVE.UpdateInterval)
			if err != nil {
				log.Error().Err(err).Msg("error while downloading TrivyDB")
			}
		}()
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

func downloadTrivyDB(log log.Logger, updateInterval time.Duration) error {
	for {
		log.Info().Msg("updating the CVE database")

		err := cveInfo.UpdateDB()
		if err != nil {
			return err
		}

		log.Info().Str("DB update completed, next update scheduled after", updateInterval.String()).Msg("")

		time.Sleep(updateInterval)
	}
}

func SetupSearchRoutes(config *config.Config,
	router *mux.Router,
	storeController storage.StoreController,
	repoDB repodb.RepoDB,
	metadata *meta.MetadataStore,
	log log.Logger,
) {
	log.Info().Msg("setting up search routes")

	if config.Extensions.Search != nil && *config.Extensions.Search.Enable {
		var resConfig gql_generated.Config

		if config.Extensions.Search.CVE != nil {
			// cveinfo should already be initialized by this time
			// as EnableSearchExtension is supposed to be called earlier, but let's be sure
			if cveInfo == nil {
				dbRepository := ""

				if config.Extensions.Search.CVE.Trivy != nil {
					dbRepository = config.Extensions.Search.CVE.Trivy.DBRepository
				}

				cveInfo = cveinfo.NewCVEInfo(storeController, repoDB, dbRepository, log)
			}

			resConfig = search.GetResolverConfig(log, storeController, repoDB, cveInfo, metadata)
		} else {
			resConfig = search.GetResolverConfig(log, storeController, repoDB, nil, metadata)
		}

		graphqlPrefix := router.PathPrefix(constants.FullSearchPrefix).Methods("OPTIONS", "GET", "POST")
		graphqlPrefix.Handler(gqlHandler.NewDefaultServer(gql_generated.NewExecutableSchema(resConfig)))
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
		endpoints := []string{constants.FullSearchPrefix}
		searchExt := getExtension("_zot",
			"https://github.com/project-zot/zot/blob/"+config.ReleaseTag+"/pkg/extensions/_zot.md",
			"zot registry extensions",
			endpoints)

		extensions = append(extensions, searchExt)
	}

	extensionList.Extensions = extensions

	return extensionList
}
