//go:build search

package extensions

import (
	"net/http"
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/search"
	cveinfo "zotregistry.dev/zot/v2/pkg/extensions/search/cve"
	"zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

const scanInterval = 15 * time.Minute

type CveScanner cveinfo.Scanner

func IsBuiltWithSearchExtension() bool {
	return true
}

func GetCveScanner(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) CveScanner {
	// Get extensions config safely
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsCveScanningEnabled() {
		return nil
	}

	cveConfig := extensionsConfig.GetSearchCVEConfig()
	dbRepository := cveConfig.Trivy.DBRepository
	javaDBRepository := cveConfig.Trivy.JavaDBRepository
	overrideTmpDir := cveConfig.Trivy.OverrideTmpDir // defaults to false if not set

	return cveinfo.NewScanner(storeController, metaDB, dbRepository, javaDBRepository, overrideTmpDir, log)
}

func EnableSearchExtension(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, taskScheduler *scheduler.Scheduler, cveScanner CveScanner, log log.Logger,
) {
	// Get extensions config safely
	extensionsConfig := conf.CopyExtensionsConfig()
	if extensionsConfig.IsCveScanningEnabled() {
		cveConfig := extensionsConfig.GetSearchCVEConfig()
		updateInterval := cveConfig.UpdateInterval

		downloadTrivyDB(updateInterval, taskScheduler, cveScanner, log)
		startScanner(scanInterval, metaDB, taskScheduler, cveScanner, log)
	} else {
		log.Info().Msg("cve config not provided, skipping cve-db update")
	}
}

func downloadTrivyDB(interval time.Duration, sch *scheduler.Scheduler, cveScanner CveScanner, log log.Logger) {
	generator := cveinfo.NewDBUpdateTaskGenerator(interval, cveScanner, log)

	log.Info().Msg("submitting cve-db update generator to scheduler")
	sch.SubmitGenerator(generator, interval, scheduler.HighPriority)
}

func startScanner(interval time.Duration, metaDB mTypes.MetaDB, sch *scheduler.Scheduler,
	cveScanner CveScanner, log log.Logger,
) {
	generator := cveinfo.NewScanTaskGenerator(metaDB, cveScanner, log)

	log.Info().Msg("submitting cve-scan generator to scheduler")
	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func SetupSearchRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, cveScanner CveScanner, log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsSearchEnabled() {
		log.Info().Msg("skip enabling the search route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up search routes")

	var cveInfo cveinfo.CveInfo
	if extensionsConfig.IsCveScanningEnabled() {
		cveInfo = cveinfo.NewCVEInfo(cveScanner, metaDB, log)
	} else {
		cveInfo = nil
	}

	resConfig := search.GetResolverConfig(log, storeController, metaDB, cveInfo)

	allowedMethods := zcommon.AllowedMethods(http.MethodGet, http.MethodPost)

	extRouter := router.PathPrefix(constants.ExtSearchPrefix).Subrouter()
	extRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	extRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	extRouter.Use(zcommon.AddExtensionSecurityHeaders())
	extRouter.Methods(allowedMethods...).
		Handler(gqlHandler.NewDefaultServer(gql_generated.NewExecutableSchema(resConfig))) //nolint: staticcheck

	log.Info().Msg("finished setting up search routes")
}
