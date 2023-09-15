//go:build search
// +build search

package extensions

import (
	"net/http"
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/search"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

const scanInterval = 15 * time.Minute

type CveScanner cveinfo.Scanner

func IsBuiltWithSearchExtension() bool {
	return true
}

func GetCveScanner(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) CveScanner {
	if !conf.IsCveScanningEnabled() {
		return nil
	}

	dbRepository := conf.Extensions.Search.CVE.Trivy.DBRepository
	javaDBRepository := conf.Extensions.Search.CVE.Trivy.JavaDBRepository

	return cveinfo.NewScanner(storeController, metaDB, dbRepository, javaDBRepository, log)
}

func EnableSearchExtension(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, taskScheduler *scheduler.Scheduler, cveScanner CveScanner, log log.Logger,
) {
	if conf.IsCveScanningEnabled() {
		updateInterval := conf.Extensions.Search.CVE.UpdateInterval

		downloadTrivyDB(updateInterval, taskScheduler, cveScanner, log)
		startScanner(scanInterval, metaDB, taskScheduler, cveScanner, log)
	} else {
		log.Info().Msg("CVE config not provided, skipping CVE update")
	}
}

func downloadTrivyDB(interval time.Duration, sch *scheduler.Scheduler, cveScanner CveScanner, log log.Logger) {
	generator := cveinfo.NewDBUpdateTaskGenerator(interval, cveScanner, log)

	log.Info().Msg("Submitting CVE DB update scheduler")
	sch.SubmitGenerator(generator, interval, scheduler.HighPriority)
}

func startScanner(interval time.Duration, metaDB mTypes.MetaDB, sch *scheduler.Scheduler,
	cveScanner CveScanner, log log.Logger,
) {
	generator := cveinfo.NewScanTaskGenerator(metaDB, cveScanner, log)

	log.Info().Msg("Submitting CVE scan scheduler")
	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func SetupSearchRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, cveScanner CveScanner, log log.Logger,
) {
	if !conf.IsSearchEnabled() {
		log.Info().Msg("skip enabling the search route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up search routes")

	var cveInfo cveinfo.CveInfo
	if conf.IsCveScanningEnabled() {
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
		Handler(gqlHandler.NewDefaultServer(gql_generated.NewExecutableSchema(resConfig)))

	log.Info().Msg("finished setting up search routes")
}
