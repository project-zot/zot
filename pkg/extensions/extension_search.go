//go:build search

package extensions

import (
	"net/http"
	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gorilla/mux"
	"github.com/vektah/gqlparser/v2/ast"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/extensions/search"
	cveinfo "zotregistry.dev/zot/v2/pkg/extensions/search/cve"
	"zotregistry.dev/zot/v2/pkg/extensions/search/gql_generated"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

const scanInterval = 15 * time.Minute

const (
	// searchParserTokenLimit bounds the number of lexical tokens a single GraphQL document may
	// contain, enforced during parsing, before the (potentially superlinear) field-merge validation
	// that follows it ever runs. The richest query zot's own CLI/UI issue (GlobalSearch, nested
	// Images/Manifests/Layers) is well under 300 tokens; 2000 leaves headroom for hand-written
	// queries while keeping a document built from many repeated/aliased selections cheap to reject.
	searchParserTokenLimit = 2000
	// searchComplexityLimit bounds total query complexity (by default, gqlgen counts each requested
	// field as 1, summed recursively), so a document with many distinct aliased root fields can't
	// dispatch an unbounded number of resolvers - each of which may hit the CVE scanner or metadb -
	// concurrently. The richest known real query costs on the order of 30; 500 leaves ample headroom.
	searchComplexityLimit = 500
	// searchQueryCacheSize bounds the query cache's entry count. gqlgen keys each entry on the raw
	// query text and stores the parsed document as the value, so a single entry can retain a
	// document close to the full MaxSearchBodySize (a valid, low-token document can still pack long
	// string literals into most of that body) - a large entry count would let an unauthenticated
	// client hold many distinct such documents in memory at once. 64 keeps the worst case in the
	// tens of MiB while still caching the handful of distinct queries zot's own CLI/UI issue.
	searchQueryCacheSize = 64
)

type CveScanner cveinfo.Scanner

func IsBuiltWithSearchExtension() bool {
	return true
}

func GetCveScanner(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, eventRecorder events.Recorder, log log.Logger,
) CveScanner {
	// Get extensions config safely
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsCveScanningEnabled() {
		return nil
	}

	cveConfig := extensionsConfig.GetSearchCVEConfig()

	// WithEventRecorder is safe to apply even when eventRecorder is nil: the scanner
	// only publishes events when eventRecorder is non-nil.
	return cveinfo.NewScanner(storeController, metaDB, cveConfig, log, cveinfo.WithEventRecorder(eventRecorder))
}

func EnableSearchExtension(conf *config.Config, storeController storage.StoreController,
	metaDB mTypes.MetaDB, taskScheduler *scheduler.Scheduler, cveScanner CveScanner,
	log log.Logger,
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
	extRouter.Use(zcommon.MaxBodySizeMiddleware(constants.MaxSearchBodySize))
	extRouter.Methods(allowedMethods...).
		Handler(newSearchGQLHandler(resConfig))

	log.Info().Msg("finished setting up search routes")
}

// newSearchGQLHandler builds the GraphQL server by hand instead of using gqlgen's
// NewDefaultServer, which the library itself documents as "not suitable for production use":
// it wires up every transport (including websocket, which zot's route never allows through
// allowedMethods above) and applies no budget on parser tokens, query complexity, or request
// body size, so a small valid document with many repeated/aliased selections can force
// superlinear parsing/validation work and dispatch an attacker-chosen number of resolvers -
// some of which reach the CVE scanner - before a single error is returned. This route has no
// authentication in the default container config, so those budgets are the only gate.
func newSearchGQLHandler(resConfig gql_generated.Config) *gqlHandler.Server {
	srv := gqlHandler.New(gql_generated.NewExecutableSchema(resConfig))

	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})

	srv.SetQueryCache(lru.New[*ast.QueryDocument](searchQueryCacheSize))
	srv.SetParserTokenLimit(searchParserTokenLimit)

	srv.Use(extension.Introspection{})
	srv.Use(extension.FixedComplexityLimit(searchComplexityLimit))

	return srv
}
