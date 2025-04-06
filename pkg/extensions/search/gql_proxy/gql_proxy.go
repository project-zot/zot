package gqlproxy

import (
	"net/http"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/log"
)

type GqlScaleOutHandlerFunc func(*config.Config, log.Logger, map[string]string, http.ResponseWriter, *http.Request)

// Returns a wrapped handler that can handle request proxying for GQL
// queries when running in cluster mode without shared storage (each instance has its own metadata).
// Requests are only proxied in local cluster mode as in this mode, each instance holds only the
// metadata for the images that it serves, however, in shared storage mode,
// all the instances have access to all the metadata so any can respond.
func GqlProxyRequestHandler(
	config *config.Config,
	log log.Logger,
	gqlSchema *ast.Schema,
) func(handler http.Handler) http.Handler {
	// This map stores the handler needed for each supported GQL operation in the application.
	// There are 2 main buckets of handlers:
	// 1. generic handlers - these cater to general use-cases such as fan-out and aggregate and hash-based proxying.
	// 2. specific handlers - these cater to specific proxy behaviour that certain operations require.
	// Most cases would use generic handlers while a few select cases would make use of the specific handlers.
	// When a GQL query is updated or a new one added, a change may be required here depending on the type of handler
	// that the operation needs to use.
	// Unsupported operations:
	// 1. CVEDiffListForImages - unsupported as needs metadata for both images on the handling server
	// 2. DerivedImageList - unsupported as needs metadata for argument image on the handling server
	// 3. BaseImageList - unsupported as needs metadata for argument image on the handling server
	// 4. StarredRepos - involves user prefs
	// 5. BookmarkedRepos - involves user prefs
	proxyFunctionalityMap := map[string]GqlScaleOutHandlerFunc{
		"GlobalSearch":            fanOutGqlHandler,
		"ImageList":               repoProxyOnceGqlHandler,
		"ExpandedRepoInfo":        repoProxyOnceGqlHandler,
		"CVEListForImage":         imageWithTagOrDigestProxyOnceGqlHandler,
		"ImageListForCVE":         fanOutGqlHandler,
		"ImageListWithCVEFixed":   repoAliasImageProxyOnceGqlHandler,
		"ImageListForDigest":      fanOutGqlHandler,
		"RepoListWithNewestImage": fanOutGqlHandler,
		"Image":                   imageWithOnlyTagProxyOnceGqlHandler,
		"Referrers":               repoProxyOnceGqlHandler,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// If not running in cluster mode, no op.
			if !config.IsClusteringEnabled() {
				next.ServeHTTP(response, request)

				return
			}
			// If in cluster mode, but using shared-storage, no op.
			if config.IsSharedStorageEnabled() {
				next.ServeHTTP(response, request)

				return
			}

			// If the request has already been proxied, don't re-proxy.
			if request.Header.Get(constants.ScaleOutHopCountHeader) != "" {
				next.ServeHTTP(response, request)

				return
			}

			query := request.URL.Query().Get("query")

			// Load the query using gqlparser.
			// This helps to read the Operation correctly which is in turn used to
			// dynamically hand-off the processing to the appropriate handler.
			processedGql, errList := gqlparser.LoadQuery(gqlSchema, query)

			if len(errList) != 0 {
				for _, err := range errList {
					log.Error().Str("query", query).Err(err).Msg(err.Message)
				}

				http.Error(response, "failed to process GQL request", http.StatusBadRequest)

				return
			}

			// Look at the first operation in the query.
			operation := ""
			gqlQueryArgs := map[string]string{}

			// Currently, only 1 operation is supported.
			// The last operation will be the one used for further processing.
			for _, op := range processedGql.Operations {
				for _, ss := range op.SelectionSet {
					switch ss := ss.(type) {
					case *ast.Field:
						operation = ss.Name

						for _, queryArg := range ss.Arguments {
							gqlQueryArgs[queryArg.Name] = queryArg.Value.Raw
						}
					default:
						log.Error().Str("query", query).Msg("unsupported type for GQL selectionset")
					}

					break
				}
			}

			// The "operation" is assumed to be present. If it is not, the above attempt to parse the GQL fails
			// and an error is returned.
			log.Debug().Str("query", query).Str("operation", operation).Msg("computed operation from query")

			// The value of operation here is one that is defined in the graphql schema.
			// However, it may not be supported yet.
			// Currently, only CVEDiffListForImages is unsupported as it needs the data from 2 images that can be
			// on different members.
			handler, ok := proxyFunctionalityMap[operation]
			if !ok {
				// If the operation is not currently supported, return an appropriate error
				http.Error(response, errors.ErrGQLQueryNotSupported.Error(), http.StatusBadRequest)

				return
			}

			// invoke the handler
			handler(config, log, gqlQueryArgs, response, request)
		})
	}
}
