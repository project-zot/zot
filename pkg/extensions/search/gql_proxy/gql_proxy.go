package gqlproxy

import (
	"net/http"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/log"
)

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
				http.Error(response, "Failed to process GQL request", http.StatusInternalServerError)

				return
			}

			// Look at the first operation in the query.
			// TODO: for completeness, this should support multiple
			// operations at once.
			operation := ""
			for _, op := range processedGql.Operations {
				for _, ss := range op.SelectionSet {
					switch ss := ss.(type) {
					case *ast.Field:
						operation = ss.Name
					default:
						log.Error().Str("query", query).Msg("Unsupported type")
					}

					break
				}
			}

			if operation == "" {
				log.Error().Str("query", query).Msg("Failed to compute operation from query")
				http.Error(response, "Failed to process GQL request", http.StatusInternalServerError)

				return
			}

			// Each operation is individually handled as the schema and structs are different.
			if operation == "GlobalSearch" {
				HandleGlobalSearchResult(config, response, request, next)

				return
			} else {
				// If the operation is not currently supported or is unknown,
				// pass it on to the local GQL server to handle it.
				next.ServeHTTP(response, request)

				return
			}
		})
	}
}
