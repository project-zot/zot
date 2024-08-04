package gqlproxy

import (
	"net/http"
	"strings"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/log"
)

// Returns a wrapped handler that can handle request proxying for GQL
// queries when running in cluster mode without shared storage (each instance has its own metadata).
// Requests are only proxied in local cluster mode as in this mode, each instance holds only the
// metadata for the images that it serves, however, in shared storage mode,
// all the instances have access to all the metadata so any can respond.
func GqlProxyRequestHandler(config *config.Config, log log.Logger) func(handler http.Handler) http.Handler {
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

			// General Structure for GQL Requests
			// Query String contains the full GraphQL Request (it's NOT JSON)
			// e.g. {(query:"", requestedPage: {limit:3 offset:0 sortBy: DOWNLOADS} )
			// {Page {TotalCount ItemCount} Repos {Name LastUpdated Size Platforms { Os Arch }
			// IsStarred IsBookmarked NewestImage { Tag Vulnerabilities {MaxSeverity Count}
			// Description IsSigned SignGlobalSearchatureInfo { Tool IsTrusted Author } Licenses Vendor Labels }
			// StarCount DownloadCount}}}

			// General Payload Structure for GQL Response
			/*
				{
					"errors": [CUSTOM_ERRORS_HERE],
					"data": {
						"NameOfQuery": {CUSTOM_SCHEMA_HERE}
					}
				}
			*/

			query := request.URL.Query().Get("query")

			operation, ok := computeGqlOperation(query)
			if !ok {
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

// Naively compute which operation is requested for GQL.
// TODO: Need to replace this with better custom GQL parsing
// or a parsing library that can conver the GQL query to
// a struct where operations data and schema are available for reading.
func computeGqlOperation(request string) (string, bool) {
	openParenthesisIndex := strings.Index(request, "(")
	if openParenthesisIndex == -1 {
		return "", false
	}

	return request[1:openParenthesisIndex], true
}
