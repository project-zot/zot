package gqlproxy

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/proxy"
)

const (
	LoggerFieldOperation    = "operation"
	LoggerFieldTargetMember = "targetMember"
	HandlerOperation        = "GlobalSearch"
)

// This is a handler for all GlobalSearchResult GQL queries in proxy mode without shared storage.
func HandleGlobalSearchResult(
	config *config.Config, response http.ResponseWriter, request *http.Request, next http.Handler,
) {
	collatedResult := common.GlobalSearchResultResp{
		Errors: []common.ErrorGQL{},
	}

	// Proxy to all members including self in order to get the data as calling next() won't return the
	// aggregated data to this handler.
	for _, targetMember := range config.Cluster.Members {
		proxyResponse, err := proxy.ProxyHTTPRequest(request.Context(), request, targetMember, config)
		if err != nil {
			log.Error().Str(LoggerFieldOperation, HandlerOperation).
				Str(LoggerFieldTargetMember, targetMember).
				Err(err).Msg("failed to proxy request")
			http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

			return
		}

		proxyBody, err := io.ReadAll(proxyResponse.Body)
		proxyResponse.Body.Close()

		if err != nil {
			log.Error().Str(LoggerFieldOperation, HandlerOperation).
				Str(LoggerFieldTargetMember, targetMember).
				Err(err).Msg("failed to read proxy body")
			http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

			return
		}

		var proxyRespData common.GlobalSearchResultResp
		// Collate Results
		err = json.Unmarshal(proxyBody, &proxyRespData)
		if err != nil {
			log.Error().Str(LoggerFieldOperation, HandlerOperation).
				Str(LoggerFieldTargetMember, targetMember).
				Str("responseBody", string(proxyBody)).
				Err(err).
				Msg("failed to unmarshal received response body")
			http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

			return
		}

		// aggregate errors
		collatedResult.Errors = append(collatedResult.Errors, proxyRespData.Errors...)

		// aggregate pagination data
		// TODO: currently, this doesn't support pagination limits. It will aggregate this data
		// from all instances subject to existing behaviour of limits.
		incomingItemCount := proxyRespData.GlobalSearchResult.GlobalSearch.Page.ItemCount
		collatedResult.GlobalSearchResult.GlobalSearch.Page.ItemCount += incomingItemCount
		incomingTotalCount := proxyRespData.GlobalSearchResult.GlobalSearch.Page.TotalCount
		collatedResult.GlobalSearchResult.GlobalSearch.Page.TotalCount += incomingTotalCount

		// aggregate results
		// TODO: GraphQL by nature doesn't send all the data - only what the client requested.
		// Because we are not yet parsing the Query, it is challenging to figure out what is to be
		// returned and what is not to be returned.
		// In this approach, all the fields are returned, but the GQL server will only have data for
		// the fields in the query so there is no impact as such.
		collatedResult.GlobalSearchResult.GlobalSearch.Images = append(
			collatedResult.GlobalSearchResult.GlobalSearch.Images,
			proxyRespData.GlobalSearchResult.GlobalSearch.Images...,
		)
		collatedResult.GlobalSearchResult.GlobalSearch.Repos = append(
			collatedResult.GlobalSearchResult.GlobalSearch.Repos,
			proxyRespData.GlobalSearchResult.GlobalSearch.Repos...,
		)
		collatedResult.GlobalSearchResult.GlobalSearch.Layers = append(
			collatedResult.GlobalSearchResult.GlobalSearch.Layers,
			proxyRespData.GlobalSearchResult.GlobalSearch.Layers...,
		)
	}

	responseBody, err := json.MarshalIndent(collatedResult, "", "    ")
	if err != nil {
		log.Error().
			Str(LoggerFieldOperation, HandlerOperation).
			Err(err).Msg("failed to marshal final response body")
		http.Error(response, "failed to create final response body", http.StatusInternalServerError)

		return
	}

	response.Header().Set("Content-Type", "application/json")

	_, err = response.Write(responseBody)
	if err != nil {
		log.Error().
			Str(LoggerFieldOperation, HandlerOperation).
			Err(err).Msg("failed to write response")
		http.Error(response, "failed to write response", http.StatusInternalServerError)

		return
	}
}
