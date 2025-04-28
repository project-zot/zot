package gqlproxy

import (
	"encoding/json"
	"io"
	"net/http"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/proxy"
)

func fanOutGqlHandler(config *config.Config, _ map[string]string, response http.ResponseWriter, request *http.Request) {
	// Proxy to all members including self in order to get the data as calling next() won't return the
	// aggregated data to this handler.
	finalMap := map[string]any{}

	for _, targetMember := range config.Cluster.Members {
		proxyResponse, err := proxy.ProxyHTTPRequest(request.Context(), request, targetMember, config)
		if err != nil {
			http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

			return
		}

		proxyBody, err := io.ReadAll(proxyResponse.Body)
		_ = proxyResponse.Body.Close()

		if err != nil {
			http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

			return
		}

		responseResult := map[string]any{}

		err = json.Unmarshal(proxyBody, &responseResult)
		if err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)

			return
		}
		// perform merge of fields
		finalMap = deepMergeMaps(finalMap, responseResult)
	}

	prepareAndWriteResponse(finalMap, response)
}
