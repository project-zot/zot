package gqlproxy

import (
	"encoding/json"
	"io"
	"net/http"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/cluster"
	"zotregistry.dev/zot/pkg/proxy"
)

func repoProxyOnceGqlHandler(
	config *config.Config,
	args map[string]string,
	response http.ResponseWriter,
	request *http.Request,
) {
	repoName, ok := args["repo"]
	if !ok {
		// no repo was specified
		http.Error(response, "repo name not specified in query", http.StatusBadRequest)

		return
	}

	proxyOnceGqlHandler(config, repoName, response, request)
}

func proxyOnceGqlHandler(config *config.Config, repoName string, response http.ResponseWriter, request *http.Request) {
	_, targetMember := cluster.ComputeTargetMember(config.Cluster.HashKey, config.Cluster.Members, repoName)

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

	prepareAndWriteResponse(responseResult, response)
}
