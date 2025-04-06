package gqlproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/cluster"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/proxy"
)

// This handler proxies once based on the value of the "repo" argument.
func repoProxyOnceGqlHandler(
	config *config.Config,
	log log.Logger,
	args map[string]string,
	response http.ResponseWriter,
	request *http.Request,
) {
	// It is safe to assume that "repo" is in the args because the GQL parse will fail
	// if it is not present.
	repoName := args["repo"]

	proxyOnceGqlHandler(config, log, repoName, response, request)
}

// This handler proxies once based on the value of the "image" argument.
func repoAliasImageProxyOnceGqlHandler(
	config *config.Config,
	log log.Logger,
	args map[string]string,
	response http.ResponseWriter,
	request *http.Request,
) {
	// It is safe to assume that "image" is in the args because the GQL parse will fail
	// if it is not present.
	repoName := args["image"]

	proxyOnceGqlHandler(config, log, repoName, response, request)
}

// This handler proxies once based on the value of the "repository" part of the "image" argument.
// Accepts image with a tag or a digest.
func imageWithTagOrDigestProxyOnceGqlHandler(
	config *config.Config,
	log log.Logger,
	args map[string]string,
	response http.ResponseWriter,
	request *http.Request,
) {
	// It is safe to assume that "image" is in the args because the GQL parse will fail
	// if it is not present.
	image := args["image"]

	dividerIndex := strings.Index(image, ":")

	if dividerIndex == -1 {
		dividerIndex = strings.Index(image, "@")
	}

	if dividerIndex == -1 {
		log.Error().Err(errors.ErrInvalidRepoRefFormat).Msgf("failed to process image name %s", image)
		http.Error(response, errors.ErrInvalidRepoRefFormat.Error(), http.StatusBadRequest)

		return
	}

	repoName := image[:dividerIndex]

	proxyOnceGqlHandler(config, log, repoName, response, request)
}

// This handler proxies once based on the value of the "repository" part of the "image" argument.
// Only allows the tag to be specified and not a digest.
func imageWithOnlyTagProxyOnceGqlHandler(
	config *config.Config,
	log log.Logger,
	args map[string]string,
	response http.ResponseWriter,
	request *http.Request,
) {
	// It is safe to assume that "image" is in the args because the GQL parse will fail
	// if it is not present.
	image := args["image"]

	dividerIndex := strings.Index(image, ":")

	if dividerIndex == -1 {
		log.Error().Err(errors.ErrInvalidRepoTagRefFormat).Msgf("failed to process image name %s", image)
		http.Error(response, errors.ErrInvalidRepoTagRefFormat.Error(), http.StatusBadRequest)

		return
	}

	repoName := image[:dividerIndex]

	proxyOnceGqlHandler(config, log, repoName, response, request)
}

// This is a generic handler that proxies directly to the target member using the name of the repo.
func proxyOnceGqlHandler(
	config *config.Config, log log.Logger, repoName string, response http.ResponseWriter, request *http.Request,
) {
	_, targetMember := cluster.ComputeTargetMember(config.Cluster.HashKey, config.Cluster.Members, repoName)

	proxyResponse, err := proxy.ProxyHTTPRequest(request.Context(), request, targetMember, config)
	if err != nil {
		log.Error().Err(err).Msg("failed to proxy HTTP Request")
		http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

		return
	}

	proxyBody, err := io.ReadAll(proxyResponse.Body)
	_ = proxyResponse.Body.Close()

	if err != nil {
		log.Error().Err(err).Msg("failed to read proxy body")
		http.Error(response, "failed to process GQL request", http.StatusInternalServerError)

		return
	}

	responseResult := map[string]any{}

	err = json.Unmarshal(proxyBody, &responseResult)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal proxy response")
		http.Error(response, err.Error(), http.StatusInternalServerError)

		return
	}

	prepareAndWriteResponse(responseResult, response)
}
