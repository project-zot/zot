package api

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/cluster"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/proxy"
)

// ClusterProxy wraps an http.HandlerFunc which requires proxying between zot instances to ensure
// that a given repository only has a single writer and reader for dist-spec operations in a scale-out cluster.
// based on the hash value of the repository name, the request will either be handled locally
// or proxied to another zot member in the cluster to get the data before sending a response to the client.
func ClusterProxy(ctrlr *Controller) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			config := ctrlr.Config
			logger := ctrlr.Log

			// if no cluster or single-node cluster, handle locally.
			if config.Cluster == nil || len(config.Cluster.Members) == 1 {
				next.ServeHTTP(response, request)

				return
			}

			// since the handler has been wrapped, it should be possible to get the name
			// of the repository from the mux.
			vars := mux.Vars(request)
			name, ok := vars["name"]

			if !ok || name == "" {
				response.WriteHeader(http.StatusNotFound)

				return
			}

			// the target member is the only one which should do read/write for the dist-spec APIs
			// for the given repository.
			targetMemberIndex, targetMember := cluster.ComputeTargetMember(config.Cluster.HashKey, config.Cluster.Members, name)
			logger.Debug().Str(constants.RepositoryLogKey, name).
				Msg(fmt.Sprintf("target member socket: %s index: %d", targetMember, targetMemberIndex))

			// if the target member is the same as the local member, the current member should handle the request.
			// since the instances have the same config, a quick index lookup is sufficient
			if targetMemberIndex == config.Cluster.Proxy.LocalMemberClusterSocketIndex {
				logger.Debug().Str(constants.RepositoryLogKey, name).Msg("handling the request locally")
				next.ServeHTTP(response, request)

				return
			}

			// if the header contains a hop-count, return an error response as there should be no multi-hop
			if request.Header.Get(constants.ScaleOutHopCountHeader) != "" {
				logger.Fatal().Str("url", request.URL.String()).
					Msg("failed to process request - cannot proxy an already proxied request")

				return
			}

			logger.Debug().Str(constants.RepositoryLogKey, name).Msg("proxying the request")

			proxyResponse, err := proxy.ProxyHTTPRequest(request.Context(), request, targetMember, ctrlr.Config)
			if err != nil {
				logger.Error().Err(err).Str(constants.RepositoryLogKey, name).Msg("failed to proxy the request")
				http.Error(response, err.Error(), http.StatusInternalServerError)

				return
			}
			defer proxyResponse.Body.Close()

			proxy.CopyHeader(response.Header(), proxyResponse.Header)
			response.WriteHeader(proxyResponse.StatusCode)
			_, _ = io.Copy(response, proxyResponse.Body)
		})
	}
}

// gets all the server sockets of a target member - IP:Port.
// for IPv6, the socket is [IPv6]:Port.
// if the input is an IP address, returns the same targetMember in an array.
// if the input is a host name, performs a lookup and returns the server sockets.
func getTargetMemberServerSockets(targetMemberSocket string) ([]string, error) {
	targetHost, targetPort, err := net.SplitHostPort(targetMemberSocket)
	if err != nil {
		return []string{}, err
	}

	addr := net.ParseIP(targetHost)
	if addr != nil {
		// this is an IP address, return as is
		return []string{targetMemberSocket}, nil
	}
	// this is a hostname - try to resolve to an IP
	resolvedAddrs, err := common.GetIPFromHostName(targetHost)
	if err != nil {
		return []string{}, err
	}

	targetSockets := make([]string, len(resolvedAddrs))
	for idx, resolvedAddr := range resolvedAddrs {
		targetSockets[idx] = net.JoinHostPort(resolvedAddr, targetPort)
	}

	return targetSockets, nil
}

// identifies and returns the cluster socket and index.
// this is the socket which the scale out cluster members will use for
// proxying and communication among each other.
// returns index, socket, error.
// returns an empty string and index value -1 if the cluster socket is not found.
func GetLocalMemberClusterSocket(members []string, localSockets []string) (int, string, error) {
	for memberIdx, member := range members {
		// for each member, get the full list of sockets, including DNS resolution
		memberSockets, err := getTargetMemberServerSockets(member)
		if err != nil {
			return -1, "", err
		}

		// for each member socket that we have, compare all the local sockets with
		// it to see if there is any match.
		for _, memberSocket := range memberSockets {
			for _, localSocket := range localSockets {
				// this checks if the sockets are equal at a host port level
				areSocketsEqual, err := common.AreSocketsEqual(memberSocket, localSocket)
				if err != nil {
					return -1, "", err
				}

				if areSocketsEqual {
					return memberIdx, member, nil
				}
			}
		}
	}

	return -1, "", nil
}
