package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/cluster"
	"zotregistry.dev/zot/pkg/common"
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

			proxyResponse, err := proxyHTTPRequest(request.Context(), request, targetMember, ctrlr)
			if err != nil {
				logger.Error().Err(err).Str(constants.RepositoryLogKey, name).Msg("failed to proxy the request")
				http.Error(response, err.Error(), http.StatusInternalServerError)

				return
			}
			defer proxyResponse.Body.Close()

			copyHeader(response.Header(), proxyResponse.Header)
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

// proxy the request to the target member and return a pointer to the response or an error.
func proxyHTTPRequest(ctx context.Context, req *http.Request,
	targetMember string, ctrlr *Controller,
) (*http.Response, error) {
	cloneURL := *req.URL

	proxyQueryScheme := "http"
	if ctrlr.Config.HTTP.TLS != nil {
		proxyQueryScheme = "https"
	}

	cloneURL.Scheme = proxyQueryScheme
	cloneURL.Host = targetMember

	clonedBody := cloneRequestBody(req)

	fwdRequest, err := http.NewRequestWithContext(ctx, req.Method, cloneURL.String(), clonedBody)
	if err != nil {
		return nil, err
	}

	copyHeader(fwdRequest.Header, req.Header)

	// always set hop count to 1 for now.
	// the handler wrapper above will terminate the process if it sees a request that
	// already has a hop count but is due for proxying.
	fwdRequest.Header.Set(constants.ScaleOutHopCountHeader, "1")

	clientOpts := common.HTTPClientOptions{
		TLSEnabled: ctrlr.Config.HTTP.TLS != nil,
		VerifyTLS:  ctrlr.Config.HTTP.TLS != nil, // for now, always verify TLS when TLS mode is enabled
		Host:       targetMember,
	}

	tlsConfig := ctrlr.Config.Cluster.TLS
	if tlsConfig != nil {
		clientOpts.CertOptions.ClientCertFile = tlsConfig.Cert
		clientOpts.CertOptions.ClientKeyFile = tlsConfig.Key
		clientOpts.CertOptions.RootCaCertFile = tlsConfig.CACert
	}

	httpClient, err := common.CreateHTTPClient(&clientOpts)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(fwdRequest)
	if err != nil {
		return nil, err
	}

	var clonedRespBody bytes.Buffer

	// copy out the contents into a new buffer as the response body
	// stream should be closed to get all the data out.
	_, _ = io.Copy(&clonedRespBody, resp.Body)
	resp.Body.Close()

	// after closing the original body, substitute it with a new reader
	// using the buffer that was just created.
	// this buffer should be closed later by the consumer of the response.
	resp.Body = io.NopCloser(bytes.NewReader(clonedRespBody.Bytes()))

	return resp, nil
}

func cloneRequestBody(src *http.Request) io.Reader {
	var bCloneForOriginal, bCloneForCopy bytes.Buffer
	multiWriter := io.MultiWriter(&bCloneForOriginal, &bCloneForCopy)
	numBytesCopied, _ := io.Copy(multiWriter, src.Body)

	// if the body is a type of io.NopCloser and length is 0,
	// the Content-Length header is not sent in the proxied request.
	// explicitly returning http.NoBody allows the implementation
	// to set the header.
	// ref: https://github.com/golang/go/issues/34295
	if numBytesCopied == 0 {
		src.Body = http.NoBody

		return http.NoBody
	}

	src.Body = io.NopCloser(&bCloneForOriginal)

	return bytes.NewReader(bCloneForCopy.Bytes())
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
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
