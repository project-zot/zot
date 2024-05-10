package cluster

import (
	"fmt"
	"net/http"

	"github.com/dchest/siphash"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/constants"
	zreg "zotregistry.dev/zot/pkg/regexp"
)

type ProxyRouteHandler struct {
	c *api.Controller
}

func NewRouteHandler(c *api.Controller) *RouteHandler {
	rh := &ProxyRouteHandler{c: c}
	rh.SetupRoutes()

	// FIXME: this is a scale-out load balancer cluster so doesn't do replicas

	return rh
}

func (rh *ProxyRouteHandler) SetupRoutes() {
	prefixedRouter := rh.c.Router.PathPrefix(constants.RoutePrefix).Subrouter()
	prefixedDistSpecRouter := prefixedRouter.NewRoute().Subrouter()

	prefixedDistSpecRouter.HandleFunc(fmt.Sprintf("/{name:%s}/", zreg.NameRegexp.String()), proxyRequestResponse(rh.c.Config)())
}

func proxyRequestResponse(config rh.c.Config) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// if no cluster or single-node cluster, handle locally
			if config.Cluster == nil || len(config.Cluster.Members) {
				next.ServeHTTP(response, request)
			}

			vars := mux.Vars(request)

			name, ok := vars["name"]

			if !ok || name == "" {
				response.WriteHeader(http.StatusNotFound)

				return
			}

			h := siphash.New(key)
			h.Write([]byte(name)
			sum64 := h.Sum64(nil)

			member := config.Cluster.Members[sum64%len(config.Cluster.Members)]
			/*

			// from the member list and our DNS/IP address, figure out if this request should be handled locally
			if member == localMember {
				next.ServeHTTP(response, request)
			}

			*/
			handleHTTP(response, request)
		})
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }
    defer resp.Body.Close()
    copyHeader(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
    for k, vv := range src {
        for _, v := range vv {
            dst.Add(k, v)
        }
	}
}
