package test

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

type RouteHandler struct {
	Route string
	// HandlerFunc is the HTTP handler function that receives a writer for output and an HTTP request as input.
	HandlerFunc http.HandlerFunc
	// AllowedMethods specifies the HTTP methods allowed for the current route.
	AllowedMethods []string
}

// Routes is a map that associates HTTP paths to their corresponding HTTP handlers.
type HTTPRoutes []RouteHandler

func StartTestHTTPServer(routes HTTPRoutes, port string) *http.Server {
	baseURL := GetBaseURL(port)
	mux := mux.NewRouter()

	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("{}"))
		if err != nil {
			return
		}
	}).Methods(http.MethodGet)

	for _, routeHandler := range routes {
		mux.HandleFunc(routeHandler.Route, routeHandler.HandlerFunc).Methods(routeHandler.AllowedMethods...)
	}

	server := &http.Server{ //nolint:gosec
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}()

	WaitTillServerReady(baseURL + "/test")

	return server
}
