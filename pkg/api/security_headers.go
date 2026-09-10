package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

const hstsHeaderValue = "max-age=63072000; includeSubDomains"

// StrictTransportSecurityHandler is a HTTP middleware that sets the
// Strict-Transport-Security header on every response served over TLS,
// instructing browsers to only ever reach this host over HTTPS.
func StrictTransportSecurityHandler() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.TLS != nil {
				response.Header().Set("Strict-Transport-Security", hstsHeaderValue)
			}

			next.ServeHTTP(response, request)
		})
	}
}
