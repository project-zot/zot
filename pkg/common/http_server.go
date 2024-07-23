package common

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	apiErr "zotregistry.dev/zot/pkg/api/errors"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
)

func AllowedMethods(methods ...string) []string {
	return append(methods, http.MethodOptions)
}

func AddExtensionSecurityHeaders() mux.MiddlewareFunc { //nolint:varnamelen
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("X-Content-Type-Options", "nosniff")

			next.ServeHTTP(resp, req)
		})
	}
}

func ACHeadersMiddleware(config *config.Config, allowedMethods ...string) mux.MiddlewareFunc {
	allowedMethodsValue := strings.Join(allowedMethods, ",")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("Access-Control-Allow-Methods", allowedMethodsValue)
			resp.Header().Set("Access-Control-Allow-Headers", "Authorization,content-type,"+constants.SessionClientHeaderName)

			if config.IsBasicAuthnEnabled() {
				resp.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if req.Method == http.MethodOptions {
				return
			}

			next.ServeHTTP(resp, req)
		})
	}
}

func CORSHeadersMiddleware(allowOrigin string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			AddCORSHeaders(allowOrigin, response)

			next.ServeHTTP(response, request)
		})
	}
}

func AddCORSHeaders(allowOrigin string, response http.ResponseWriter) {
	if allowOrigin == "" {
		response.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		response.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	}
}

// AuthzOnlyAdminsMiddleware permits only admin user access if auth is enabled.
func AuthzOnlyAdminsMiddleware(conf *config.Config) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if !conf.IsBasicAuthnEnabled() {
				next.ServeHTTP(response, request)

				return
			}

			// get userAccessControl built in previous authn/authz middlewares
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should not happen as this has been previously checked for errors
				AuthzFail(response, request, userAc.GetUsername(), conf.HTTP.Realm, conf.HTTP.Auth.FailDelay)

				return
			}

			// reject non-admin access if authentication is enabled
			if userAc != nil && !userAc.IsAdmin() {
				AuthzFail(response, request, userAc.GetUsername(), conf.HTTP.Realm, conf.HTTP.Auth.FailDelay)

				return
			}

			next.ServeHTTP(response, request)
		})
	}
}

func AuthzFail(w http.ResponseWriter, r *http.Request, identity, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)

	// don't send auth headers if request is coming from UI
	if r.Header.Get(constants.SessionClientHeaderName) != constants.SessionClientHeaderValue {
		if realm == "" {
			realm = "Authorization Required"
		}

		realm = "Basic realm=" + strconv.Quote(realm)

		w.Header().Set("WWW-Authenticate", realm)
	}

	w.Header().Set("Content-Type", "application/json")

	if identity == "" {
		WriteJSON(w, http.StatusUnauthorized, apiErr.NewErrorList(apiErr.NewError(apiErr.UNAUTHORIZED)))
	} else {
		WriteJSON(w, http.StatusForbidden, apiErr.NewErrorList(apiErr.NewError(apiErr.DENIED)))
	}
}

func WriteJSON(response http.ResponseWriter, status int, data interface{}) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	WriteData(response, status, constants.DefaultMediaType, body)
}

func WriteData(w http.ResponseWriter, status int, mediaType string, data []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func QueryHasParams(values url.Values, params []string) bool {
	for _, param := range params {
		if !values.Has(param) {
			return false
		}
	}

	return true
}
