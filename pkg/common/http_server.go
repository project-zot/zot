package common

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
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

			// Access-Control-Allow-Credentials must not be "true" when
			// Access-Control-Allow-Origin is the wildcard "*" (CORS spec §3.2).
			// Only advertise credentials support when an explicit origin is set.
			authConfig := config.CopyAuthConfig()
			allowOrigin := strings.TrimSpace(config.GetAllowOrigin())
			if authConfig.IsBasicAuthnEnabled() && allowOrigin != "" && allowOrigin != "*" {
				resp.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if req.Method == http.MethodOptions {
				return
			}

			next.ServeHTTP(resp, req)
		})
	}
}

// MaxBodySizeMiddleware caps the request body at maxBytes before it reaches the wrapped
// handler, so a handler that buffers its whole body into memory (e.g. io.ReadAll) can't be
// forced to allocate an unbounded amount for a single request.
func MaxBodySizeMiddleware(maxBytes int64) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			req.Body = http.MaxBytesReader(resp, req.Body, maxBytes)

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
			if !conf.IsAuthnEnabled() {
				next.ServeHTTP(response, request)

				return
			}

			authConfig := conf.CopyAuthConfig()
			challenge := adminAuthChallenge(authConfig, conf.GetRealm())
			failDelay := authConfig.GetFailDelay()

			// get userAccessControl built in previous authn/authz middlewares
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should not happen as this has been previously checked for errors
				authzFailWithChallenge(response, request, "", challenge, failDelay, "")

				return
			}

			// Missing authentication context, non-admin principals, principals without an authz
			// decision (no accessControl configured, where IsAdmin would default to true), and admins
			// whose adminPolicy conditions deny this request all fail closed.
			isAdmin, reason := userAc.IsAdminByPolicy()
			if userAc.IsAnonymous() || !isAdmin {
				authzFailWithChallenge(response, request, userAc.GetUsername(), challenge, failDelay, reason)

				return
			}

			next.ServeHTTP(response, request)
		})
	}
}

// adminAuthChallenge selects the WWW-Authenticate challenge for an admin route rejection from the
// server's auth config, as for dist-spec routes (see examples/README-COMBINED-AUTHENTICATION.md,
// "Challenge Advertisement"): Bearer when a Bearer challenge can be advertised, else Basic when
// Basic credentials can authenticate, else none (e.g. mTLS only, which has no HTTP challenge).
// Admin routes are not repository-scoped, so a Bearer challenge carries an empty scope.
func adminAuthChallenge(authConfig *config.AuthConfig, realm string) string {
	switch {
	case authConfig.ShouldAdvertiseBearerChallenge():
		return fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"\"",
			authConfig.Bearer.Realm, authConfig.Bearer.Service)
	case authConfig.CanAuthenticateWithBasicCredentials():
		return basicAuthChallenge(realm)
	default:
		return ""
	}
}

// IsBrowserRequest reports whether a request comes from a browser, which must never get a
// "WWW-Authenticate: Basic" challenge. Such a challenge makes the browser show its native
// login prompt and cache the entered credentials per (origin, realm), independently of the
// zot session. Logout cannot remove that cache over plain HTTP, and since a Basic
// Authorization header takes precedence over the session cookie, cached credentials would
// silently override any later UI login (see issue #4699). Bearer challenges are not
// affected: browsers do not act on them.
func IsBrowserRequest(request *http.Request) bool {
	// UI requests that already carry the session header.
	if request.Header.Get(constants.SessionClientHeaderName) == constants.SessionClientHeaderValue {
		return true
	}

	// Fetch Metadata headers are only sent by browsers, so registry clients (docker,
	// podman, skopeo, curl) are unaffected. Browsers send them only to secure origins
	// (HTTPS or localhost), which covers requests issued before the UI attaches its header.
	if request.Header.Get("Sec-Fetch-Mode") != "" {
		return true
	}

	// Fallback for plain HTTP, where Fetch Metadata is absent: top-level navigations
	// (e.g. a bookmarked /v2/_catalog URL) advertise text/html, registry clients do not.
	// Script fetches send "Accept: */*" and cannot be told apart from registry clients here,
	// so on plain HTTP they are only covered once the UI attaches its session header.
	return strings.Contains(request.Header.Get("Accept"), "text/html")
}

func basicAuthChallenge(realm string) string {
	if realm == "" {
		realm = "Authorization Required"
	}

	return "Basic realm=" + strconv.Quote(realm)
}

func AuthzFail(w http.ResponseWriter, r *http.Request, identity, realm string, delay int) {
	AuthzFailWithReason(w, r, identity, realm, delay, "")
}

// AuthzFailWithReason behaves like AuthzFail but, when reason is non-empty,
// embeds it in the response body's error detail under the "reason" key. This
// lets policy conditions surface the operator-authored Message to the client
// alongside the standard DENIED error code.
func AuthzFailWithReason(w http.ResponseWriter, r *http.Request, identity, realm string, delay int, reason string) {
	authzFailWithChallenge(w, r, identity, basicAuthChallenge(realm), delay, reason)
}

// authzFailWithChallenge writes an authz failure: 401 without an identity, else 403. challenge, if
// non-empty, is sent as WWW-Authenticate, except to UI session clients, and a Basic challenge is
// additionally withheld from any browser request (see IsBrowserRequest).
func authzFailWithChallenge(w http.ResponseWriter, r *http.Request, identity, challenge string, delay int,
	reason string,
) {
	// an anonymous request sent no credentials to throttle; bad credentials are delayed in authn
	if identity != "" {
		time.Sleep(time.Duration(delay) * time.Second)
	}

	// don't send auth headers if request is coming from UI
	sendChallenge := challenge != "" &&
		r.Header.Get(constants.SessionClientHeaderName) != constants.SessionClientHeaderValue
	// e.g. an anonymous browser navigation to /v2/_catalog with disableAnonymousCatalog, or to
	// an admin route; Bearer challenges are still sent to non-UI clients. A prefix check is
	// enough: callers build Basic challenges with basicAuthChallenge, which always emits
	// a single `Basic realm=...` challenge.
	if sendChallenge && strings.HasPrefix(challenge, "Basic ") && IsBrowserRequest(r) {
		sendChallenge = false
	}

	if sendChallenge {
		w.Header().Set("WWW-Authenticate", challenge)
	}

	w.Header().Set("Content-Type", "application/json")

	if identity == "" {
		WriteJSON(w, http.StatusUnauthorized, apiErr.NewErrorList(apiErr.NewError(apiErr.UNAUTHORIZED)))

		return
	}

	denied := apiErr.NewError(apiErr.DENIED)
	if reason != "" {
		denied.AddDetail(map[string]string{"reason": reason})
	}

	WriteJSON(w, http.StatusForbidden, apiErr.NewErrorList(denied))
}

func WriteJSON(response http.ResponseWriter, status int, data any) {
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
