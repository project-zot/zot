package common_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/common"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

func TestAuthzOnlyAdminsMiddleware(t *testing.T) {
	Convey("AuthzOnlyAdminsMiddleware", t, func() {
		nextCalled := false
		next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			nextCalled = true
			response.WriteHeader(http.StatusOK)
		})

		Convey("allows requests when authentication is disabled", func() {
			conf := config.New()
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusOK)
			So(nextCalled, ShouldBeTrue)
		})

		Convey("denies a non-admin principal with Bearer authentication", func() {
			conf := config.New()
			conf.HTTP.Auth.Bearer = &config.BearerConfig{
				Cert:    "/path/to/cert.pem",
				Realm:   "test-realm",
				Service: "test-service",
			}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("non-admin")
			userAc.SetIsAdmin(false)
			userAc.SaveOnRequest(request)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusForbidden)
			So(nextCalled, ShouldBeFalse)
			// Bearer is the configured scheme: no Basic challenge for a disabled scheme.
			So(response.Header().Get("WWW-Authenticate"), ShouldEqual,
				`Bearer realm="test-realm",service="test-service",scope=""`)
		})

		Convey("denies a non-admin principal with a Basic challenge when only htpasswd is enabled", func() {
			conf := config.New()
			conf.HTTP.Realm = "zot"
			conf.HTTP.Auth.HTPasswd.Path = "/path/to/htpasswd"
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("non-admin")
			userAc.SetIsAdmin(false)
			userAc.SaveOnRequest(request)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusForbidden)
			So(nextCalled, ShouldBeFalse)
			So(response.Header().Get("WWW-Authenticate"), ShouldEqual, `Basic realm="zot"`)
		})

		Convey("sends no challenge to a UI session client", func() {
			conf := config.New()
			conf.HTTP.Auth.HTPasswd.Path = "/path/to/htpasswd"
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			request.Header.Set(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("non-admin")
			userAc.SetIsAdmin(false)
			userAc.SaveOnRequest(request)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusForbidden)
			So(response.Header().Get("WWW-Authenticate"), ShouldBeEmpty)
		})

		Convey("allows an admin principal with Bearer authentication", func() {
			conf := config.New()
			conf.HTTP.Auth.Bearer = &config.BearerConfig{
				Cert:    "/path/to/cert.pem",
				Realm:   "test-realm",
				Service: "test-service",
			}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("admin")
			userAc.SetIsAdmin(true)
			userAc.SetAdminPolicyEvaluator(func() (bool, string) { return true, "" })
			userAc.SaveOnRequest(request)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusOK)
			So(nextCalled, ShouldBeTrue)
		})

		Convey("denies an admin principal whose adminPolicy conditions deny the request", func() {
			conf := config.New()
			conf.HTTP.Realm = "zot"
			conf.HTTP.Auth.HTPasswd.Path = "/path/to/htpasswd"
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("admin")
			userAc.SetIsAdmin(true)
			userAc.SetAdminPolicyEvaluator(func() (bool, string) { return false, "admin requires TLS" })
			userAc.SaveOnRequest(request)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusForbidden)
			So(nextCalled, ShouldBeFalse)
			So(response.Body.String(), ShouldContainSubstring, "admin requires TLS")
		})

		Convey("denies a missing principal with mTLS authentication", func() {
			conf := config.New()
			conf.HTTP.TLS = &config.TLSConfig{Cert: "server.cert", Key: "server.key", CACert: "ca.crt"}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusUnauthorized)
			So(nextCalled, ShouldBeFalse)
			// mTLS has no HTTP challenge, and Basic is not configured.
			So(response.Header().Get("WWW-Authenticate"), ShouldBeEmpty)
		})

		Convey("denies an authenticated principal without an authz decision", func() {
			// No accessControl configured: BaseAuthzHandler never runs, so IsAdmin defaults to true.
			// Admin-only routes must still require an explicit adminPolicy match.
			conf := config.New()
			conf.HTTP.TLS = &config.TLSConfig{Cert: "server.cert", Key: "server.key", CACert: "ca.crt"}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername("client-cert-user")
			userAc.SaveOnRequest(request)
			So(userAc.IsAdmin(), ShouldBeTrue)
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusForbidden)
			So(nextCalled, ShouldBeFalse)
		})

		Convey("denies a malformed access-control context", func() {
			conf := config.New()
			conf.HTTP.TLS = &config.TLSConfig{Cert: "server.cert", Key: "server.key", CACert: "ca.crt"}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin", nil)
			request = request.WithContext(context.WithValue(request.Context(), reqCtx.GetContextKey(), "invalid"))
			response := httptest.NewRecorder()

			common.AuthzOnlyAdminsMiddleware(conf)(next).ServeHTTP(response, request)

			So(response.Code, ShouldEqual, http.StatusUnauthorized)
			So(nextCalled, ShouldBeFalse)
			// mTLS has no HTTP challenge, and Basic is not configured.
			So(response.Header().Get("WWW-Authenticate"), ShouldBeEmpty)
		})
	})
}

func TestAuthzFailDelaySkipsAnonymousRequests(t *testing.T) {
	Convey("AuthzFail applies failDelay only to requests that carried an identity", t, func() {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v2/repo/blobs/uploads/", nil)

		start := time.Now()
		response := httptest.NewRecorder()
		common.AuthzFail(response, request, "", "zot", 2)
		So(response.Code, ShouldEqual, http.StatusUnauthorized)
		So(time.Since(start), ShouldBeLessThan, time.Second)

		start = time.Now()
		response = httptest.NewRecorder()
		common.AuthzFail(response, request, "alice", "zot", 1)
		So(response.Code, ShouldEqual, http.StatusForbidden)
		So(time.Since(start), ShouldBeGreaterThanOrEqualTo, time.Second)
	})
}

func TestAuthzFailBrowserChallenges(t *testing.T) {
	Convey("Authz challenges are withheld only from the zot UI, browsers keep Basic", t, func() {
		tests := []struct {
			name      string
			headers   map[string]string
			challenge bool
		}{
			{name: "registry client", challenge: true},
			{name: "docker client", headers: map[string]string{"User-Agent": "Docker-Client/28.0"}, challenge: true},
			{name: "wildcard accept", headers: map[string]string{"Accept": "*/*"}, challenge: true},
			{name: "ui client", headers: map[string]string{
				constants.SessionClientHeaderName: constants.SessionClientHeaderValue,
			}},
			// e.g. a bookmarked /v2/_catalog, the GraphQL playground or Swagger UI: no UI header,
			// so the native Basic prompt is how they authenticate
			{
				name: "browser navigation over https", headers: map[string]string{"Sec-Fetch-Mode": "navigate"},
				challenge: true,
			},
			{name: "browser navigation over plain http", headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			}, challenge: true},
		}

		for _, test := range tests {
			// anonymous request to /v2/_catalog with disableAnonymousCatalog
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v2/_catalog", nil)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}

			response := httptest.NewRecorder()
			common.AuthzFail(response, request, "", "zot", 0)
			So(response.Code, ShouldEqual, http.StatusUnauthorized)

			if test.challenge {
				So(response.Header().Get("WWW-Authenticate"), ShouldEqual, `Basic realm="zot"`)
			} else {
				So(response.Header().Get("WWW-Authenticate"), ShouldBeEmpty)
			}
		}
	})

	Convey("Admin routes: browsers without the UI header keep their Basic or Bearer challenge", t, func() {
		for _, bearer := range []bool{false, true} {
			conf := config.New()
			conf.HTTP.Realm = "zot"
			conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{Path: "/tmp/htpasswd"}
			if bearer {
				conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{}
				conf.HTTP.Auth.Bearer = &config.BearerConfig{
					Realm: "https://auth.example.com/token", Service: "zot", Cert: "/tmp/cert.pem",
				}
			}

			handler := common.AuthzOnlyAdminsMiddleware(conf)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("next handler must not run for an anonymous request")
			}))

			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/zot/admin", nil)
			request.Header.Set("Sec-Fetch-Mode", "navigate")

			reqCtx.NewUserAccessControl().SaveOnRequest(request) // anonymous

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			So(response.Code, ShouldEqual, http.StatusUnauthorized)

			if bearer {
				So(response.Header().Get("WWW-Authenticate"), ShouldStartWith, "Bearer ")
			} else {
				So(response.Header().Get("WWW-Authenticate"), ShouldStartWith, "Basic ")
			}
		}
	})
}
