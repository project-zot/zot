package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

var errTestTokenProxyRead = errors.New("test token proxy read error")

type errTokenProxyReadCloser struct{}

func (errTokenProxyReadCloser) Read(_ []byte) (int, error) {
	return 0, errTestTokenProxyRead
}

func (errTokenProxyReadCloser) Close() error {
	return nil
}

func newTestBearerAuth(bearerConfig *config.BearerConfig) *BearerAuth {
	if bearerConfig != nil && len(bearerConfig.OIDC) == 0 {
		bearerConfig.OIDC = []config.BearerOIDCConfig{{Issuer: "https://issuer.example.com", Audiences: []string{"zot"}}}
	}

	authConfig := &config.AuthConfig{Bearer: bearerConfig}

	return &BearerAuth{
		authConfig:   authConfig,
		bearerConfig: bearerConfig,
		log:          log.NewTestLogger(),
		oidc:         &OIDCBearerAuthorizer{},
	}
}

func TestNewBearerAuthWithoutBearerConfig(t *testing.T) {
	t.Parallel()

	bearerAuth := NewBearerAuth(&config.AuthConfig{}, log.NewTestLogger())
	if bearerAuth == nil {
		t.Fatal("expected bearer auth")
	}

	if bearerAuth.TokenExchangeHandler() != nil {
		t.Fatal("expected no token exchange handler without OIDC")
	}
}

func TestNewBearerAuthInvalidCertPanics(t *testing.T) {
	t.Parallel()

	certPath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(certPath, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("failed to write invalid cert: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid bearer cert")
		}
	}()

	NewBearerAuth(&config.AuthConfig{Bearer: &config.BearerConfig{Cert: certPath}}, log.NewTestLogger())
}

func TestBearerAuthMiddlewareBypassesMgmtWithoutCredentials(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm", Service: "service"}}
	bearerAuth := &BearerAuth{authConfig: conf.HTTP.Auth, bearerConfig: conf.HTTP.Auth.Bearer, log: log.NewTestLogger()}
	ctlr := &Controller{Config: conf, Log: log.NewTestLogger()}

	called := false
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		response.WriteHeader(http.StatusAccepted)
	})

	request := httptest.NewRequest(http.MethodGet, constants.FullMgmt, nil)
	response := httptest.NewRecorder()
	bearerAuth.Middleware(ctlr)(next).ServeHTTP(response, request)

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, response.Code)
	}
}

func TestBearerAuthMiddlewareDefaultsUnknownMethodsToPull(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm", Service: "service"}}
	bearerAuth := &BearerAuth{authConfig: conf.HTTP.Auth, bearerConfig: conf.HTTP.Auth.Bearer, log: log.NewTestLogger()}
	ctlr := &Controller{Config: conf, Log: log.NewTestLogger()}

	request := httptest.NewRequest(http.MethodTrace, "/v2/repo/manifests/latest", nil)
	request = mux.SetURLVars(request, map[string]string{"name": "repo"})
	response := httptest.NewRecorder()
	bearerAuth.Middleware(ctlr)(http.NotFoundHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}

	if !strings.Contains(response.Header().Get("WWW-Authenticate"), "scope=\"repository:repo:pull\"") {
		t.Fatalf("expected pull challenge, got %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestTokenProxyRequestBody(t *testing.T) {
	t.Parallel()

	t.Run("nil body", func(t *testing.T) {
		t.Parallel()

		body, contentLength, err := tokenProxyRequestBody(&http.Request{}, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if body != nil {
			t.Fatal("expected nil body")
		}

		if contentLength != 0 {
			t.Fatalf("expected content length 0, got %d", contentLength)
		}
	})

	t.Run("passes through non-form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("raw-body"))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len("raw-body"))

		body, contentLength, err := tokenProxyRequestBody(request, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(bodyBytes) != "raw-body" {
			t.Fatalf("expected raw body to be preserved, got %q", string(bodyBytes))
		}

		if contentLength != int64(len("raw-body")) {
			t.Fatalf("expected content length %d, got %d", len("raw-body"), contentLength)
		}
	})

	t.Run("rewrites form service", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(
			"grant_type=password&service=zot-service&scope=repository:test:pull",
		))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

		body, _, err := tokenProxyRequestBody(request, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		got := string(bodyBytes)
		if !strings.Contains(got, "service=upstream") {
			t.Fatalf("expected service to be rewritten, got %q", got)
		}

		if !strings.Contains(got, "scope=repository%3Atest%3Apull") {
			t.Fatalf("expected scope to be preserved, got %q", got)
		}
	})

	t.Run("returns body read errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Body = errTokenProxyReadCloser{}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, _, err := tokenProxyRequestBody(request, "upstream")
		if !errors.Is(err, errTestTokenProxyRead) {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("returns form parse errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("service=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, _, err := tokenProxyRequestBody(request, "upstream")
		if !errors.Is(err, zerr.ErrInvalidTokenProxyForm) {
			t.Fatalf("expected invalid form error, got %v", err)
		}
	})

	t.Run("rejects oversized form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token",
			strings.NewReader(strings.Repeat("a", constants.MaxTokenRequestBodySize+1)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, _, err := tokenProxyRequestBody(request, "upstream")
		if !errors.Is(err, errTokenRequestBodyTooLarge) {
			t.Fatalf("expected body too large error, got %v", err)
		}
	})
}

func TestTokenProxyHeaders(t *testing.T) {
	t.Parallel()

	src := http.Header{}
	src.Add("Connection", "X-Hop, X-Also-Hop")
	src.Set("X-Hop", "drop")
	src.Set("X-Also-Hop", "drop")
	src.Set("Content-Length", "10")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("X-Keep", "preserve")

	dst := http.Header{}
	copyTokenProxyHeaders(dst, src)

	if dst.Get("X-Keep") != "preserve" {
		t.Fatalf("expected X-Keep to be preserved, got %q", dst.Get("X-Keep"))
	}

	for _, header := range []string{"X-Hop", "X-Also-Hop", "Content-Length", "Keep-Alive", "Connection"} {
		if dst.Get(header) != "" {
			t.Fatalf("expected %s to be stripped, got %q", header, dst.Get(header))
		}
	}
}

func TestIsFormURLEncoded(t *testing.T) {
	t.Parallel()

	if isFormURLEncoded("application/%zz") {
		t.Fatal("expected unexpected media type to be rejected")
	}

	if isFormURLEncoded("application/x-www-form-urlencoded; bad") {
		t.Fatal("expected invalid content type to be rejected")
	}
}

func TestProxyOIDCBearerTokenExchangeErrorsAndRedirect(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid upstream token endpoint realm", func(t *testing.T) {
		t.Parallel()

		bearerAuth := newTestBearerAuth(&config.BearerConfig{UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{Realm: "http://[::1", Service: "upstream"}})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
		)
		if !errors.Is(err, zerr.ErrInvalidUpstreamTokenEndpoint) {
			t.Fatalf("expected invalid upstream token endpoint realm error, got %v", err)
		}
	})

	t.Run("rejects relative upstream token endpoint realm", func(t *testing.T) {
		t.Parallel()

		bearerAuth := newTestBearerAuth(&config.BearerConfig{UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{Realm: "/token", Service: "upstream"}})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
		)
		if !errors.Is(err, zerr.ErrInvalidUpstreamTokenEndpoint) {
			t.Fatalf("expected invalid upstream token endpoint realm error, got %v", err)
		}
	})

	t.Run("rejects insecure upstream token endpoint realm by default", func(t *testing.T) {
		t.Parallel()

		bearerAuth := newTestBearerAuth(&config.BearerConfig{UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{Realm: "http://example.com/token", Service: "upstream"}})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
		)
		if !errors.Is(err, zerr.ErrInvalidUpstreamTokenEndpoint) {
			t.Fatalf("expected invalid upstream token endpoint realm error, got %v", err)
		}
	})

	t.Run("returns form rewrite errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("service=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		bearerAuth := newTestBearerAuth(&config.BearerConfig{
			UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
				Realm:             "http://example.com/token",
				Service:           "upstream",
				AllowInsecureHTTP: true,
			},
		})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			request,
		)
		if !errors.Is(err, zerr.ErrInvalidTokenProxyForm) {
			t.Fatalf("expected invalid form error, got %v", err)
		}
	})

	t.Run("returns request construction errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodGet, "/token", nil)
		request.Method = "bad\nmethod"

		bearerAuth := newTestBearerAuth(&config.BearerConfig{
			UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
				Realm:             "http://example.com/token",
				Service:           "upstream",
				AllowInsecureHTTP: true,
			},
		})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			request,
		)
		if err == nil {
			t.Fatal("expected request construction error")
		}
	})

	t.Run("returns upstream request errors", func(t *testing.T) {
		t.Parallel()

		proxyServer := httptest.NewServer(http.NotFoundHandler())
		upstreamRealm := proxyServer.URL + "/token"
		proxyServer.Close()

		bearerAuth := newTestBearerAuth(&config.BearerConfig{
			UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
				Realm:             upstreamRealm,
				Service:           "upstream",
				AllowInsecureHTTP: true,
			},
		})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
		)
		if err == nil {
			t.Fatal("expected upstream request error")
		}
	})

	t.Run("relays redirect responses", func(t *testing.T) {
		t.Parallel()

		proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, "/next", http.StatusFound)
		}))
		defer proxyServer.Close()

		response := httptest.NewRecorder()
		bearerAuth := newTestBearerAuth(&config.BearerConfig{
			UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
				Realm:             proxyServer.URL + "/token",
				Service:           "upstream",
				AllowInsecureHTTP: true,
			},
		})
		err := bearerAuth.proxyOIDCBearerTokenExchange(
			response,
			httptest.NewRequest(http.MethodGet, "/token", nil),
		)
		if err != nil {
			t.Fatalf("unexpected proxy error: %v", err)
		}

		if response.Code != http.StatusFound {
			t.Fatalf("expected status %d, got %d", http.StatusFound, response.Code)
		}

		if response.Header().Get("Location") != "/next" {
			t.Fatalf("expected redirect location to be relayed, got %q", response.Header().Get("Location"))
		}
	})
}

func TestOIDCBearerTokenExchangeProxyError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{
		Bearer: &config.BearerConfig{
			Realm:   "zot",
			Service: "zot",
			UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
				Realm:   "/token",
				Service: "upstream",
			},
		},
	}

	bearerAuth := newTestBearerAuth(conf.HTTP.Auth.Bearer)

	request := httptest.NewRequest(http.MethodGet, "/zot/auth/token", nil)
	request.SetBasicAuth("user", "not-an-oidc-token")

	response := httptest.NewRecorder()
	bearerAuth.TokenExchangeHandler()(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, response.Code)
	}

	var tokenErr apiErr.Error
	if err := json.Unmarshal(response.Body.Bytes(), &tokenErr); err != nil {
		t.Fatalf("expected JSON proxy error: %v", err)
	}
}

func TestOIDCBearerTokenExchangeRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{
		Realm: "zot",
		OIDC:  []config.BearerOIDCConfig{{Issuer: "https://issuer.example.com", Audiences: []string{"zot"}}},
	}}

	ctlr := NewController(conf)
	ctlr.Router = mux.NewRouter()
	NewRouteHandler(ctlr)

	request := httptest.NewRequest(http.MethodPut, constants.TokenPath, nil)
	response := httptest.NewRecorder()
	ctlr.Router.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, response.Code)
	}
}

func TestOIDCBearerTokenExchangeRejectsMultipleAuthorizationHeaders(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "zot"}}

	bearerAuth := newTestBearerAuth(conf.HTTP.Auth.Bearer)

	request := httptest.NewRequest(http.MethodGet, "/zot/auth/token", nil)
	request.Header.Add("Authorization", "Basic dXNlcjpwYXNz")
	request.Header.Add("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	bearerAuth.TokenExchangeHandler()(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}

func TestOIDCBearerTokenExchangeRequestParseErrors(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "zot"}}

	bearerAuth := newTestBearerAuth(conf.HTTP.Auth.Bearer)

	t.Run("rejects invalid form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, strings.NewReader("password=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		bearerAuth.TokenExchangeHandler()(response, request)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
		}
	})

	t.Run("rejects unreadable form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, nil)
		request.Body = errTokenProxyReadCloser{}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		bearerAuth.TokenExchangeHandler()(response, request)

		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
		}
	})

	t.Run("rejects oversized form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath,
			strings.NewReader(strings.Repeat("a", constants.MaxTokenRequestBodySize+1)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		bearerAuth.TokenExchangeHandler()(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, response.Code)
		}
	})
}

func TestOIDCBearerTokenExchangeRequiresOIDCAuthorizer(t *testing.T) {
	t.Parallel()

	bearerAuth := &BearerAuth{}
	if bearerAuth.TokenExchangeHandler() != nil {
		t.Fatal("expected token exchange handler to be nil without OIDC authorizer")
	}
}
