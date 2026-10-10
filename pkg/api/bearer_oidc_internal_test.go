package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

func newOIDCOutageTestServer(t *testing.T, tokenIssuer string) (*httptest.Server, string, *atomic.Bool, *atomic.Int32) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	down := &atomic.Bool{}
	keyRequests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			keyRequests.Add(1)
		}
		if down.Load() {
			http.Error(w, "issuer unavailable", http.StatusServiceUnavailable)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/jwks" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
			}}})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks",
			})
		}
	}))
	t.Cleanup(server.Close)

	if tokenIssuer == "" {
		tokenIssuer = server.URL
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": tokenIssuer, "aud": []string{"zot"}, "sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	return server, "Bearer " + signed, down, keyRequests
}

func TestOIDCIssuerIsolation(t *testing.T) {
	t.Parallel()

	server, header, _, _ := newOIDCOutageTestServer(t, "")
	var requests atomic.Int32
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer unavailable.Close()

	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: unavailable.URL, Audiences: []string{"zot"}},
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := authorizer.Authenticate(ctx, header); err != nil {
		t.Fatalf("healthy issuer must authenticate despite another issuer hanging: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("authentication contacted an unrelated issuer")
	}

	unknown, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: unavailable.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{header, "******", ""} {
		if _, err := unknown.Authenticate(context.Background(), token); err == nil {
			t.Fatal("unknown issuer or malformed token authenticated")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("unknown issuer or malformed token triggered discovery")
	}

	alternate, alternateHeader, _, _ := newOIDCOutageTestServer(t, "https://alternate.example")
	skipIssuer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: alternate.URL, Audiences: []string{"zot"}, SkipIssuerVerification: true},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := skipIssuer.Authenticate(context.Background(), alternateHeader); err != nil {
		t.Fatalf("skipIssuerVerification must still allow a different token issuer: %v", err)
	}
}

func TestOIDCVerifierRefreshRetainsKeys(t *testing.T) {
	t.Parallel()

	server, header, down, keyRequests := newOIDCOutageTestServer(t, "")
	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
		t.Fatal(err)
	}

	provider := authorizer.providers[0]
	for _, unavailable := range []bool{false, true} {
		down.Store(unavailable)
		provider.verifierMu.Lock()
		provider.verifierDeadline = time.Time{}
		provider.verifierMu.Unlock()

		if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
			t.Fatalf("cached token must authenticate during discovery refresh (down=%v): %v", unavailable, err)
		}
		provider.verifierMu.RLock()
		done := provider.refreshDone
		provider.verifierMu.RUnlock()
		if done != nil {
			<-done
		}
		if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
			t.Fatalf("cached token must authenticate after discovery refresh (down=%v): %v", unavailable, err)
		}
		if keyRequests.Load() != 1 {
			t.Fatalf("discovery refresh discarded cached keys: %d JWKS requests", keyRequests.Load())
		}
	}
}

func TestOIDCHTTPTimeout(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"/.well-known/openid-configuration", "/jwks"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == endpoint {
					<-r.Context().Done()

					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks",
				})
			}))
			defer server.Close()
			_, header, _, _ := newOIDCOutageTestServer(t, server.URL)
			authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
				{Issuer: server.URL, Audiences: []string{"zot"}},
			}, log.NewTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			provider := authorizer.providers[0]
			if provider.httpClient == nil || provider.httpClient.Timeout != oidcHTTPTimeout {
				t.Fatal("OIDC HTTP client must have a timeout by default")
			}
			provider.httpClient.Timeout = 50 * time.Millisecond

			done := make(chan error, 1)
			go func() {
				_, err := authorizer.Authenticate(context.Background(), header)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("hanging endpoint must fail authentication")
				}
			case <-time.After(time.Second):
				t.Fatal("OIDC network request did not time out")
			}
		})
	}
}

func TestNewBearerAuthCreatesOIDCBearerAuthorizer(t *testing.T) {
	t.Parallel()

	authConfig := &config.AuthConfig{Bearer: &config.BearerConfig{
		OIDC: config.BearerOIDCConfigs{{
			Issuer:    "https://issuer.example.com",
			Audiences: []string{"zot"},
		}},
	}}

	bearerAuth := NewBearerAuth(authConfig, log.NewTestLogger())
	if bearerAuth.oidc == nil {
		t.Fatal("expected OIDC bearer authorizer")
	}

	if bearerAuth.TokenExchangeHandler(nil) == nil {
		t.Fatal("expected OIDC bearer token exchange handler")
	}
}

func TestNewBearerAuthOIDCBearerAuthorizerInvalidConfigPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid OIDC bearer config")
		}
	}()

	NewBearerAuth(&config.AuthConfig{Bearer: &config.BearerConfig{
		OIDC: config.BearerOIDCConfigs{{
			Issuer:               "https://issuer.example.com",
			Audiences:            []string{"zot"},
			CertificateAuthority: "not a valid PEM certificate",
		}},
	}}, log.NewTestLogger())
}

func TestRouteSetupRegistersOIDCBearerTokenHandler(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{
		Bearer: &config.BearerConfig{
			OIDC: config.BearerOIDCConfigs{{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"zot"},
			}},
		},
	}

	ctlr := NewController(conf)
	ctlr.Router = mux.NewRouter()
	NewRouteHandler(ctlr)

	request := httptest.NewRequest(http.MethodOptions, constants.TokenPath, nil)
	response := httptest.NewRecorder()
	ctlr.Router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected token exchange OPTIONS status %d, got %d", http.StatusNoContent, response.Code)
	}
}
