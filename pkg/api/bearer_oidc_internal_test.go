package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

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

	if bearerAuth.TokenExchangeHandler() == nil {
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
