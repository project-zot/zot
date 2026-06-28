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

func TestControllerReusesOIDCBearerAuthorizer(t *testing.T) {
	t.Parallel()

	ctlr := &Controller{Log: log.NewTestLogger()}
	oidcConfig := config.BearerOIDCConfigs{{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"zot"},
	}}

	first := ctlr.getOIDCBearerAuthorizer(oidcConfig)
	if first == nil {
		t.Fatal("expected OIDC bearer authorizer")
	}

	second := ctlr.getOIDCBearerAuthorizer(oidcConfig)
	if first != second {
		t.Fatal("expected controller to reuse OIDC bearer authorizer")
	}
}

func TestControllerOIDCBearerAuthorizerInvalidConfigPanics(t *testing.T) {
	t.Parallel()

	ctlr := &Controller{Log: log.NewTestLogger()}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid OIDC bearer config")
		}
	}()

	ctlr.getOIDCBearerAuthorizer(config.BearerOIDCConfigs{{
		Audiences: []string{"zot"},
	}})
}

func TestRouteSetupReusesOIDCBearerAuthorizer(t *testing.T) {
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

	if ctlr.oidcBearerAuthz == nil {
		t.Fatal("expected route setup to initialize OIDC bearer authorizer")
	}

	request := httptest.NewRequest(http.MethodOptions, constants.TokenPath, nil)
	response := httptest.NewRecorder()
	ctlr.Router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected token exchange OPTIONS status %d, got %d", http.StatusNoContent, response.Code)
	}
}
