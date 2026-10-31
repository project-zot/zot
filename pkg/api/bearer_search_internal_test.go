package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

// Name-less routes like the search extension are not scope-checked against the token, so a
// traditional bearer token without repository grants must not see any repository there.
func TestBearerAuthUnscopedTokenDeniedOutsideCatalog(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm", Service: "service"}}
	ctlr := &Controller{Config: conf, Log: log.NewTestLogger()}

	bearerAuth := &BearerAuth{
		authConfig:   conf.HTTP.Auth,
		bearerConfig: conf.HTTP.Auth.Bearer,
		log:          ctlr.Log,
		traditional: NewBearerAuthorizer("realm", "service", func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		}),
	}
	authn := &AuthnMiddleware{bearerAuth: bearerAuth, log: ctlr.Log}

	var userAc *reqCtx.UserAccessControl

	handler := authn.tryAuthnHandlers(ctlr)(BaseAuthzHandler(ctlr)(http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			userAc, err = reqCtx.UserAcFromContext(request.Context())
			if err != nil {
				t.Error(err)
			}

			response.WriteHeader(http.StatusOK)
		})))

	testCases := []struct {
		name        string
		method      string
		path        string
		access      []ResourceAccess
		wantAllowed []string
		wantDenied  []string
	}{
		{
			name:       "search with no access grants",
			method:     http.MethodPost,
			path:       constants.FullSearchPrefix,
			wantDenied: []string{"secret/app", "public/app"},
		},
		{
			name:       "search with a catalog-only grant",
			method:     http.MethodPost,
			path:       constants.FullSearchPrefix,
			access:     []ResourceAccess{{Type: "repository", Name: "", Actions: []string{"pull"}}},
			wantDenied: []string{"secret/app", "public/app"},
		},
		{
			name:        "search with a repository grant",
			method:      http.MethodPost,
			path:        constants.FullSearchPrefix,
			access:      []ResourceAccess{{Type: "repository", Name: "public/app", Actions: []string{"pull"}}},
			wantAllowed: []string{"public/app"},
			wantDenied:  []string{"secret/app"},
		},
		{
			name:       "base route with no access grants",
			method:     http.MethodGet,
			path:       constants.RoutePrefix + "/",
			wantDenied: []string{"secret/app"},
		},
		{
			// catalog-only tokens keep listing every repository
			name:        "catalog with a catalog-only grant",
			method:      http.MethodGet,
			path:        constants.RoutePrefix + constants.ExtCatalogPrefix,
			access:      []ResourceAccess{{Type: "repository", Name: "", Actions: []string{"pull"}}},
			wantAllowed: []string{"secret/app", "public/app"},
		},
	}

	for _, testCase := range testCases {
		token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, ClaimsWithAccess{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Access: testCase.access,
		}).SignedString(privateKey)
		if err != nil {
			t.Fatal(err)
		}

		userAc = nil
		request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader("{}"))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK || userAc == nil {
			t.Fatalf("%s: expected the request to reach the handler, got %d: %s",
				testCase.name, response.Code, response.Body.String())
		}

		for _, repo := range testCase.wantAllowed {
			if !userAc.Can(constants.ReadPermission, repo) {
				t.Errorf("%s: expected read access to %s", testCase.name, repo)
			}
		}

		for _, repo := range testCase.wantDenied {
			for _, action := range []string{
				constants.ReadPermission, constants.CreatePermission,
				constants.UpdatePermission, constants.DeletePermission,
			} {
				if userAc.Can(action, repo) {
					t.Errorf("%s: expected %s on %s to be denied", testCase.name, action, repo)
				}
			}
		}
	}
}
