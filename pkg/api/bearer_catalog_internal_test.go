package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestBearerAuthCatalogRequiresLegacyScope(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm", Service: "service"}}
	conf.HTTP.AccessControl = &config.AccessControlConfig{}
	ctlr := &Controller{Config: conf, Log: log.NewTestLogger()}

	repositories := []string{"private/one", "private/two"}
	ctlr.StoreController = storage.StoreController{DefaultStore: mocks.MockedImageStore{
		GetNextRepositoriesFn: func(_ string, _ int, filter storageTypes.FilterRepoFunc) ([]string, bool, error) {
			filtered := []string{}
			for _, repo := range repositories {
				allowed, err := filter(repo)
				if err != nil {
					return nil, false, err
				}

				if allowed {
					filtered = append(filtered, repo)
				}
			}

			return filtered, false, nil
		},
	}}

	bearerAuth := &BearerAuth{
		authConfig:   conf.HTTP.Auth,
		bearerConfig: conf.HTTP.Auth.Bearer,
		log:          ctlr.Log,
		traditional: NewBearerAuthorizer("realm", "service", func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		}),
	}
	authn := &AuthnMiddleware{bearerAuth: bearerAuth, log: ctlr.Log}
	routeHandler := &RouteHandler{c: ctlr}
	handler := authn.tryAuthnHandlers(ctlr)(BaseAuthzHandler(ctlr)(http.HandlerFunc(routeHandler.ListRepositories)))

	testCases := []struct {
		name       string
		access     []ResourceAccess
		wantStatus int
	}{
		{
			name:       "no access grants",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "repository grant without catalog permission",
			access:     []ResourceAccess{{Type: "repository", Name: "private/one", Actions: []string{"pull"}}},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired catalog grant",
			access: []ResourceAccess{{
				Type: "repository", Name: "", Actions: []string{"pull"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			}},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "legacy catalog grant",
			access:     []ResourceAccess{{Type: "repository", Name: "", Actions: []string{"pull"}}},
			wantStatus: http.StatusOK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
				Access:           testCase.access,
			}).SignedString(privateKey)
			if err != nil {
				t.Fatal(err)
			}

			for _, path := range []string{"/v2/_catalog", "/v2/_catalog?n=10"} {
				t.Run(path, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodGet, path, nil)
					request.Header.Set("Authorization", "Bearer "+token)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)

					if response.Code != testCase.wantStatus {
						t.Fatalf("expected status %d, got %d: %s", testCase.wantStatus, response.Code, response.Body.String())
					}

					if testCase.wantStatus == http.StatusUnauthorized {
						if challenge := response.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `scope="repository::pull"`) {
							t.Fatalf("expected legacy catalog scope challenge, got %q", challenge)
						}

						return
					}

					var catalog RepositoryList
					if err := json.Unmarshal(response.Body.Bytes(), &catalog); err != nil {
						t.Fatal(err)
					}

					if !slices.Equal(catalog.Repositories, repositories) {
						t.Fatalf("expected catalog %v, got %v", repositories, catalog.Repositories)
					}
				})
			}
		})
	}
}
