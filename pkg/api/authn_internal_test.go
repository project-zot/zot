package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestGetOpenIDClaimMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                       string
		authConfig                 *config.AuthConfig
		providerName               string
		expectedIdentityClaim      string
		expectedGroups             string
		expectedIdentityConfigured bool
	}{
		{
			name:                       "nil auth config uses defaults",
			expectedIdentityClaim:      defaultUsernameClaim,
			expectedGroups:             defaultGroupsClaim,
			expectedIdentityConfigured: false,
		},
		{
			name: "empty provider uses defaults",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{},
				},
			},
			expectedIdentityClaim:      defaultUsernameClaim,
			expectedGroups:             defaultGroupsClaim,
			expectedIdentityConfigured: false,
		},
		{
			name: "missing provider uses defaults",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{},
				},
			},
			providerName:               "oidc",
			expectedIdentityClaim:      defaultUsernameClaim,
			expectedGroups:             defaultGroupsClaim,
			expectedIdentityConfigured: false,
		},
		{
			name: "provider without claim mapping uses defaults",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {},
					},
				},
			},
			providerName:               "oidc",
			expectedIdentityClaim:      defaultUsernameClaim,
			expectedGroups:             defaultGroupsClaim,
			expectedIdentityConfigured: false,
		},
		{
			name: "custom username and groups claims",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClaimMapping: &config.ClaimMapping{
								Username: "preferred_username",
								Groups:   "roles",
							},
						},
					},
				},
			},
			providerName:               "oidc",
			expectedIdentityClaim:      "preferred_username",
			expectedGroups:             "roles",
			expectedIdentityConfigured: true,
		},
		{
			name: "custom groups keeps default username",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClaimMapping: &config.ClaimMapping{
								Groups: "roles",
							},
						},
					},
				},
			},
			providerName:               "oidc",
			expectedIdentityClaim:      defaultUsernameClaim,
			expectedGroups:             "roles",
			expectedIdentityConfigured: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identityClaim, groupsClaim, identityConfigured := getOpenIDClaimMapping(test.authConfig, test.providerName)
			assert.Equal(t, test.expectedIdentityClaim, identityClaim)
			assert.Equal(t, test.expectedGroups, groupsClaim)
			assert.Equal(t, test.expectedIdentityConfigured, identityConfigured)
		})
	}

	logger := log.NewTestLogger()

	t.Run("extractOpenIDIdentity_fallbackToEmailWhenConfiguredNonDefaultClaimMissing", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.AuthConfig{
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClaimMapping: &config.ClaimMapping{
							Username: "preferred_username",
						},
					},
				},
			},
		}

		info := &oidc.UserInfo{
			UserInfoProfile: oidc.UserInfoProfile{
				PreferredUsername: "",
			},
			UserInfoEmail: oidc.UserInfoEmail{Email: "user@example.com"},
		}

		identity, groups, ok := extractOpenIDIdentity(logger, authConfig, "oidc", info, nil)
		assert.True(t, ok)
		assert.Equal(t, "user@example.com", identity)
		assert.Empty(t, groups)
	})

	t.Run("extractOpenIDIdentity_explicitDefaultClaimMissingRejects", func(t *testing.T) {
		t.Parallel()

		authConfig := &config.AuthConfig{
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClaimMapping: &config.ClaimMapping{
							Username: "email",
						},
					},
				},
			},
		}

		info := &oidc.UserInfo{
			UserInfoEmail: oidc.UserInfoEmail{Email: ""},
		}

		identity, groups, ok := extractOpenIDIdentity(logger, authConfig, "oidc", info, nil)
		assert.False(t, ok)
		assert.Empty(t, identity)
		assert.Nil(t, groups)
	})

	t.Run("extractOpenIDIdentity_mergesSortsDedupesGroupsFromUserInfoAndIDToken", func(t *testing.T) {
		t.Parallel()

		info := &oidc.UserInfo{
			UserInfoEmail: oidc.UserInfoEmail{Email: "user@example.com"},
			Claims: map[string]any{
				"groups": []any{"b", "a", "", nil, "a"},
			},
		}

		idTokenClaims := map[string]any{
			"groups": []string{"c", "b"},
		}

		identity, groups, ok := extractOpenIDIdentity(logger, nil, "", info, idTokenClaims)
		assert.True(t, ok)
		assert.Equal(t, "user@example.com", identity)
		expected := []string{"a", "b", "c"}
		assert.True(t, slices.Equal(expected, groups))
	})
}

func TestGetOpenIDIdentity(t *testing.T) {
	t.Parallel()

	info := &oidc.UserInfo{
		Subject: "subject-id",
		UserInfoProfile: oidc.UserInfoProfile{
			Name:              "Full Name",
			PreferredUsername: "preferred-user",
		},
		UserInfoEmail: oidc.UserInfoEmail{Email: "user@example.com"},
		Claims: map[string]any{
			"custom_username": "custom-user",
			"numeric":         42,
		},
	}

	tests := []struct {
		name     string
		info     *oidc.UserInfo
		claim    string
		expected string
	}{
		{name: "nil userinfo", claim: defaultUsernameClaim},
		{name: "preferred username", info: info, claim: "preferred_username", expected: "preferred-user"},
		{name: "email", info: info, claim: defaultUsernameClaim, expected: "user@example.com"},
		{name: "subject", info: info, claim: "sub", expected: "subject-id"},
		{name: "name", info: info, claim: "name", expected: "Full Name"},
		{name: "custom string claim", info: info, claim: "custom_username", expected: "custom-user"},
		{name: "custom non-string claim", info: info, claim: "numeric"},
		{name: "missing custom claim", info: info, claim: "missing"},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identity := getOpenIDIdentity(test.info, test.claim)
			assert.Equal(t, test.expected, identity)
		})
	}
}

func TestAppendOpenIDGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		groups        []string
		claims        map[string]any
		claim         string
		expected      []string
		expectedFound bool
	}{
		{
			name:          "appends any slice",
			groups:        []string{"existing"},
			claims:        map[string]any{"roles": []any{"dev", 7}},
			claim:         "roles",
			expected:      []string{"existing", "dev", "7"},
			expectedFound: true,
		},
		{
			name:          "skips nil and empty entries in any slice",
			claims:        map[string]any{"roles": []any{"dev", nil, ""}},
			claim:         "roles",
			expected:      []string{"dev"},
			expectedFound: true,
		},
		{
			name:          "appends string slice",
			claims:        map[string]any{"roles": []string{"admin", "ops"}},
			claim:         "roles",
			expected:      []string{"admin", "ops"},
			expectedFound: true,
		},
		{
			name:          "skips empty entries in string slice",
			claims:        map[string]any{"roles": []string{"admin", "", "ops"}},
			claim:         "roles",
			expected:      []string{"admin", "ops"},
			expectedFound: true,
		},
		{
			name:          "appends non-empty string",
			claims:        map[string]any{"roles": "admin"},
			claim:         "roles",
			expected:      []string{"admin"},
			expectedFound: true,
		},
		{
			name:          "finds empty string",
			claims:        map[string]any{"roles": ""},
			claim:         "roles",
			expected:      nil,
			expectedFound: true,
		},
		{
			name:          "finds empty any slice",
			claims:        map[string]any{"roles": []any{}},
			claim:         "roles",
			expected:      nil,
			expectedFound: true,
		},
		{
			name:          "finds empty string slice",
			claims:        map[string]any{"roles": []string{}},
			claim:         "roles",
			expected:      nil,
			expectedFound: true,
		},
		{
			name:          "does not find missing claim",
			claims:        map[string]any{},
			claim:         "roles",
			expected:      nil,
			expectedFound: false,
		},
		{
			name:          "does not find unsupported claim type",
			claims:        map[string]any{"roles": 7},
			claim:         "roles",
			expected:      nil,
			expectedFound: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			groups, found := appendOpenIDGroups(test.groups, test.claims, test.claim)
			assert.Equal(t, test.expectedFound, found)
			assert.Equal(t, test.expected, groups)
		})
	}
}

func TestAuthorizationSchemeHelpers(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("GET", "/v2/", nil)
	request.Header.Set("Authorization", "Basic")
	assert.False(t, hasBasicAuthorizationHeader(request), "expected malformed Basic header to be ignored")

	request.Header.Set("Authorization", " bearer token ")
	assert.True(t, hasBearerAuthorizationHeader(request), "expected bearer header to be detected case-insensitively")

	request.Header.Set("Authorization", "Basic token")
	assert.True(t, hasBasicAuthorizationHeader(request), "expected basic header to be detected")

	request.Header.Del("Authorization")
	assert.False(t, hasAuthorizationScheme(request, "basic"), "expected missing Authorization header to be ignored")
}

func TestBasicAuthnReturnsFalseWithoutCredentialBackend(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{}
	ctlr := &Controller{Config: conf, Log: log.NewTestLogger()}
	request := httptest.NewRequest("GET", "/v2/_catalog", nil)
	request.SetBasicAuth("alice", "password")
	response := httptest.NewRecorder()

	authenticated, err := (&AuthnMiddleware{htpasswd: NewHTPasswd(log.NewTestLogger())}).basicAuthn(
		ctlr,
		reqCtx.NewUserAccessControl(),
		response,
		request,
	)
	assert.NoError(t, err)
	assert.False(t, authenticated, "expected authentication to fail without configured credential backend")
}

func TestAuthenticateAPIKeyCredentialRequiresMetaDB(t *testing.T) {
	t.Parallel()

	authenticated, err := authenticateAPIKeyCredential(
		&Controller{Log: log.NewTestLogger()},
		reqCtx.NewUserAccessControl(),
		httptest.NewRequest(http.MethodGet, "/v2/repo/tags/list", nil),
		"alice",
		constants.APIKeysPrefix+"key",
	)

	assert.False(t, authenticated)
	assert.Error(t, err)
}

func TestTryAuthnHandlersDoesNotEvaluateAnonymousAccessForBearerCredentials(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{
		APIKey: true,
		Bearer: &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		},
	}
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				AnonymousPolicy: []string{constants.ReadPermission},
			},
		},
	}

	ctlr := &Controller{
		Config: conf,
		Log:    log.NewTestLogger(),
		MetaDB: mocks.MetaDBMock{
			GetUserAPIKeyInfoFn: func(hashedKey string) (string, error) {
				return "alice", nil
			},
			IsAPIKeyExpiredFn: func(_ context.Context, hashedKey string) (bool, error) {
				return false, nil
			},
			UpdateUserAPIKeyLastUsedFn: func(_ context.Context, hashedKey string) error {
				return nil
			},
		},
	}
	bearerAuth := &BearerAuth{authConfig: conf.HTTP.Auth, bearerConfig: conf.HTTP.Auth.Bearer, log: log.NewTestLogger()}
	authnMiddleware := &AuthnMiddleware{bearerAuth: bearerAuth}

	called := false
	next := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		response.WriteHeader(http.StatusAccepted)
	})

	token := newWrappedCredentialBearerToken("alice", constants.APIKeysPrefix+"key")
	request := httptest.NewRequest(http.MethodPut, "/v2/repo/manifests/latest", nil)
	request = mux.SetURLVars(request, map[string]string{"name": "repo", "reference": "latest"})
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	authnMiddleware.tryAuthnHandlers(ctlr)(next).ServeHTTP(response, request)

	assert.True(t, called)
	assert.Equal(t, http.StatusAccepted, response.Code)
}

func TestAuthChallengeHelpers(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	setBearerAuthChallenge(response, &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm"}}, nil)
	assert.Empty(t, response.Header().Get("WWW-Authenticate"))

	response = httptest.NewRecorder()
	setBearerAuthChallenge(response, &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "realm", Service: "service"}}, nil)
	assert.Equal(t, `Bearer realm="realm",service="service",scope=""`, response.Header().Get("WWW-Authenticate"))

	assert.False(t, (&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm"},
		APIKey: true,
	}).ShouldAdvertiseBearerChallenge())
	assert.False(t, (&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm"},
		APIKey: true,
	}).ShouldInitializeBearerAuth())
	assert.True(t, (&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm", Service: "service"},
		APIKey: true,
	}).ShouldAdvertiseBearerChallenge())
	assert.True(t, (&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm", Service: "service"},
		APIKey: true,
	}).ShouldInitializeBearerAuth())

	amw := &AuthnMiddleware{bearerAuth: &BearerAuth{}}
	assert.False(t, amw.shouldChallengeWithBearer(&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm"},
		APIKey: true,
	}))
	assert.True(t, amw.shouldChallengeWithBearer(&config.AuthConfig{
		Bearer: &config.BearerConfig{Realm: "realm", Service: "service"},
		APIKey: true,
	}))

	response = httptest.NewRecorder()
	setBasicAuthChallenge(response, "")
	assert.Equal(t, `Basic realm="Authorization Required"`, response.Header().Get("WWW-Authenticate"))

	response = httptest.NewRecorder()
	setBasicAuthChallenge(response, "zot")
	assert.Equal(t, `Basic realm="zot"`, response.Header().Get("WWW-Authenticate"))
}

func TestCheckVersionSupportChallengeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authConfig    *config.AuthConfig
		realm         string
		sessionClient bool
		wantChallenge string
	}{
		{
			name: "openid only does not advertise basic",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{"oidc": {}},
				},
			},
		},
		{
			name: "basic credential backend uses quoted basic realm",
			authConfig: &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{Path: "/tmp/htpasswd"},
			},
			realm:         "zot",
			wantChallenge: `Basic realm="zot"`,
		},
		{
			name: "bearer token endpoint uses shared bearer challenge",
			authConfig: &config.AuthConfig{
				Bearer: &config.BearerConfig{Realm: "https://auth.example.test/token", Service: "zot"},
				APIKey: true,
			},
			wantChallenge: `Bearer realm="https://auth.example.test/token",service="zot",scope=""`,
		},
		{
			name: "ui session client suppresses challenge",
			authConfig: &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{Path: "/tmp/htpasswd"},
			},
			realm:         "zot",
			sessionClient: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			conf := config.New()
			conf.HTTP.Auth = test.authConfig
			conf.HTTP.Realm = test.realm

			request := httptest.NewRequest(http.MethodGet, "/v2/", nil)
			if test.sessionClient {
				request.Header.Set(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)
			}

			response := httptest.NewRecorder()
			(&RouteHandler{c: &Controller{Config: conf}}).CheckVersionSupport(response, request)

			assert.Equal(t, http.StatusOK, response.Code)
			assert.Equal(t, "registry/2.0", response.Header().Get(constants.DistAPIVersion))
			assert.Equal(t, test.wantChallenge, response.Header().Get("WWW-Authenticate"))
		})
	}
}
