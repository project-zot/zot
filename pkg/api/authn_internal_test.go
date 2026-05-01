package api

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
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
