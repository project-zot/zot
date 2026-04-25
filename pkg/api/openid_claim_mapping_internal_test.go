//go:build sync && scrub && metrics && search && lint && mgmt

package api

import (
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestGetOpenIDClaimMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		authConfig         *config.AuthConfig
		providerName       string
		expectedUsername   string
		expectedGroups     string
		expectedConfigured bool
	}{
		{
			name:               "nil auth config uses defaults",
			expectedUsername:   defaultUsernameClaim,
			expectedGroups:     defaultGroupsClaim,
			expectedConfigured: false,
		},
		{
			name: "empty provider uses defaults",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{},
				},
			},
			expectedUsername:   defaultUsernameClaim,
			expectedGroups:     defaultGroupsClaim,
			expectedConfigured: false,
		},
		{
			name: "missing provider uses defaults",
			authConfig: &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{},
				},
			},
			providerName:       "oidc",
			expectedUsername:   defaultUsernameClaim,
			expectedGroups:     defaultGroupsClaim,
			expectedConfigured: false,
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
			providerName:       "oidc",
			expectedUsername:   defaultUsernameClaim,
			expectedGroups:     defaultGroupsClaim,
			expectedConfigured: false,
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
			providerName:       "oidc",
			expectedUsername:   "preferred_username",
			expectedGroups:     "roles",
			expectedConfigured: true,
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
			providerName:       "oidc",
			expectedUsername:   defaultUsernameClaim,
			expectedGroups:     "roles",
			expectedConfigured: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			usernameClaim, groupsClaim, usernameConfigured := getOpenIDClaimMapping(test.authConfig, test.providerName)
			if usernameClaim != test.expectedUsername {
				t.Fatalf("expected username claim %q, got %q", test.expectedUsername, usernameClaim)
			}

			if groupsClaim != test.expectedGroups {
				t.Fatalf("expected groups claim %q, got %q", test.expectedGroups, groupsClaim)
			}

			if usernameConfigured != test.expectedConfigured {
				t.Fatalf("expected usernameConfigured %t, got %t", test.expectedConfigured, usernameConfigured)
			}
		})
	}
}

func TestGetOpenIDUsername(t *testing.T) {
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

			username := getOpenIDUsername(test.info, test.claim)
			if username != test.expected {
				t.Fatalf("expected username %q, got %q", test.expected, username)
			}
		})
	}
}

func TestAppendOpenIDGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		groups   []string
		claims   map[string]any
		claim    string
		expected []string
	}{
		{
			name:     "appends any slice",
			groups:   []string{"existing"},
			claims:   map[string]any{"roles": []any{"dev", 7}},
			claim:    "roles",
			expected: []string{"existing", "dev", "7"},
		},
		{
			name:     "appends string slice",
			claims:   map[string]any{"roles": []string{"admin", "ops"}},
			claim:    "roles",
			expected: []string{"admin", "ops"},
		},
		{
			name:     "appends non-empty string",
			claims:   map[string]any{"roles": "admin"},
			claim:    "roles",
			expected: []string{"admin"},
		},
		{
			name:     "ignores empty string",
			claims:   map[string]any{"roles": ""},
			claim:    "roles",
			expected: nil,
		},
		{
			name:     "ignores missing claim",
			claims:   map[string]any{},
			claim:    "roles",
			expected: nil,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			groups := appendOpenIDGroups(test.groups, test.claims, test.claim)
			if len(groups) != len(test.expected) {
				t.Fatalf("expected groups %v, got %v", test.expected, groups)
			}

			for i := range test.expected {
				if groups[i] != test.expected[i] {
					t.Fatalf("expected groups %v, got %v", test.expected, groups)
				}
			}
		})
	}
}
