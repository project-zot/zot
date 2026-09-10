//go:build mgmt

package extensions

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMarshalJSONNilHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{APIKey: true})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.True(t, decoded["apikey"].(bool))
	assert.NotContains(t, decoded, "htpasswd")
}

func TestAuthMarshalJSONLDAPOnly(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		LDAP: &struct {
			Address string `json:"address,omitempty" mapstructure:"address"`
		}{Address: "ldap.example.com"},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "ldap")

	htpasswd, ok := decoded["htpasswd"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, htpasswd)
}

func TestAuthMarshalJSONBearerOnlyEmptyHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		HTPasswd: &HTPasswd{},
		Bearer: &BearerConfig{
			Realm:   "https://auth.example.com/token",
			Service: "zot",
		},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "htpasswd")
	assert.NotContains(t, decoded, "ldap")

	bearer, ok := decoded["bearer"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://auth.example.com/token", bearer["realm"])
	assert.Equal(t, "zot", bearer["service"])
}

func TestAuthMarshalJSONOpenIDOnlyEmptyHTPasswd(t *testing.T) {
	t.Parallel()

	buf, err := json.Marshal(Auth{
		HTPasswd: &HTPasswd{},
		OpenID: &OpenIDConfig{
			Providers: map[string]OpenIDProviderConfig{
				"oidc": {Name: "Example"},
			},
		},
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.NotContains(t, decoded, "htpasswd")

	openid, ok := decoded["openid"].(map[string]any)
	require.True(t, ok)
	providers, ok := openid["providers"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, providers, "oidc")
}
