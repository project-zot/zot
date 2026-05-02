//go:build search

package client_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/cli/client"
)

func writeZotFile(t *testing.T, dir, json string) string {
	t.Helper()

	p := filepath.Join(dir, ".zot")
	assert.NoError(t, os.WriteFile(p, []byte(json), 0o600))

	return p
}

func TestReadZliConfigFile_errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfgContents string
		wantSubs    string
		wantErrIs   []error
	}{
		{
			name:        "configs_not_array",
			cfgContents: `{"configs":{"x":1}}`,
			wantSubs:    `field "configs" must be a JSON array`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "configs_element_not_object",
			cfgContents: `{"configs":[1]}`,
			wantSubs:    "must be a JSON object",
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "missing_profile_name",
			cfgContents: `{"configs":[{"url":"https://example.com"}]}`,
			wantSubs:    `"_name" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "empty_profile_name",
			cfgContents: `{"configs":[{"_name":"","url":"https://example.com"}]}`,
			wantSubs:    `"_name" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "profile_name_not_string",
			cfgContents: `{"configs":[{"_name":1,"url":"https://example.com"}]}`,
			wantSubs:    `"_name" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "missing_url",
			cfgContents: `{"configs":[{"_name":"main"}]}`,
			wantSubs:    `"url" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "empty_url",
			cfgContents: `{"configs":[{"_name":"main","url":""}]}`,
			wantSubs:    `"url" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "url_not_string",
			cfgContents: `{"configs":[{"_name":"main","url":123}]}`,
			wantSubs:    `"url" must be a non-empty string`,
			wantErrIs:   []error{zerr.ErrCliBadConfig},
		},
		{
			name:        "missing_configs_field",
			cfgContents: `{}`,
			wantSubs:    "",
			wantErrIs:   []error{zerr.ErrCliBadConfig, zerr.ErrCliMissingConfigsField},
		},
	}

	for _, tableCase := range tests {
		t.Run(tableCase.name, func(t *testing.T) {
			t.Parallel()

			p := writeZotFile(t, t.TempDir(), tableCase.cfgContents)
			_, err := client.ReadZliConfigFile(p)

			require.Error(t, err)

			for _, target := range tableCase.wantErrIs {
				require.ErrorIs(t, err, target)
			}

			if tableCase.wantSubs != "" {
				assert.Contains(t, err.Error(), tableCase.wantSubs)
			}
		})
	}
}

func TestZliConfigFile_RemoveEntry_NotFound(t *testing.T) {
	t.Parallel()

	f := client.ZliConfigFile{
		Configs: []client.ZliConfig{{Name: "only", URL: "https://example.com"}},
	}

	err := f.RemoveEntry("missing")
	assert.ErrorIs(t, err, zerr.ErrConfigNotFound)
}

func TestZliConfig_GetVar(t *testing.T) {
	t.Parallel()

	zliCfg := client.ZliConfig{Name: "main", URL: "https://example.com"}

	okCases := []struct {
		key  string
		want string
	}{
		{"_name", "main"},
		{client.URLFlag, "https://example.com"},
		{"showspinner", ""},
		{"verify-tls", ""},
	}

	for _, okCase := range okCases {
		t.Run(okCase.key, func(t *testing.T) {
			t.Parallel()

			got, err := zliCfg.GetVar(okCase.key)
			require.NoError(t, err)
			assert.Equal(t, okCase.want, got)
		})
	}

	t.Run("illegal_key", func(t *testing.T) {
		t.Parallel()

		_, err := zliCfg.GetVar("not-a-real-key")
		assert.ErrorIs(t, err, zerr.ErrIllegalConfigKey)
	})
}

func TestZliConfig_SetVar(t *testing.T) {
	t.Parallel()

	errCases := []struct {
		name    string
		key     string
		val     string
		wantErr error
	}{
		{"cannot_set_name", "_name", "other", zerr.ErrIllegalConfigKey},
		{"illegal_key", "bogus", "x", zerr.ErrIllegalConfigKey},
		{"invalid_url", client.URLFlag, "not-a-valid-url", zerr.ErrInvalidURL},
	}

	for _, errCase := range errCases {
		t.Run(errCase.name, func(t *testing.T) {
			t.Parallel()

			cfg := client.ZliConfig{Name: "main", URL: "https://example.com"}
			assert.ErrorIs(t, cfg.SetVar(errCase.key, errCase.val), errCase.wantErr)
		})
	}

	t.Run("parses_verify_tls_bool", func(t *testing.T) {
		t.Parallel()

		cfg := client.ZliConfig{Name: "main", URL: "https://example.com"}
		require.NoError(t, cfg.SetVar("verify-tls", "false"))

		v, ok := cfg.VerifyTLS.(bool)
		assert.True(t, ok)
		assert.False(t, v)
	})
}

func TestZliConfig_ResetVar(t *testing.T) {
	t.Parallel()

	base := client.ZliConfig{Name: "main", URL: "https://example.com"}

	errCases := []struct {
		name    string
		key     string
		wantErr error
	}{
		{"url", client.URLFlag, zerr.ErrCannotResetConfigKey},
		{"name", "_name", zerr.ErrCannotResetConfigKey},
		{"illegal_key", "bogus", zerr.ErrIllegalConfigKey},
	}

	for _, errCase := range errCases {
		t.Run(errCase.name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			assert.ErrorIs(t, cfg.ResetVar(errCase.key), errCase.wantErr)
		})
	}

	t.Run("clears_verify_tls", func(t *testing.T) {
		t.Parallel()

		cfg := client.ZliConfig{Name: "main", URL: "https://example.com", VerifyTLS: false}
		require.NoError(t, cfg.ResetVar("verify-tls"))
		assert.Nil(t, cfg.VerifyTLS)
	})
}
