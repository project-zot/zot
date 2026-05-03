//go:build search

package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
)

func writeTestZotFile(t *testing.T, dir, content string) string {
	t.Helper()

	path := filepath.Join(dir, ".zot")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

// tempConfigPath returns ~/.zot path under an isolated temp dir; when writeFile is true, writes cfgContents first.
func tempConfigPath(t *testing.T, writeFile bool, cfgContents string) string {
	t.Helper()

	dir := t.TempDir()
	if writeFile {
		return writeTestZotFile(t, dir, cfgContents)
	}

	return filepath.Join(dir, ".zot")
}

func TestGetConfigValue(t *testing.T) {
	t.Parallel()

	validProfile := `{"configs":[{"_name":"a","url":"https://example.com"}]}`

	tests := []struct {
		name           string
		cfgContents    string // ignored when writeFile is false (missing ~/.zot until read)
		writeFile      bool
		configName     string
		wantErrIs      error
		wantCliBadWrap bool // errors.Is(_, ErrCliBadConfig); implies !isConfigUnavailable
	}{
		{
			name:       "fresh_missing_file_ErrConfigNotFound",
			writeFile:  false,
			configName: "any",
			wantErrIs:  zerr.ErrConfigNotFound,
		},
		{
			name:        "fresh_empty_configs_ErrConfigNotFound",
			cfgContents: `{}`,
			writeFile:   true,
			configName:  "any",
			wantErrIs:   zerr.ErrConfigNotFound,
		},
		{
			name:           "read_invalid_JSON_ErrCliBadConfig",
			cfgContents:    `not-json`,
			writeFile:      true,
			configName:     "any",
			wantCliBadWrap: true,
		},
		{
			name:        "profile_not_found_ErrConfigNotFound",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "missing",
			wantErrIs:   zerr.ErrConfigNotFound,
		},
	}

	for _, tableCase := range tests {
		t.Run(tableCase.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := tempConfigPath(t, tableCase.writeFile, tableCase.cfgContents)

			got, err := getConfigValue(cfgPath, tableCase.configName, URLFlag)

			switch {
			case tableCase.wantCliBadWrap:
				require.Error(t, err)
				require.False(t, isConfigUnavailable(err))
				require.True(t, errors.Is(err, zerr.ErrCliBadConfig))
				require.Equal(t, "", got)
			case tableCase.wantErrIs != nil:
				require.ErrorIs(t, err, tableCase.wantErrIs)
				require.Equal(t, "", got)
			default:
				require.Failf(t, "table row must set wantErrIs or wantCliBadWrap: %s", tableCase.name)
			}
		})
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := writeTestZotFile(t, dir, validProfile)

		got, err := getConfigValue(cfgPath, "a", URLFlag)
		require.NoError(t, err)
		require.Equal(t, "https://example.com", got)
	})
}

func TestResetConfigValue(t *testing.T) {
	t.Parallel()

	validProfile := `{"configs":[{"_name":"a","url":"https://example.com"}]}`

	tests := []struct {
		name           string
		cfgContents    string
		writeFile      bool
		configName     string
		key            string
		wantErrIs      error
		wantCliBadWrap bool
	}{
		{
			name:       "fresh_ErrConfigNotFound",
			writeFile:  false,
			configName: "any",
			key:        showspinnerConfig,
			wantErrIs:  zerr.ErrConfigNotFound,
		},
		{
			name:       "cannot_reset_URL_before_read",
			writeFile:  false,
			configName: "any",
			key:        URLFlag,
			wantErrIs:  zerr.ErrCannotResetConfigKey,
		},
		{
			name:           "read_invalid_JSON_ErrCliBadConfig",
			cfgContents:    `not-json`,
			writeFile:      true,
			configName:     "a",
			key:            showspinnerConfig,
			wantCliBadWrap: true,
		},
		{
			name:        "profile_not_found_ErrConfigNotFound",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "nobody",
			key:         showspinnerConfig,
			wantErrIs:   zerr.ErrConfigNotFound,
		},
		{
			name:        "ResetVar_illegal_key_ErrIllegalConfigKey",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "a",
			key:         "bogus-key",
			wantErrIs:   zerr.ErrIllegalConfigKey,
		},
	}

	for _, tableCase := range tests {
		t.Run(tableCase.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := tempConfigPath(t, tableCase.writeFile, tableCase.cfgContents)

			err := resetConfigValue(cfgPath, tableCase.configName, tableCase.key)

			switch {
			case tableCase.wantCliBadWrap:
				require.Error(t, err)
				require.False(t, isConfigUnavailable(err))
				require.True(t, errors.Is(err, zerr.ErrCliBadConfig))
			case tableCase.wantErrIs != nil:
				require.ErrorIs(t, err, tableCase.wantErrIs)
			default:
				require.Failf(t, "incomplete table case: %s", tableCase.name)
			}
		})
	}

	t.Run("success_ResetVar_verify_tls_then_WriteFile", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := writeTestZotFile(t, dir,
			`{"configs":[{"_name":"a","url":"https://example.com","verify-tls":false}]}`)

		require.NoError(t, resetConfigValue(cfgPath, "a", verifyTLSConfig))

		cfg, err := ReadZliConfigFile(cfgPath)
		require.NoError(t, err)
		require.Len(t, cfg.Configs, 1)
		require.Nil(t, cfg.Configs[0].VerifyTLS)
	})
}

func TestSetConfigValue(t *testing.T) {
	t.Parallel()

	validProfile := `{"configs":[{"_name":"a","url":"https://example.com"}]}`

	tests := []struct {
		name           string
		cfgContents    string
		writeFile      bool
		configName     string
		key            string
		val            string
		wantErrIs      error
		wantCliBadWrap bool
	}{
		{
			name:       "fresh_ErrConfigNotFound",
			writeFile:  false,
			configName: "any",
			key:        URLFlag,
			val:        "https://example.com",
			wantErrIs:  zerr.ErrConfigNotFound,
		},
		{
			name:           "read_invalid_JSON_ErrCliBadConfig",
			cfgContents:    `not-json`,
			writeFile:      true,
			configName:     "a",
			key:            URLFlag,
			val:            "https://example.com",
			wantCliBadWrap: true,
		},
		{
			name:        "profile_not_found_ErrConfigNotFound",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "nobody",
			key:         URLFlag,
			val:         "https://other.example",
			wantErrIs:   zerr.ErrConfigNotFound,
		},
		{
			name:        "SetVar_invalid_URL_ErrInvalidURL",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "a",
			key:         URLFlag,
			val:         "not-a-valid-url",
			wantErrIs:   zerr.ErrInvalidURL,
		},
		{
			name:        "SetVar_illegal_key_ErrIllegalConfigKey",
			cfgContents: validProfile,
			writeFile:   true,
			configName:  "a",
			key:         "bogus-key",
			val:         "x",
			wantErrIs:   zerr.ErrIllegalConfigKey,
		},
		{
			name:       "illegal_name_key_before_read_ErrIllegalConfigKey",
			writeFile:  false,
			configName: "any",
			key:        nameKey,
			val:        "other",
			wantErrIs:  zerr.ErrIllegalConfigKey,
		},
	}

	for _, tableCase := range tests {
		t.Run(tableCase.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := tempConfigPath(t, tableCase.writeFile, tableCase.cfgContents)

			err := setConfigValue(cfgPath, tableCase.configName, tableCase.key, tableCase.val)

			switch {
			case tableCase.wantCliBadWrap:
				require.Error(t, err)
				require.False(t, isConfigUnavailable(err))
				require.True(t, errors.Is(err, zerr.ErrCliBadConfig))
			case tableCase.wantErrIs != nil:
				require.ErrorIs(t, err, tableCase.wantErrIs)
			default:
				require.Failf(t, "incomplete table case: %s", tableCase.name)
			}
		})
	}

	t.Run("success_SetVar_then_WriteFile", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := writeTestZotFile(t, dir, validProfile)

		require.NoError(t, setConfigValue(cfgPath, "a", showspinnerConfig, "false"))

		got, err := getConfigValue(cfgPath, "a", showspinnerConfig)
		require.NoError(t, err)
		require.Equal(t, "false", got)
	})
}

func TestConfigCmd_listFreshAndFindErrors(t *testing.T) {
	t.Parallel()

	validProfile := `{"configs":[{"_name":"a","url":"https://example.com"}]}`

	tests := []struct {
		name        string
		writeFile   bool
		cfgContents string
		runGetAll   bool
		configName  string // only when runGetAll && wantErrIs != nil (Find miss)
		wantOut     string
		wantErrIs   error
	}{
		{
			name:      "getAllConfig_fresh_returns_empty",
			runGetAll: true,
			wantOut:   "",
		},
		{
			name:        "getAllConfig_unknown_profile_ErrConfigNotFound",
			writeFile:   true,
			cfgContents: validProfile,
			runGetAll:   true,
			configName:  "missing",
			wantErrIs:   zerr.ErrConfigNotFound,
		},
		{
			name:    "getConfigNames_fresh_returns_empty",
			wantOut: "",
		},
	}

	for _, tableCase := range tests {
		t.Run(tableCase.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := tempConfigPath(t, tableCase.writeFile, tableCase.cfgContents)

			switch {
			case tableCase.runGetAll && tableCase.wantErrIs != nil:
				_, err := getAllConfig(cfgPath, tableCase.configName)
				require.ErrorIs(t, err, tableCase.wantErrIs)
			case tableCase.runGetAll:
				out, err := getAllConfig(cfgPath, "any")
				require.NoError(t, err)
				require.Equal(t, tableCase.wantOut, out)
			default:
				out, err := getConfigNames(cfgPath)
				require.NoError(t, err)
				require.Equal(t, tableCase.wantOut, out)
			}
		})
	}
}
