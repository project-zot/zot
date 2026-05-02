//go:build search

package client

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	jsoniter "github.com/json-iterator/go"

	zerr "zotregistry.dev/zot/v2/errors"
)

const (
	defaultConfigPerms = 0o644
	defaultFilePerms   = 0o600

	nameKey           = "_name"
	showspinnerConfig = "showspinner"
	verifyTLSConfig   = "verify-tls"
)

// ZliConfigFile is the on-disk JSON shape for ~/.zot (zli CLI registry profiles).
type ZliConfigFile struct {
	Configs []ZliConfig `json:"configs"`
}

// ZliConfig is one named registry profile inside ZliConfigFile.Configs.
type ZliConfig struct {
	Name        string `json:"_name"` //nolint:tagliatelle // persisted ~/.zot schema uses `_name`
	URL         string `json:"url"`
	ShowSpinner any    `json:"showspinner,omitempty"`
	VerifyTLS   any    `json:"verify-tls,omitempty"` //nolint:tagliatelle // hyphenated ~/.zot key
}

// isConfigUnavailable reports errors that mean there is no usable ~/.zot config yet (empty file
// or JSON without a "configs" field). Those cases are treated like an empty config for some commands.
func isConfigUnavailable(err error) bool {
	return errors.Is(err, zerr.ErrEmptyJSON) || errors.Is(err, zerr.ErrCliMissingConfigsField)
}

// ReadZliConfigFile reads and validates ~/.zot JSON from path.
//
// If the path does not exist yet, OpenFile(..., O_CREATE) creates an empty file first so later
// ReadFile sees zero bytes and returns [ErrEmptyJSON] ("fresh" CLI state). Adding entries via
// `zli config add` still works without relying on this side effect.
func ReadZliConfigFile(filePath string) (*ZliConfigFile, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, defaultConfigPerms)
	if err != nil {
		return nil, err
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return nil, zerr.ErrEmptyJSON
	}

	json := jsoniter.ConfigCompatibleWithStandardLibrary

	var jsonMap map[string]any
	if unmarshalErr := json.Unmarshal(data, &jsonMap); unmarshalErr != nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrCliBadConfig, unmarshalErr)
	}

	if _, ok := jsonMap["configs"]; !ok || jsonMap["configs"] == nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrCliBadConfig, zerr.ErrCliMissingConfigsField)
	}

	configsAny, ok := jsonMap["configs"].([]any)
	if !ok {
		return nil, fmt.Errorf(
			`%w: field "configs" must be a JSON array, got %T`,
			zerr.ErrCliBadConfig, jsonMap["configs"])
	}

	out := &ZliConfigFile{Configs: make([]ZliConfig, 0, len(configsAny))}

	for i, v := range configsAny {
		configMap, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf(
				`%w: configs[%d] must be a JSON object, got %T`,
				zerr.ErrCliBadConfig, i, v)
		}

		c, err := zliConfigFromMap(configMap, i)
		if err != nil {
			return nil, err
		}

		out.Configs = append(out.Configs, c)
	}

	return out, nil
}

func zliConfigFromMap(configMap map[string]any, i int) (ZliConfig, error) {
	nameRaw, nameOk := configMap[nameKey]
	nameStr, nameIsStr := nameRaw.(string)
	if !nameOk || !nameIsStr || strings.TrimSpace(nameStr) == "" {
		return ZliConfig{}, fmt.Errorf(
			`%w: configs[%d]: "_name" must be a non-empty string`,
			zerr.ErrCliBadConfig, i)
	}

	urlRaw, urlOk := configMap[URLFlag]
	urlStr, urlIsStr := urlRaw.(string)
	if !urlOk || !urlIsStr || strings.TrimSpace(urlStr) == "" {
		return ZliConfig{}, fmt.Errorf(
			`%w: configs[%d]: "url" must be a non-empty string`,
			zerr.ErrCliBadConfig, i)
	}

	profile := ZliConfig{
		Name: nameStr,
		URL:  urlStr,
	}

	if showSpinner, ok := configMap[showspinnerConfig]; ok {
		profile.ShowSpinner = showSpinner
	}

	if verifyTLS, ok := configMap[verifyTLSConfig]; ok {
		profile.VerifyTLS = verifyTLS
	}

	return profile, nil
}

// WriteFile marshals this config to path with standard zli permissions.
func (f *ZliConfigFile) WriteFile(filePath string) error {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	cfg := *f
	if cfg.Configs == nil {
		cfg.Configs = []ZliConfig{}
	}

	marshalled, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, marshalled, defaultFilePerms); err != nil {
		return err
	}

	return nil
}

// Find returns the profile with the given name, applying defaults to the matched entry.
func (f *ZliConfigFile) Find(configName string) (*ZliConfig, error) {
	for i := range f.Configs {
		if f.Configs[i].Name == configName {
			f.Configs[i].ApplyDefaults()

			return &f.Configs[i], nil
		}
	}

	return nil, zerr.ErrConfigNotFound
}

// HasEntry reports whether a profile name already exists.
func (f *ZliConfigFile) HasEntry(configName string) bool {
	return slices.ContainsFunc(f.Configs, func(c ZliConfig) bool {
		return c.Name == configName
	})
}

// AddEntry appends a new profile after validating URL and duplicate names.
func (f *ZliConfigFile) AddEntry(configName, urlStr string) error {
	if err := validateURL(urlStr); err != nil {
		return err
	}

	if f.HasEntry(configName) {
		return zerr.ErrDuplicateConfigName
	}

	c := ZliConfig{
		Name: configName,
		URL:  urlStr,
	}
	c.ApplyDefaults()
	f.Configs = append(f.Configs, c)

	return nil
}

// RemoveEntry removes a profile by name.
func (f *ZliConfigFile) RemoveEntry(configName string) error {
	for i, c := range f.Configs {
		if c.Name != configName {
			continue
		}

		f.Configs = append(f.Configs[:i], f.Configs[i+1:]...)

		return nil
	}

	return zerr.ErrConfigNotFound
}

// FormatNames renders name and URL columns for `zli config --list`.
func (f *ZliConfigFile) FormatNames() (string, error) {
	var builder strings.Builder

	writer := tabwriter.NewWriter(&builder, 0, 8, 1, '\t', tabwriter.AlignRight) //nolint:mnd

	for _, c := range f.Configs {
		fmt.Fprintf(writer, "%s\t%s\n", c.Name, c.URL)
	}

	if err := writer.Flush(); err != nil {
		return "", err
	}

	return builder.String(), nil
}

// ApplyDefaults sets omitted boolean fields to their CLI defaults (mutates receiver).
func (c *ZliConfig) ApplyDefaults() {
	if c.ShowSpinner == nil {
		c.ShowSpinner = true
	}

	if c.VerifyTLS == nil {
		c.VerifyTLS = true
	}
}

// GetVar returns a single setting as text (after defaults apply via Find).
func (c *ZliConfig) GetVar(key string) (string, error) {
	switch key {
	case nameKey:
		return c.Name, nil
	case URLFlag:
		return c.URL, nil
	case showspinnerConfig:
		if c.ShowSpinner == nil {
			return "", nil
		}

		return fmt.Sprintf("%v", c.ShowSpinner), nil
	case verifyTLSConfig:
		if c.VerifyTLS == nil {
			return "", nil
		}

		return fmt.Sprintf("%v", c.VerifyTLS), nil
	default:
		return "", zerr.ErrIllegalConfigKey
	}
}

// SetVar updates url / showspinner / verify-tls (does not persist).
func (c *ZliConfig) SetVar(key, value string) error {
	if key == nameKey {
		return zerr.ErrIllegalConfigKey
	}

	if key != URLFlag && key != showspinnerConfig && key != verifyTLSConfig {
		return zerr.ErrIllegalConfigKey
	}

	boolVal, parseErr := strconv.ParseBool(value)
	out := any(value)
	if parseErr == nil {
		out = boolVal
	}

	switch key {
	case URLFlag:
		if err := validateURL(value); err != nil {
			return err
		}

		c.URL = value
	case showspinnerConfig:
		c.ShowSpinner = out
	case verifyTLSConfig:
		c.VerifyTLS = out
	}

	return nil
}

// ResetVar clears optional booleans (does not persist).
func (c *ZliConfig) ResetVar(key string) error {
	switch key {
	case URLFlag, nameKey:
		return zerr.ErrCannotResetConfigKey
	case showspinnerConfig:
		c.ShowSpinner = nil
	case verifyTLSConfig:
		c.VerifyTLS = nil
	default:
		return zerr.ErrIllegalConfigKey
	}

	return nil
}

// FormatListedVars renders lines for `zli config <name> --list`.
func (c *ZliConfig) FormatListedVars() string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "%s = %v\n", URLFlag, c.URL)
	fmt.Fprintf(&builder, "%s = %v\n", showspinnerConfig, c.ShowSpinner)
	fmt.Fprintf(&builder, "%s = %v\n", verifyTLSConfig, c.VerifyTLS)

	return builder.String()
}
