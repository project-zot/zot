package config

import (
	"time"

	"zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

// BaseConfig has params applicable to all extensions.
type BaseConfig struct {
	Enable *bool `mapstructure:",omitempty"`
}

type ExtensionConfig struct {
	Search  *SearchConfig
	Sync    *sync.Config
	Metrics *MetricsConfig
	Scrub   *ScrubConfig
	Lint    *LintConfig
	UI      *UIConfig
	Mgmt    *MgmtConfig
	APIKey  *APIKeyConfig
	Trust   *ImageTrustConfig
	Events  *events.Config
}

type ImageTrustConfig struct {
	BaseConfig `mapstructure:",squash"`

	Cosign   bool
	Notation bool
}

type APIKeyConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type MgmtConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type LintConfig struct {
	BaseConfig `mapstructure:",squash"`

	MandatoryAnnotations []string
}

type SearchConfig struct {
	BaseConfig `mapstructure:",squash"`

	CVE *CVEConfig
}

type CVEConfig struct {
	UpdateInterval time.Duration // should be 2 hours or more, if not specified default be kept as 2 hours
	Trivy          *TrivyConfig
}

type TrivyConfig struct {
	DBRepository     string // default is "ghcr.io/aquasecurity/trivy-db"
	JavaDBRepository string // default is "ghcr.io/aquasecurity/trivy-java-db"
}

type MetricsConfig struct {
	BaseConfig `mapstructure:",squash"`

	Prometheus *PrometheusConfig
}

type PrometheusConfig struct {
	Path string // default is "/metrics"
}

type ScrubConfig struct {
	BaseConfig `mapstructure:",squash"`

	Interval time.Duration
}

type UIConfig struct {
	BaseConfig `mapstructure:",squash"`
}

// isSearchEnabledInternal checks if search is enabled (internal use only).
func (e *ExtensionConfig) isSearchEnabledInternal() bool {
	return e != nil && e.Search != nil && e.Search.Enable != nil && *e.Search.Enable
}

// isUIEnabledInternal checks if UI is enabled (internal use only).
func (e *ExtensionConfig) isUIEnabledInternal() bool {
	return e != nil && e.UI != nil && e.UI.Enable != nil && *e.UI.Enable
}

// IsCveScanningEnabled checks if CVE scanning is enabled in this extensions config.
func (e *ExtensionConfig) IsCveScanningEnabled() bool {
	if e == nil {
		return false
	}

	return e.Search != nil && e.Search.Enable != nil && *e.Search.Enable &&
		e.Search.CVE != nil && e.Search.CVE.Trivy != nil
}

// IsEventRecorderEnabled checks if event recording is enabled in this extensions config.
func (e *ExtensionConfig) IsEventRecorderEnabled() bool {
	if e == nil {
		return false
	}

	return e.Events != nil && e.Events.Enable != nil && *e.Events.Enable
}

// IsSearchEnabled checks if search is enabled in this extensions config.
func (e *ExtensionConfig) IsSearchEnabled() bool {
	return e.isSearchEnabledInternal()
}

// IsSyncEnabled checks if sync is enabled in this extensions config.
func (e *ExtensionConfig) IsSyncEnabled() bool {
	if e == nil {
		return false
	}

	// Sync is enabled if either:
	// 1. Explicitly enabled (Enable == true), OR
	// 2. There are registries configured (enabled by default when registries exist)
	// This matches the behavior in root.go where Sync.Enable defaults to true when registries are present
	return e.Sync != nil && ((e.Sync.Enable != nil && *e.Sync.Enable) ||
		(e.Sync.Enable == nil && len(e.Sync.Registries) > 0))
}

// IsStreamingEnabled checks if streaming is enabled in this extensions config.
func (e *ExtensionConfig) IsStreamingEnabled() bool {
	if e == nil {
		return false
	}

	return e.Sync != nil && e.Sync.EnableStreaming != nil && *e.Sync.EnableStreaming
}

// IsScrubEnabled checks if scrub is enabled in this extensions config.
func (e *ExtensionConfig) IsScrubEnabled() bool {
	if e == nil {
		return false
	}

	return e.Scrub != nil && e.Scrub.Enable != nil && *e.Scrub.Enable
}

// IsMetricsEnabled checks if metrics are enabled in this extensions config.
func (e *ExtensionConfig) IsMetricsEnabled() bool {
	if e == nil {
		return false
	}

	return e.Metrics != nil && e.Metrics.Enable != nil && *e.Metrics.Enable
}

// IsCosignEnabled checks if Cosign is enabled in this extensions config.
func (e *ExtensionConfig) IsCosignEnabled() bool {
	if e == nil {
		return false
	}

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable && e.Trust.Cosign
}

// IsNotationEnabled checks if Notation is enabled in this extensions config.
func (e *ExtensionConfig) IsNotationEnabled() bool {
	if e == nil {
		return false
	}

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable && e.Trust.Notation
}

// IsImageTrustEnabled checks if image trust is enabled in this extensions config.
func (e *ExtensionConfig) IsImageTrustEnabled() bool {
	if e == nil {
		return false
	}

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable
}

// IsUIEnabled checks if UI is enabled in this extensions config.
func (e *ExtensionConfig) IsUIEnabled() bool {
	return e.isUIEnabledInternal()
}

// AreUserPrefsEnabled checks if user preferences are enabled in this extensions config.
func (e *ExtensionConfig) AreUserPrefsEnabled() bool {
	if e == nil {
		return false
	}

	return e.isSearchEnabledInternal() && e.isUIEnabledInternal()
}

// GetSearchCVEConfig returns the search CVE config.
func (e *ExtensionConfig) GetSearchCVEConfig() *CVEConfig {
	if e == nil {
		return nil
	}

	if e.Search != nil {
		return e.Search.CVE
	}

	return nil
}

// GetScrubInterval returns the scrub interval.
func (e *ExtensionConfig) GetScrubInterval() time.Duration {
	if e == nil {
		return 0
	}

	if e.Scrub != nil {
		return e.Scrub.Interval
	}

	return 0
}

// GetSyncConfig returns the sync config.
func (e *ExtensionConfig) GetSyncConfig() *sync.Config {
	if e == nil {
		return nil
	}

	return e.Sync
}

// GetMetricsPrometheusConfig returns the metrics prometheus config.
func (e *ExtensionConfig) GetMetricsPrometheusConfig() *PrometheusConfig {
	if e == nil {
		return nil
	}

	if e.Metrics != nil {
		return e.Metrics.Prometheus
	}

	return nil
}

// GetEventsConfig returns the events config.
func (e *ExtensionConfig) GetEventsConfig() *events.Config {
	if e == nil {
		return nil
	}

	return e.Events
}
