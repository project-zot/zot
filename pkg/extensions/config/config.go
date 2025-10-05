package config

import (
	gosync "sync"
	"time"

	"zotregistry.dev/zot/pkg/extensions/config/events"
	"zotregistry.dev/zot/pkg/extensions/config/sync"
)

// BaseConfig has params applicable to all extensions.
type BaseConfig struct {
	Enable *bool `mapstructure:",omitempty"`
}

type ExtensionConfig struct {
	mu      gosync.RWMutex
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
	Cosign     bool
	Notation   bool
}

type APIKeyConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type MgmtConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type LintConfig struct {
	BaseConfig           `mapstructure:",squash"`
	MandatoryAnnotations []string
}

type SearchConfig struct {
	BaseConfig `mapstructure:",squash"`
	// CVE search
	CVE *CVEConfig
}

type CVEConfig struct {
	UpdateInterval time.Duration // should be 2 hours or more, if not specified default be kept as 24 hours
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
	Interval   time.Duration
}

type UIConfig struct {
	BaseConfig `mapstructure:",squash"`
}

// =============================================================================
// INTERNAL METHODS (non-locking, for use by other methods that already hold locks)
// =============================================================================

// isSearchEnabledInternal checks if search is enabled without acquiring a lock (internal use only).
func (e *ExtensionConfig) isSearchEnabledInternal() bool {
	return e != nil && e.Search != nil && e.Search.Enable != nil && *e.Search.Enable
}

// isUIEnabledInternal checks if UI is enabled without acquiring a lock (internal use only).
func (e *ExtensionConfig) isUIEnabledInternal() bool {
	return e != nil && e.UI != nil && e.UI.Enable != nil && *e.UI.Enable
}

// =============================================================================
// PUBLIC THREAD-SAFE METHODS (acquire locks)
// =============================================================================

// IsCveScanningEnabled checks if CVE scanning is enabled in this extensions config.
func (e *ExtensionConfig) IsCveScanningEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Search != nil && e.Search.Enable != nil && *e.Search.Enable &&
		e.Search.CVE != nil && e.Search.CVE.Trivy != nil
}

// IsEventRecorderEnabled checks if event recording is enabled in this extensions config.
func (e *ExtensionConfig) IsEventRecorderEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Events != nil && e.Events.Enable != nil && *e.Events.Enable
}

// IsSearchEnabled checks if search is enabled in this extensions config.
func (e *ExtensionConfig) IsSearchEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.isSearchEnabledInternal()
}

// IsSyncEnabled checks if sync is enabled in this extensions config.
func (e *ExtensionConfig) IsSyncEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Sync is enabled if either:
	// 1. Explicitly enabled (Enable == true), OR
	// 2. There are registries configured (enabled by default when registries exist)
	// This matches the behavior in root.go where Sync.Enable defaults to true when registries are present
	return e.Sync != nil && ((e.Sync.Enable != nil && *e.Sync.Enable) || len(e.Sync.Registries) > 0)
}

// IsScrubEnabled checks if scrub is enabled in this extensions config.
func (e *ExtensionConfig) IsScrubEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Scrub != nil && e.Scrub.Enable != nil && *e.Scrub.Enable
}

// IsMetricsEnabled checks if metrics are enabled in this extensions config.
func (e *ExtensionConfig) IsMetricsEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Metrics != nil && e.Metrics.Enable != nil && *e.Metrics.Enable
}

// IsCosignEnabled checks if Cosign is enabled in this extensions config.
func (e *ExtensionConfig) IsCosignEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable && e.Trust.Cosign
}

// IsNotationEnabled checks if Notation is enabled in this extensions config.
func (e *ExtensionConfig) IsNotationEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable && e.Trust.Notation
}

// IsImageTrustEnabled checks if image trust is enabled in this extensions config.
func (e *ExtensionConfig) IsImageTrustEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.Trust != nil && e.Trust.Enable != nil && *e.Trust.Enable
}

// IsUIEnabled checks if UI is enabled in this extensions config.
func (e *ExtensionConfig) IsUIEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.isUIEnabledInternal()
}

// AreUserPrefsEnabled checks if user preferences are enabled in this extensions config.
func (e *ExtensionConfig) AreUserPrefsEnabled() bool {
	if e == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.isSearchEnabledInternal() && e.isUIEnabledInternal()
}

// =============================================================================
// THREAD-SAFE SETTER METHODS
// =============================================================================

// SetMetricsPrometheusPath safely sets the Prometheus path.
func (e *ExtensionConfig) SetMetricsPrometheusPath(path string) {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.Metrics != nil && e.Metrics.Prometheus != nil {
		e.Metrics.Prometheus.Path = path
	}
}

// SetSyncConfig safely sets the sync config.
func (e *ExtensionConfig) SetSyncConfig(syncConfig *sync.Config) {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.Sync = syncConfig
}

// SetSearchCVEConfig safely sets the search CVE config.
func (e *ExtensionConfig) SetSearchCVEConfig(cveConfig *CVEConfig) {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.Search != nil {
		e.Search.CVE = cveConfig
	}
}

// SetScrubConfig safely sets the scrub config.
func (e *ExtensionConfig) SetScrubConfig(scrubConfig *ScrubConfig) {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.Scrub = scrubConfig
}
