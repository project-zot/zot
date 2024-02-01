package config

import (
	"time"

	"zotregistry.dev/zot/pkg/extensions/config/sync"
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
