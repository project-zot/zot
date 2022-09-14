package config

import (
	"time"

	msConfig "zotregistry.io/zot/pkg/meta/config"
)

// BaseConfig has params applicable to all extensions.
type BaseConfig struct {
	Enable *bool `mapstructure:",omitempty"`
}

type ExtensionConfig struct {
	Search   *SearchConfig
	Sync     *SyncConfig
	Metrics  *MetricsConfig
	Scrub    *ScrubConfig
	Lint     *LintConfig
	UI       *UIConfig
	Metadata *msConfig.MetadataStoreConfig
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

// key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type SyncConfig struct {
	Enable          *bool
	CredentialsFile string
	Registries      []RegistryConfig
}

type RegistryConfig struct {
	URLs         []string
	PollInterval time.Duration
	Content      []Content
	TLSVerify    *bool
	OnDemand     bool
	CertDir      string
	MaxRetries   *int
	RetryDelay   *time.Duration
	OnlySigned   *bool
}

type Content struct {
	Prefix      string
	Tags        *Tags
	Destination string `mapstructure:",omitempty"`
	StripPrefix bool
}

type Tags struct {
	Regex  *string
	Semver *bool
}
