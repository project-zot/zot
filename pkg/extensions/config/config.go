package config

import (
	"time"
)

type ExtensionConfig struct {
	Search  *SearchConfig
	Sync    *SyncConfig
	Metrics *MetricsConfig
	Scrub   *ScrubConfig
	Lint    *LintConfig
	UI      *UIConfig
}

type LintConfig struct {
	Enabled              *bool
	MandatoryAnnotations []string
}

type SearchConfig struct {
	// CVE search
	CVE    *CVEConfig
	Enable *bool
}

type CVEConfig struct {
	UpdateInterval time.Duration // should be 2 hours or more, if not specified default be kept as 24 hours
}

type MetricsConfig struct {
	Enable     *bool
	Prometheus *PrometheusConfig
}

type PrometheusConfig struct {
	Path string // default is "/metrics"
}

type ScrubConfig struct {
	Interval time.Duration
}

type UIConfig struct {
	Enable *bool
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
