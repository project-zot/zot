package config

import (
	"time"

	"zotregistry.io/zot/pkg/extensions/sync"
)

// BaseConfig has params applicable to all extensions.
type BaseConfig struct {
	Enable *bool `mapstructure:",omitempty"`
}

type ExtensionConfig struct {
	Search    *SearchConfig
	Sync      *sync.Config
	Metrics   *MetricsConfig
	Scrub     *ScrubConfig
	Lint      *LintConfig
	SysConfig *SysConfig
}

type LintConfig struct {
	BaseConfig           `mapstructure:",squash"`
	MandatoryAnnotations []string
}

type SysConfig struct {
	Enable *bool
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
