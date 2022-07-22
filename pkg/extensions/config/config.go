package config

import (
	"time"

	"zotregistry.io/zot/pkg/extensions/sync"
)

type ExtensionConfig struct {
	Search  *SearchConfig
	Sync    *sync.Config
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
	Enable   *bool
	Interval time.Duration
}

type UIConfig struct {
	Enable *bool
}
