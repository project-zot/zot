package extensions

import "time"

type ExtensionConfig struct {
	Search *SearchConfig
}

type SearchConfig struct {
	// CVE search
	CVE *CVEConfig
}

type CVEConfig struct {
	UpdateInterval time.Duration // should be 2 hours or more, if not specified default be kept as 24 hours
}
