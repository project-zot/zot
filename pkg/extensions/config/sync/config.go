package sync

import (
	"time"
)

// key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	Enable          *bool
	CredentialsFile string
	/* DownloadDir is needed only in case of using cloud based storages
	it uses regclient to first copy images into this dir (as oci layout)
	and then move them into storage. */
	DownloadDir string
	Registries  []RegistryConfig
}

type RegistryConfig struct {
	URLs             []string
	PollInterval     time.Duration
	Content          []Content
	TLSVerify        *bool
	OnDemand         bool
	CertDir          string
	MaxRetries       *int
	RetryDelay       *time.Duration
	OnlySigned       *bool
	CredentialHelper string
	PreserveDigest   bool               // sync without converting
	StreamCache      *StreamCacheConfig `mapstructure:",omitempty"`
}

type StreamCacheConfig struct {
	Enable   *bool
	CacheDir string
	MaxSize  int64 // Maximum cache size in bytes (0 = unlimited)
}

type Content struct {
	Prefix      string
	Tags        *Tags
	Destination string `mapstructure:",omitempty"`
	StripPrefix bool
}

type Tags struct {
	Regex        *string
	ExcludeRegex *string
	Semver       *bool
}
