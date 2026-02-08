package sync

import (
	"time"
)

// CredentialsFile is a map where key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	Enable          *bool
	EnableStreaming *bool
	CredentialsFile string
	/* DownloadDir is needed only in case of using cloud based storages
	it uses regclient to first copy images into this dir (as oci layout)
	and then move them into storage. */
	DownloadDir string
	Registries  []RegistryConfig
}

type RegistryConfig struct {
	URLs                  []string
	PollInterval          time.Duration
	Content               []Content
	TLSVerify             *bool
	OnDemand              bool
	CertDir               string
	MaxRetries            *int
	RetryDelay            *time.Duration
	OnlySigned            *bool
	CredentialHelper      string
	PreserveDigest        bool          // sync without converting
	SyncTimeout           time.Duration // overall HTTP client timeout for all sync operations
	ResponseHeaderTimeout time.Duration `yaml:"-"` // response header timeout; set in root.go
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
