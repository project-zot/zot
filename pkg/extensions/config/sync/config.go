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
	// SkipTagBasedReferrerSync disables syncing referrers that are stored as digest-encoded tags
	// (e.g. sha256-<hex>.sig, sha256-<hex>.att, sha256-<hex>.sbom used by legacy cosign tooling).
	// When true, only OCI-spec referrers discovered via the Referrers API are synced.
	// Eliminates the expensive tag-listing round-trip on every on-demand referrer request.
	// Default false to preserve backwards-compatible behaviour.
	SkipTagBasedReferrerSync bool
	// SkipRecursiveReferrerSync disables recursive traversal of referrer graphs.
	// When true, only the direct referrers of the queried digest are synced; referrers-of-referrers
	// are synced lazily when explicitly requested by a client.
	// Default false to preserve backwards-compatible behaviour.
	SkipRecursiveReferrerSync bool
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
