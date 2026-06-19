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
	URLs                   []string
	PollInterval           time.Duration
	Content                []Content
	TLSVerify              *bool
	OnDemand               bool
	CertDir                string
	MaxRetries             *int
	RetryDelay             *time.Duration
	OnlySigned             *bool
	SyncLegacyCosignTags   *bool // when unset, defaults to true
	CredentialHelper       string
	CredentialHelperConfig *CredentialHelperConfig
	PreserveDigest         bool          // sync without converting
	SyncTimeout            time.Duration // overall HTTP client timeout for all sync operations
	ResponseHeaderTimeout  time.Duration `yaml:"-"` // response header timeout; set in root.go
}

// CredentialHelperConfig holds the options used by the "oauth2" credential helper,
// which exchanges a JWT assertion for a short-lived registry access token.
type CredentialHelperConfig struct {
	TokenURL         string   // OAuth2 token endpoint
	AssertionFile    string   // file holding the JWT assertion, re-read on every refresh
	GrantType        string   // "client_credentials" (default) or the jwt-bearer grant URN
	ClientID         string   // optional OAuth2 client identifier
	ClientSecret     string   // optional OAuth2 client secret, sent in the request body
	ClientSecretFile string   // file holding the client secret, takes precedence over ClientSecret
	Scopes           []string // optional OAuth2 scopes
	Username         string   // registry username paired with the token, defaults to "<token>"
}

// ShouldSyncLegacyCosignTags returns whether to sync legacy cosign tags (e.g. sha256-<digest>.sig/sbom).
// Default is true when SyncLegacyCosignTags is unset (nil).
func (r RegistryConfig) ShouldSyncLegacyCosignTags() bool {
	return r.SyncLegacyCosignTags == nil || *r.SyncLegacyCosignTags
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
