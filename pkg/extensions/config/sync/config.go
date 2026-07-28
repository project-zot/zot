package sync

import (
	"errors"
	"time"

	"github.com/mitchellh/mapstructure"
)

var (
	errOAuth2HelperConfigMissing = errors.New("oauth2 credential helper requires an oauth2CredentialHelper config")
	errOAuth2TokenURLMissing     = errors.New("oauth2 credential helper requires a tokenURL")
	errOAuth2AssertionMissing    = errors.New("oauth2 credential helper requires an assertionFile or a signingFile")
	errOAuth2AssertionConflict   = errors.New("oauth2 credential helper allows only assertionFile or signingFile")
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
	MaxRetryDelay          *time.Duration // max HTTP retry backoff; when unset defaults to retryDelay (fixed delay)
	OnlySigned             *bool
	SyncLegacyCosignTags   *bool // when unset, defaults to true
	CredentialHelper       string
	Oauth2CredentialHelper map[string]any `mapstructure:",omitempty"` // decoded per CredentialHelper
	PreserveDigest         bool           // sync without converting
	SyncTimeout            time.Duration  // overall HTTP client timeout for all sync operations
	ResponseHeaderTimeout  time.Duration  `yaml:"-"` // response header timeout; set in root.go
}

// OAuth2HelperConfig holds the options used by the "oauth2" credential helper,
// which exchanges a JWT assertion for a short-lived registry access token.
//
// The assertion comes from one of two mutually exclusive sources, exactly one of which must be set:
//   - AssertionFile: a pre-signed JWT issued and rotated by an external platform (e.g. a Kubernetes
//     projected service account token, EKS IRSA or a workload-identity token), re-read on every
//     refresh. zot never holds a private key; single-use semantics, if any, are owned by the platform.
//   - SigningFile: a private key and claims that zot uses to mint a fresh, single-use assertion
//     (unique "jti") on every refresh, then exchanges it for a short-lived access token.
type OAuth2HelperConfig struct {
	TokenURL         string   // OAuth2 token endpoint
	AssertionFile    string   // file holding a pre-signed JWT assertion, re-read on every refresh
	SigningFile      string   // file holding the signing key and claims used to mint assertions in-code
	GrantType        string   // "client_credentials" (default) or the jwt-bearer grant URN
	ClientID         string   // optional OAuth2 client identifier
	ClientSecretFile string   // file holding the optional OAuth2 client secret, sent in the request body
	Scopes           []string // optional OAuth2 scopes
	Username         string   // registry username paired with the token, defaults to "<token>"
}

// decodeOauth2CredentialHelper decodes the generic Oauth2CredentialHelper dictionary
// into the typed configuration of a specific credential helper. New helpers can reuse
// it by adding a typed wrapper such as OAuth2HelperConfigFromMap below.
func decodeOauth2CredentialHelper(raw map[string]any, out any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           out,
		WeaklyTypedInput: true,
		ErrorUnused:      true, // reject misspelled keys, mirroring the strict top-level config load
		TagName:          "mapstructure",
	})
	if err != nil {
		return err
	}

	return decoder.Decode(raw)
}

// OAuth2HelperConfigFromMap decodes the generic Oauth2CredentialHelper dictionary into
// the typed OAuth2 helper configuration. It returns nil when no configuration is set.
func OAuth2HelperConfigFromMap(raw map[string]any) (*OAuth2HelperConfig, error) {
	if len(raw) == 0 {
		return nil, nil //nolint:nilnil // absence of config is not an error here
	}

	config := &OAuth2HelperConfig{}
	if err := decodeOauth2CredentialHelper(raw, config); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that the OAuth2 helper configuration is complete and consistent.
func (config *OAuth2HelperConfig) Validate() error {
	if config == nil {
		return errOAuth2HelperConfigMissing
	}

	if config.TokenURL == "" {
		return errOAuth2TokenURLMissing
	}

	hasAssertionFile := config.AssertionFile != ""
	hasSigningFile := config.SigningFile != ""

	if !hasAssertionFile && !hasSigningFile {
		return errOAuth2AssertionMissing
	}

	if hasAssertionFile && hasSigningFile {
		return errOAuth2AssertionConflict
	}

	return nil
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
