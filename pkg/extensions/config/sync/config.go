package sync

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
)

// TokenExchangeGrantType is the RFC 8693 token exchange grant, used to trade a subject
// token issued by an external identity provider for an access token minted by a security
// token service.
const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // not a credential

var (
	errOAuth2HelperConfigMissing = errors.New("oauth2 credential helper requires an oauth2CredentialHelper config")
	errOAuth2TokenURLMissing     = errors.New("oauth2 credential helper requires a tokenURL")
	errOAuth2AssertionMissing    = errors.New("oauth2 credential helper requires an assertionFile or a signingFile")
	errOAuth2AssertionConflict   = errors.New("oauth2 credential helper allows only assertionFile or signingFile")
	errOAuth2AudienceMissing     = errors.New(
		"oauth2 credential helper requires an audience when grantType is " + TokenExchangeGrantType)
	errOAuth2ExchangeOnlyFields = errors.New(
		"oauth2 credential helper allows audience, subjectTokenType and requestedTokenType " +
			"only when grantType is " + TokenExchangeGrantType)
	errOAuth2TokenTypeNotURI = errors.New(
		"oauth2 credential helper requires subjectTokenType and requestedTokenType to be absolute URIs")
)

// hasValue reports whether a configuration value holds anything other than blanks, so that
// a whitespace-only entry is rejected the same way an omitted one is.
func hasValue(value string) bool {
	return strings.TrimSpace(value) != ""
}

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
	ManifestCheckInterval  time.Duration
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
	// ReqConcurrent caps the number of in-flight requests per upstream host. The limit is applied
	// independently to the upstream registry and to each of its mirrors (regclient copies it onto every
	// host), so it is a per-host cap, not a shared total across hosts. When unset it defaults to
	// regclient's default (3). Raising it helps when a single zot proxies many concurrent on-demand pulls
	// of different images from one upstream, where the default causes head-of-line blocking.
	//
	// ReqConcurrent and DisableHTTP2 compose, and both are usually needed together: ReqConcurrent
	// alone still funnels every request through one HTTP/2 connection (one TCP congestion window) if
	// the upstream negotiates h2, while DisableHTTP2 alone still caps concurrency at ReqConcurrent's
	// default of 3 connections. To actually open more than 3 parallel connections to an HTTP/2
	// upstream, raise ReqConcurrent and set DisableHTTP2.
	ReqConcurrent *int
	// ReqPerSec caps the request rate (requests/second) per upstream host, applied independently to the
	// upstream registry and to each of its mirrors (a per-host cap, not a shared total across hosts).
	// When unset it defaults to regclient's default (0, i.e. unlimited).
	ReqPerSec *float64
	// DisableHTTP2 forces HTTP/1.1 to the upstream, so each concurrent request opens its own TCP
	// connection instead of sharing the single connection (and congestion window) HTTP/2 multiplexes
	// requests onto. See the ReqConcurrent doc comment above: the two settings compose, and raising
	// ReqConcurrent is what actually lets more than 3 connections open.
	DisableHTTP2 *bool
	// MaxIdleConnsPerHost overrides the transport's per-host idle connection pool size (Go default: 2),
	// applied whether or not DisableHTTP2 is set (it also helps a plain-HTTP or already-HTTP/1.1
	// upstream keep its connections pooled). An explicit value here always wins.
	//
	// When DisableHTTP2 is true and this is left unset, it defaults to ReqConcurrent's effective
	// value (the configured value, or regclient's default of 3) instead of Go's default of 2 —
	// otherwise DisableHTTP2 alone would still hit the handshake-per-request pattern this option
	// exists to avoid, since concurrent HTTP/1.1 connections beyond 2 would get closed instead of
	// pooled.
	MaxIdleConnsPerHost *int
}

// OAuth2HelperConfig holds the options used by the "oauth2" credential helper,
// which exchanges a signed assertion for a short-lived registry access token.
//
// The assertion comes from one of two mutually exclusive sources, exactly one of which must be set:
//   - AssertionFile: a pre-signed JWT issued and rotated by an external platform (e.g. a Kubernetes
//     projected service account token, EKS IRSA or a workload-identity token), re-read on every
//     refresh. zot never holds a private key; single-use semantics, if any, are owned by the platform.
//   - SigningFile: a private key and claims that zot uses to mint a fresh, single-use assertion
//     (unique "jti") on every refresh, then exchanges it for a short-lived access token.
//
// With the RFC 8693 token-exchange grant the assertion is sent as the subject token rather
// than as a client credential, which is what a security token service such as Google STS
// expects when federating an external workload identity. That grant also accepts subject
// tokens that are not JWTs, declared through SubjectTokenType.
type OAuth2HelperConfig struct {
	TokenURL         string   // OAuth2 token endpoint
	AssertionFile    string   // file holding the pre-signed assertion, re-read on every refresh
	SigningFile      string   // file holding the signing key and claims used to mint assertions in-code
	GrantType        string   // "client_credentials" (default), the jwt-bearer or the token-exchange grant URN
	ClientID         string   // optional OAuth2 client identifier
	ClientSecretFile string   // file holding the optional OAuth2 client secret, sent in the request body
	Scopes           []string // optional OAuth2 scopes
	Username         string   // registry username paired with the token, defaults to "<token>"

	// The fields below apply to the token-exchange grant only.
	Audience           string // required, identifies the target of the exchange
	SubjectTokenType   string // type of the subject token being exchanged, defaults to the JWT token type
	RequestedTokenType string // type asked of the endpoint, defaults to the access-token type
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

	if !hasValue(config.TokenURL) {
		return errOAuth2TokenURLMissing
	}

	hasAssertionFile := hasValue(config.AssertionFile)
	hasSigningFile := hasValue(config.SigningFile)

	if !hasAssertionFile && !hasSigningFile {
		return errOAuth2AssertionMissing
	}

	if hasAssertionFile && hasSigningFile {
		return errOAuth2AssertionConflict
	}

	// The RFC 8693 fields are meaningless outside the token-exchange grant, so reject them
	// there rather than silently ignoring a misconfiguration.
	if config.GrantType != TokenExchangeGrantType {
		if hasValue(config.Audience) || hasValue(config.SubjectTokenType) || hasValue(config.RequestedTokenType) {
			return errOAuth2ExchangeOnlyFields
		}

		return nil
	}

	if !hasValue(config.Audience) {
		return errOAuth2AudienceMissing
	}

	/* RFC 8693 identifies token types by URI. The registered ones are URNs, but the spec
	allows other schemes, so require an absolute URI rather than the "urn" scheme: that
	still rejects a bare word such as "jwt". The audience deliberately gets no such check,
	because it is a logical name rather than a URI, and the workload identity audience
	Google expects carries no scheme at all. */
	for _, tokenType := range []string{config.SubjectTokenType, config.RequestedTokenType} {
		if !hasValue(tokenType) {
			continue // optional, a default applies
		}

		if parsed, err := url.Parse(tokenType); err != nil || !parsed.IsAbs() {
			return errOAuth2TokenTypeNotURI
		}
	}

	return nil
}

// ShouldSyncLegacyCosignTags returns whether to sync legacy cosign tags (e.g. sha256-<digest>.sig/sbom).
// Default is true when SyncLegacyCosignTags is unset (nil).
func (r RegistryConfig) ShouldSyncLegacyCosignTags() bool {
	return r.SyncLegacyCosignTags == nil || *r.SyncLegacyCosignTags
}

// SyncTimeoutOrDefault returns the configured sync timeout, or DefaultSyncTimeout when unset.
func (r RegistryConfig) SyncTimeoutOrDefault() time.Duration {
	if r.SyncTimeout <= 0 {
		return syncConstants.DefaultSyncTimeout
	}

	return r.SyncTimeout
}

// LargestSyncTimeout returns the largest SyncTimeout across registries, with per-registry
// defaults applied. When sync is not configured it returns DefaultSyncTimeout.
func (c *Config) LargestSyncTimeout() time.Duration {
	if c == nil {
		return syncConstants.DefaultSyncTimeout
	}

	maxTimeout := time.Duration(0)

	for _, reg := range c.Registries {
		if timeout := reg.SyncTimeoutOrDefault(); timeout > maxTimeout {
			maxTimeout = timeout
		}
	}

	if maxTimeout == 0 {
		return syncConstants.DefaultSyncTimeout
	}

	return maxTimeout
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
