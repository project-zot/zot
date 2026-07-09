package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/tiendc/go-deepcopy"

	"zotregistry.dev/zot/v2/pkg/buildinfo"
	"zotregistry.dev/zot/v2/pkg/compat"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

var (
	openIDSupportedProviders = [...]string{"google", "gitlab", "oidc"} //nolint: gochecknoglobals
	oauth2SupportedProviders = [...]string{"github"}                   //nolint: gochecknoglobals
)

type StorageConfig struct {
	RootDirectory   string
	MaxRepos        int
	Dedupe          bool
	RemoteCache     bool
	RedirectBlobURL bool
	GC              bool
	Commit          bool
	GCDelay         time.Duration // applied for blobs
	GCInterval      time.Duration
	Retention       ImageRetention
	StorageDriver   map[string]any `mapstructure:",omitempty"`
	CacheDriver     map[string]any `mapstructure:",omitempty"`

	// GCMaxSchedulerDelay is the maximum random delay for GC task scheduling
	// This field is not configurable by the end user
	GCMaxSchedulerDelay time.Duration `yaml:"-"`
}

type ImageRetention struct {
	DryRun   bool
	Delay    time.Duration // applied for referrers and untagged
	Policies []RetentionPolicy
}

type RetentionPolicy struct {
	Repositories    []string
	DeleteReferrers bool
	DeleteUntagged  *bool
	KeepTags        []KeepTagsPolicy
	KeepUntagged    *KeepUntaggedPolicy
}

type KeepTagsPolicy struct {
	Patterns                []string
	PulledWithin            *time.Duration
	PushedWithin            *time.Duration
	MostRecentlyPushedCount int
	MostRecentlyPulledCount int
}

type KeepUntaggedPolicy struct {
	PulledWithin            *time.Duration
	PushedWithin            *time.Duration
	MostRecentlyPushedCount int
	MostRecentlyPulledCount int
}

type TLSConfig struct {
	Cert   string
	Key    string
	CACert string
}

type MTLSConfig struct {
	// IdentityAttibutes is an ordered list of identity attributes to try
	// Options: "CommonName", "Subject", "Email", "URI", "DNSName" (case-insensitive)
	// Default: ["CommonName"] (backward compatible)
	IdentityAttibutes []string `json:"identityAttributes,omitempty" mapstructure:"identityAttributes,omitempty"`

	// URISANPattern is a regex pattern to extract identity from URI SAN
	// Only used when IdentityAttibutes contains "URI"
	// Example: "spiffe://example.org/workload/(.*)" extracts the workload ID
	// If empty, uses the full URI SAN value
	URISANPattern string `json:"uriSanPattern,omitempty" mapstructure:"uriSanPattern,omitempty"`

	// URISANIndex specifies which URI SAN to use if multiple exist (0-based)
	// Maps to cert.URIs[index] - the URIs field is a slice, so index is needed
	// Default: 0 (first URI)
	URISANIndex int `json:"uriSanIndex,omitempty" mapstructure:"uriSanIndex,omitempty"`

	// DNSANIndex specifies which DNS SAN to use if multiple exist (0-based)
	// Maps to cert.DNSNames[index] - the DNSNames field is a slice, so index is needed
	// Default: 0 (first DNS name)
	DNSANIndex int `json:"dnsSanIndex,omitempty" mapstructure:"dnsSanIndex,omitempty"`

	// EmailSANIndex specifies which Email SAN to use if multiple exist (0-based)
	// Maps to cert.EmailAddresses[index] - the EmailAddresses field is a slice, so index is needed
	// Default: 0 (first email)
	EmailSANIndex int `json:"emailSanIndex,omitempty" mapstructure:"emailSanIndex,omitempty"`
}

type AuthHTPasswd struct {
	Path string
}

type AuthConfig struct {
	FailDelay         int
	HTPasswd          AuthHTPasswd
	LDAP              *LDAPConfig
	Bearer            *BearerConfig
	OpenID            *OpenIDConfig
	APIKey            bool
	SessionKeysFile   string
	SessionHashKey    []byte         `json:"-"`
	SessionEncryptKey []byte         `json:"-"`
	SessionDriver     map[string]any `mapstructure:",omitempty"`
	SecureSession     *bool          `json:"secureSession,omitempty" mapstructure:"secureSession,omitempty"`
	MTLS              *MTLSConfig    `json:"mtls,omitempty"          mapstructure:"mtls,omitempty"`
}

// IsLdapAuthEnabled checks if LDAP authentication is enabled in this auth config.
func (a *AuthConfig) IsLdapAuthEnabled() bool {
	return a != nil && a.LDAP != nil
}

// IsHtpasswdAuthEnabled checks if HTPasswd authentication is enabled in this auth config.
func (a *AuthConfig) IsHtpasswdAuthEnabled() bool {
	return a != nil && a.HTPasswd.Path != ""
}

// IsBearerAuthEnabled checks if Bearer authentication is enabled in this auth config.
func (a *AuthConfig) IsBearerAuthEnabled() bool {
	return a.IsTraditionalBearerAuthEnabled() || a.IsOIDCBearerAuthEnabled()
}

// HasBearerConfig checks if Bearer authentication config is present.
func (a *AuthConfig) HasBearerConfig() bool {
	return a != nil && a.Bearer != nil
}

// IsTraditionalBearerAuthEnabled checks if traditional Bearer authentication is enabled in this auth config.
func (a *AuthConfig) IsTraditionalBearerAuthEnabled() bool {
	return a.IsTraditionalBearerAuthEnabledWithCert() || a.IsTraditionalBearerAuthEnabledWithASM()
}

// IsTraditionalBearerAuthEnabledWithCert checks if traditional Bearer authentication with a
// static cert is enabled in this auth config.
func (a *AuthConfig) IsTraditionalBearerAuthEnabledWithCert() bool {
	return a != nil && a.Bearer != nil && a.Bearer.Cert != "" && a.Bearer.Realm != "" && a.Bearer.Service != ""
}

// IsTraditionalBearerAuthEnabledWithASM checks if traditional Bearer authentication with
// AWS Secrets Manager is enabled in this auth config.
func (a *AuthConfig) IsTraditionalBearerAuthEnabledWithASM() bool {
	return a != nil && a.Bearer != nil && a.Bearer.AWSSecretsManager != nil &&
		a.Bearer.Realm != "" && a.Bearer.Service != ""
}

// IsOIDCBearerAuthEnabled checks if OIDC Bearer authentication is enabled in this auth config.
func (a *AuthConfig) IsOIDCBearerAuthEnabled() bool {
	return a != nil && a.Bearer != nil && a.Bearer.OIDC.IsEnabled()
}

// IsUpstreamTokenEndpointConfigured checks if an upstream token endpoint is configured for bearer auth.
func (a *AuthConfig) IsUpstreamTokenEndpointConfigured() bool {
	return a != nil && a.Bearer.HasUpstreamTokenEndpoint()
}

// IsOpenIDAuthEnabled checks if OpenID authentication is enabled in this auth config.
func (a *AuthConfig) IsOpenIDAuthEnabled() bool {
	if a == nil || a.OpenID == nil {
		return false
	}

	for provider := range a.OpenID.Providers {
		if IsOpenIDSupported(provider) || IsOauth2Supported(provider) {
			return true
		}
	}

	return false
}

// IsAPIKeyEnabled checks if API Key authentication is enabled in this auth config.
func (a *AuthConfig) IsAPIKeyEnabled() bool {
	return a != nil && a.APIKey
}

// IsBasicAuthnEnabled checks if any basic authentication method is enabled in this auth config.
func (a *AuthConfig) IsBasicAuthnEnabled() bool {
	if a == nil {
		return false
	}

	return a.IsHtpasswdAuthEnabled() || a.IsLdapAuthEnabled() || a.IsOpenIDAuthEnabled() || a.IsAPIKeyEnabled()
}

// CanAuthenticateWithBasicCredentials reports whether the server can authenticate a client
// using HTTP Basic credentials (username/password) in the Authorization header.
//
// This is intentionally narrower than IsBasicAuthnEnabled(): OpenID is not a Basic
// credential flow, while htpasswd/LDAP/API keys are.
func (a *AuthConfig) CanAuthenticateWithBasicCredentials() bool {
	return a.IsHtpasswdAuthEnabled() || a.IsLdapAuthEnabled() || a.IsAPIKeyEnabled()
}

// GetFailDelay returns the configured fail delay for authentication attempts.
func (a *AuthConfig) GetFailDelay() int {
	if a == nil {
		return 0
	}

	return a.FailDelay
}

// GetMTLSConfig returns the mTLS configuration if it exists.
func (a *AuthConfig) GetMTLSConfig() *MTLSConfig {
	if a == nil {
		return nil
	}

	return a.MTLS
}

type BearerConfig struct {
	Realm                 string
	Service               string
	UpstreamTokenEndpoint *UpstreamTokenEndpointConfig `json:"upstreamTokenEndpoint,omitempty" mapstructure:"upstreamTokenEndpoint,omitempty"` //nolint:lll
	Cert                  string

	// OIDC configuration for workload identity authentication
	OIDC BearerOIDCConfigs `json:"oidc,omitempty" mapstructure:"oidc,omitempty"`

	// AWSSecretsManager configuration for retrieving JWT Bearer verification keys.
	AWSSecretsManager *AWSSecretsManagerConfig `json:"awsSecretsManager,omitempty" mapstructure:"awsSecretsManager,omitempty"` //nolint:lll
}

type UpstreamTokenEndpointConfig struct {
	Realm             string `json:"realm,omitempty"             mapstructure:"realm,omitempty"`
	Service           string `json:"service,omitempty"           mapstructure:"service,omitempty"`
	AllowInsecureHTTP bool   `json:"allowInsecureHttp,omitempty" mapstructure:"allowInsecureHttp,omitempty"`
}

// HasUpstreamTokenEndpoint checks if this bearer config can proxy token-service requests.
func (b *BearerConfig) HasUpstreamTokenEndpoint() bool {
	return b != nil && b.UpstreamTokenEndpoint != nil &&
		b.UpstreamTokenEndpoint.Realm != "" && b.UpstreamTokenEndpoint.Service != ""
}

// BearerOIDCConfigs is a slice of BearerOIDCConfig.
type BearerOIDCConfigs []BearerOIDCConfig

func (b BearerOIDCConfigs) IsEnabled() bool {
	for i := range b {
		if b[i].Issuer != "" && len(b[i].Audiences) > 0 {
			return true
		}
	}

	return false
}

// BearerOIDCConfig configures OIDC token validation for workload identity.
// This enables workloads to authenticate using OIDC ID tokens in the Authorization header.
type BearerOIDCConfig struct {
	// Issuer is the OIDC issuer URL. Required for OIDC workload identity.
	// Example: "https://kubernetes.default.svc.cluster.local"
	Issuer string `json:"issuer" mapstructure:"issuer"`

	// Audiences is a list of acceptable audiences for the OIDC token.
	// At least one audience must be specified.
	// Example: ["zot", "https://zot.example.com"]
	Audiences []string `json:"audiences" mapstructure:"audiences"`

	// ClaimMapping specifies how OIDC claims are validated and mapped to Zot identities.
	// Default: {"username":"claims.iss + '/' + claims.sub"}
	ClaimMapping *CELClaimValidationAndMapping `json:"claimMapping,omitempty" mapstructure:"claimMapping,omitempty"`

	// CertificateAuthority is a PEM-encoded optional CA certificate to validate the OIDC provider's TLS certificate.
	// Mutually exclusive with CertificateAuthorityFile.
	CertificateAuthority string `json:"certificateAuthority,omitempty" mapstructure:"certificateAuthority,omitempty"`

	// CertificateAuthorityFile is the path to a PEM-encoded optional CA certificate
	// to validate the OIDC provider's TLS certificate.
	// Mutually exclusive with CertificateAuthority.
	CertificateAuthorityFile string `json:"certificateAuthorityFile,omitempty" mapstructure:"certificateAuthorityFile,omitempty"` //nolint:lll

	// SkipIssuerVerification skips issuer verification (for testing only).
	// Default: false
	SkipIssuerVerification bool `json:"skipIssuerVerification,omitempty" mapstructure:"skipIssuerVerification,omitempty"`
}

// AWSSecretsManagerConfig configures retrieval of JWT verification keys from AWS Secrets Manager.
// The secret format is expected to be a JSON object where each key is a key ID and the value is
// the corresponding PEM-or-JWKS-encoded public key.
type AWSSecretsManagerConfig struct {
	// Region is the AWS region where the secret is stored.
	Region string `json:"region" mapstructure:"region"`

	// SecretName is the name of the secret in AWS Secrets Manager.
	SecretName string `json:"secretName" mapstructure:"secretName"`

	// RefreshInterval specifies how often to refresh the secret from AWS Secrets Manager.
	// Default: 1 minute.
	RefreshInterval time.Duration `json:"refreshInterval,omitempty" mapstructure:"refreshInterval,omitempty"`
}

type SessionKeys struct {
	HashKey    string
	EncryptKey string `mapstructure:",omitempty"`
}

type OpenIDConfig struct {
	Providers map[string]OpenIDProviderConfig
	// CallbackAllowOrigins is an allowlist of absolute URL origins that are permitted in the
	// callback_ui query parameter during the OpenID/OAuth2 login flow. If empty, callback_ui must
	// be a same-origin relative path (e.g. "/v2/") to prevent open redirects.
	// Example: ["http://localhost:3000", "https://ui.example.com"]
	CallbackAllowOrigins []string `mapstructure:"callbackAllowOrigins,omitempty"`
}

type OpenIDCredentials struct {
	ClientID     string
	ClientSecret string
}

type OpenIDProviderConfig struct {
	CredentialsFile string
	Name            string
	ClientID        string
	ClientSecret    string
	KeyPath         string
	Issuer          string
	AuthURL         string
	TokenURL        string
	Scopes          []string
	ClaimMapping    *ClaimMapping `mapstructure:",omitempty"`
}

// ClaimMapping specifies how OpenID claims are mapped to Zot identities:
// which claim supplies the username and which claim supplies group membership.
type ClaimMapping struct {
	// Username specifies which OpenID claim to use as the username for the authenticated user.
	// Acceptable values include "preferred_username", "email", "sub", "name", or any custom claim name.
	// If not configured, the default is "email".
	Username string `mapstructure:"username,omitempty"`

	// Groups specifies which OpenID claim to use as the groups for the authenticated user.
	// If not configured, the default is "groups".
	Groups string `mapstructure:"groups,omitempty"`
}

// CELClaimValidationAndMapping specifies Common Expression Language (CEL) expressions
// for validating and mapping OIDC claims.
type CELClaimValidationAndMapping struct {
	// Variables is a list of CELVariable definitions used to extract variables from OIDC claims.
	Variables []CELVariable `mapstructure:"variables,omitempty"`

	// Validations is a list of CELValidation definitions used to validate OIDC claims.
	Validations []CELValidation `mapstructure:"validations,omitempty"`

	// Username is the CEL expression used to extract the username from OIDC claims.
	// This expression should evaluate to a string value.
	// Default: "claims.iss + '/' + claims.sub"
	Username string `mapstructure:"username,omitempty"`

	// Groups is the CEL expression used to extract groups from OIDC claims.
	// This expression should evaluate to a list of strings.
	// Default: "" (no groups extracted)
	Groups string `mapstructure:"groups,omitempty"`
}

// CELVariable represents a CEL expression to extract a variable from OIDC claims.
type CELVariable struct {
	// Name is the name of the variable to be extracted.
	Name string `mapstructure:"name"`

	// Expression is the CEL expression that will extract the variable from the OIDC claims.
	Expression string `mapstructure:"expression"`
}

// CELValidation represents a CEL expression used for validating OIDC claims.
type CELValidation struct {
	// Expression is the CEL expression used for validation. It should evaluate to a boolean value.
	// If the expression evaluates to false, the validation fails and the associated error message
	// is returned.
	Expression string `mapstructure:"expression"`

	// Message is the error message returned if the expression evaluates to false.
	Message string `mapstructure:"message"`
}

type MethodRatelimitConfig struct {
	Method string
	Rate   int
}

type RatelimitConfig struct {
	Rate    *int                    // requests per second
	Methods []MethodRatelimitConfig `mapstructure:",omitempty"`
}

//nolint:maligned
type HTTPConfig struct {
	Address     string
	ExternalURL string `mapstructure:",omitempty"`
	Port        string
	AllowOrigin string // comma separated
	// ReadTimeout controls maximum duration for reading the entire request (including body).
	// When unset (nil), server-level defaults may apply. When explicitly set to <= 0,
	// the HTTP server treats it as no timeout.
	ReadTimeout *time.Duration `mapstructure:"readTimeout,omitempty"`
	// WriteTimeout controls maximum duration before timing out response writes.
	// When unset (nil), server-level defaults may apply. When explicitly set to <= 0,
	// the HTTP server treats it as no timeout.
	WriteTimeout  *time.Duration `mapstructure:"writeTimeout,omitempty"`
	TLS           *TLSConfig
	Auth          *AuthConfig
	AccessControl *AccessControlConfig `mapstructure:"accessControl,omitempty"`
	Realm         string
	Ratelimit     *RatelimitConfig            `mapstructure:",omitempty"`
	Compat        []compat.MediaCompatibility `mapstructure:",omitempty"`
}

type SchedulerConfig struct {
	NumWorkers int
}

// ClusterConfig contains the scale-out configuration which is identical for all zot replicas.
type ClusterConfig struct {
	// contains the "host:port" of all the zot instances participating
	// in the cluster.
	Members []string `json:"members" mapstructure:"members"`

	// contains the hash key that is required for siphash.
	// must be a 128-bit (16-byte) key
	// https://github.com/dchest/siphash?tab=readme-ov-file#func-newkey-byte-hashhash64
	HashKey string `json:"hashKey" mapstructure:"hashKey"`

	// contains client TLS config.
	TLS *TLSConfig `json:"tls" mapstructure:"tls"`

	// private field for storing Proxy details such as internal socket list.
	Proxy *ClusterRequestProxyConfig `json:"-" mapstructure:"-"`
}

// IsClustered returns true if the cluster configuration represents a multi-node cluster.
func (c *ClusterConfig) IsClustered() bool {
	return c != nil && len(c.Members) > 1
}

type ClusterRequestProxyConfig struct {
	// holds the cluster socket (IP:port) derived from the host's
	// interface configuration and the listening port of the HTTP server.
	LocalMemberClusterSocket string
	// index of the local member cluster socket in the members array.
	LocalMemberClusterSocketIndex uint64
}

type LDAPCredentials struct {
	BindDN       string
	BindPassword string
}

type LDAPConfig struct {
	CredentialsFile    string
	Port               int
	Insecure           bool
	StartTLS           bool // if !Insecure, then StartTLS or LDAPs
	SkipVerify         bool
	SubtreeSearch      bool
	Address            string
	bindDN             string `json:"-"`
	bindPassword       string `json:"-"`
	UserGroupAttribute string
	BaseDN             string
	UserAttribute      string
	UserFilter         string
	CACert             string
}

func (ldapConf *LDAPConfig) BindDN() string {
	if ldapConf == nil {
		return ""
	}

	return ldapConf.bindDN
}

func (ldapConf *LDAPConfig) SetBindDN(bindDN string) *LDAPConfig {
	if ldapConf == nil {
		return nil
	}
	ldapConf.bindDN = bindDN

	return ldapConf
}

func (ldapConf *LDAPConfig) BindPassword() string {
	if ldapConf == nil {
		return ""
	}

	return ldapConf.bindPassword
}

func (ldapConf *LDAPConfig) SetBindPassword(bindPassword string) *LDAPConfig {
	if ldapConf == nil {
		return nil
	}
	ldapConf.bindPassword = bindPassword

	return ldapConf
}

type LogConfig struct {
	Level  string
	Output string
	Audit  string
}

type GlobalStorageConfig struct {
	StorageConfig `mapstructure:",squash"`

	SubPaths map[string]StorageConfig

	// FastRestart lets the controller skip the startup storage walk when neither
	// the Zot binary nor the storage config has changed since the last run. This
	// avoids re-reading all metadata from storage on every restart, at the cost
	// of not detecting out-of-band changes to storage; any storage-config change
	// forces a full reparse. It is a top-level storage setting only and is not
	// honored under subPaths. Defaults to false.
	FastRestart *bool `mapstructure:",omitempty"`
}

type AccessControlConfig struct {
	Repositories Repositories `json:"repositories" mapstructure:"repositories"`
	AdminPolicy  Policy
	Groups       Groups
	Metrics      Metrics

	// compiledConditions caches CEL programs for all policy condition
	// expressions present in this access-control config, keyed by expression
	// string. Populated at config validation and refreshed on hot reload.
	// Reads are atomic; writes are infrequent (startup + SIGHUP).
	//
	// Type-erased to map[string]any (rather than map[string]*cel.Expression)
	// to keep this package free of any reference to pkg/cel. pkg/common (and
	// thus zli, transitively via pkg/cli/client) imports pkg/api/config; a
	// typed cel.Expression field here would pull cel-go, ANTLR, and the
	// protobuf reflection runtime into the zli binary (~8MB of dead code,
	// since zli never evaluates CEL). Callers in pkg/api cast back to
	// *cel.Expression at use.
	compiledConditions atomic.Pointer[map[string]any]
}

// LoadCompiledConditions returns the current compiled-conditions snapshot, or
// nil if none have been registered. Safe for concurrent use. Values are
// *cel.Expression; see compiledConditions for why the type is erased.
func (config *AccessControlConfig) LoadCompiledConditions() map[string]any {
	if config == nil {
		return nil
	}

	if p := config.compiledConditions.Load(); p != nil {
		return *p
	}

	return nil
}

// StoreCompiledConditions atomically replaces the compiled-conditions
// snapshot. Called by the authz layer after compiling an access-control
// config (initial startup and hot reload). Values must be *cel.Expression;
// see compiledConditions for why the type is erased.
func (config *AccessControlConfig) StoreCompiledConditions(programs map[string]any) {
	if config == nil {
		return
	}

	config.compiledConditions.Store(&programs)
}

// IsAuthzEnabled checks if authorization is enabled (access control is configured).
func (config *AccessControlConfig) IsAuthzEnabled() bool {
	return config != nil
}

func (config *AccessControlConfig) AnonymousPolicyExists() bool {
	if config == nil {
		return false
	}

	for _, repository := range config.Repositories {
		if len(repository.AnonymousPolicy) > 0 {
			return true
		}
	}

	return false
}

// HasMixedAnonymousAndAuthenticatedPolicies reports whether the access control configuration contains
// at least one anonymous repository policy AND at least one authenticated-only policy
// (default/admin/user-specific).
func (config *AccessControlConfig) HasMixedAnonymousAndAuthenticatedPolicies() bool {
	return config != nil && config.AnonymousPolicyExists() && !config.ContainsOnlyAnonymousPolicy()
}

// ContainsOnlyAnonymousPolicy checks if the access control configuration contains only anonymous policies.
func (config *AccessControlConfig) ContainsOnlyAnonymousPolicy() bool {
	if config == nil {
		return true
	}

	// Check if admin policy has any actions or users
	if len(config.AdminPolicy.Actions)+len(config.AdminPolicy.Users) > 0 {
		return false
	}

	anonymousPolicyPresent := false

	for _, repository := range config.Repositories {
		// Check if repository has default policy
		if len(repository.DefaultPolicy) > 0 {
			return false
		}

		// Check if repository has anonymous policy
		if len(repository.AnonymousPolicy) > 0 {
			anonymousPolicyPresent = true
		}

		// Check if repository has any non-empty policies
		for _, policy := range repository.Policies {
			if len(policy.Actions)+len(policy.Users) > 0 {
				return false
			}
		}
	}

	return anonymousPolicyPresent
}

// GetRepositories safely gets a copy of the repositories configuration.
func (config *AccessControlConfig) GetRepositories() Repositories {
	if config == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	reposCopy := make(Repositories)
	maps.Copy(reposCopy, config.Repositories)

	return reposCopy
}

// GetAdminPolicy safely gets a copy of the admin policy.
func (config *AccessControlConfig) GetAdminPolicy() Policy {
	if config == nil {
		return Policy{}
	}

	return config.AdminPolicy
}

// GetMetrics safely gets a copy of the metrics configuration.
func (config *AccessControlConfig) GetMetrics() Metrics {
	if config == nil {
		return Metrics{}
	}

	return config.Metrics
}

// ContainsOnlyMetricsAnonymousPolicy identifies an access control configuration
// that contains only an anonymous policy for metrics.
func (config *AccessControlConfig) ContainsOnlyMetricsAnonymousPolicy() bool {
	if config == nil {
		return false
	}
	admin := config.GetAdminPolicy()
	if len(admin.Actions)+len(admin.Users)+len(admin.Groups) > 0 {
		return false
	}

	return len(config.GetRepositories()) == 0 &&
		len(config.GetGroups()) == 0 &&
		slices.Contains(config.GetMetrics().AnonymousPolicy, "read")
}

// GetGroups safely gets a copy of the groups configuration.
func (config *AccessControlConfig) GetGroups() Groups {
	if config == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	groupsCopy := make(Groups)
	maps.Copy(groupsCopy, config.Groups)

	return groupsCopy
}

type (
	Repositories map[string]PolicyGroup
	Groups       map[string]Group
)

type Group struct {
	Users []string
}

type PolicyGroup struct {
	Policies        []Policy
	DefaultPolicy   []string
	AnonymousPolicy []string
}

type Policy struct {
	Users   []string
	Actions []string
	Groups  []string

	// Conditions is an optional list of CEL expressions that must all evaluate
	// to true for this policy entry to grant access. When any condition is
	// false (or fails to evaluate) the policy is ignored.
	Conditions []Condition
}

// Condition is a CEL boolean expression gating a Policy entry, modeled after
// conditional access in cloud IAM systems. The expression is evaluated against
// a `req` struct containing:
//
//   - req.time                  current time as a CEL timestamp (compare with timestamp("..."))
//   - req.method                raw HTTP method of the originating request (e.g. "GET", "PUT")
//   - req.userAgent             User-Agent header
//   - req.action                abstract action being authorized ("read", "create", "update", "delete")
//   - req.repository            the requested repository, when known
//   - req.reference             tag or digest, when the route has one
//   - req.referenceType         "tag", "digest", or "" when the route has no reference
//   - req.tag                   the tag, when reference is a tag
//   - req.digest                the digest, when reference is a digest
//   - req.user.username         authenticated username
//   - req.user.groups           authenticated user's groups (list<string>)
//   - req.auth.anonymous        convenience for `req.user.username == ""`
//   - req.auth.admin            true when the user matches the admin policy
//   - req.client.ip             TCP peer address from RemoteAddr (port stripped); always trustworthy
//   - req.client.forwardedFor   X-Forwarded-For chain as list<string>, left to right; untrusted
//   - req.tls.enabled           whether the request arrived over TLS at zot
//   - req.tls.version           TLS version string ("1.2", "1.3", ...) when applicable
//   - req.claims                authn-time attribute bag (map), populated by the active authn flow
//
// Use `req.action` for action gating (it incorporates create-vs-update logic);
// `req.method` is the raw verb escape hatch.
//
// `req.claims` is a generic surface, not tied to OIDC: today the OIDC bearer
// flow feeds the ID token's claim set into it, and other flows (browser
// OpenID, mTLS cert attributes, ...) can feed this surface as they grow that
// capability.
//
// Network gates: `req.client.ip` is always the TCP peer (the proxy, behind a
// reverse proxy). `req.client.forwardedFor` is the raw X-Forwarded-For header
// chain — useful but untrusted, since any client can set that header. The
// idiomatic pattern is to gate on the chain only after asserting the TCP
// peer is your trusted proxy:
//
//	req.client.ip == "10.0.0.5" && req.client.forwardedFor[0].startsWith("192.0.2.")
//
// When the expression evaluates to false, Message is surfaced to the client
// in the 403 response body's error detail under the "reason" key (so the
// client knows why the policy did not apply) and is also logged for operator
// diagnosis. Internal lookup or evaluation failures are *not* surfaced — the
// client just gets a generic deny — so as not to leak implementation issues.
type Condition struct {
	Expression string
	Message    string
}

type Metrics struct {
	Users           []string
	AnonymousPolicy []string
}

type Config struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	GoVersion       string
	Commit          string
	ReleaseTag      string
	BinaryType      string
	Storage         GlobalStorageConfig
	HTTP            HTTPConfig
	Log             *LogConfig
	Extensions      *extconf.ExtensionConfig
	Scheduler       *SchedulerConfig `json:"scheduler" mapstructure:",omitempty"`
	Cluster         *ClusterConfig   `json:"cluster"   mapstructure:",omitempty"`

	// Mutex to protect concurrent access to config fields
	mu sync.RWMutex
}

func New() *Config {
	return &Config{
		DistSpecVersion: distspec.Version,
		GoVersion:       buildinfo.GoVersion,
		Commit:          buildinfo.Commit,
		ReleaseTag:      buildinfo.ReleaseTag,
		BinaryType:      buildinfo.BinaryType,
		Storage: GlobalStorageConfig{
			StorageConfig: StorageConfig{
				Dedupe:     true,
				GC:         true,
				GCDelay:    storageConstants.DefaultGCDelay,
				GCInterval: storageConstants.DefaultGCInterval,
				Retention:  ImageRetention{},
			},
		},
		HTTP: HTTPConfig{
			Address: "127.0.0.1",
			Port:    "8080",
			Auth:    &AuthConfig{FailDelay: 0},
		},
		Log: &LogConfig{Level: "debug"},
	}
}

func (expConfig StorageConfig) ParamsEqual(actConfig StorageConfig) bool {
	return expConfig.GC == actConfig.GC && expConfig.Dedupe == actConfig.Dedupe &&
		expConfig.RedirectBlobURL == actConfig.RedirectBlobURL && expConfig.GCDelay == actConfig.GCDelay &&
		expConfig.GCInterval == actConfig.GCInterval
}

// isRetentionEnabledInternal checks if retention is enabled without acquiring a lock (internal use only).
func (c *Config) isRetentionEnabledInternal() bool {
	if c == nil {
		return false
	}

	var needsMetaDB bool

	for _, retentionPolicy := range c.Storage.Retention.Policies {
		for _, tagRetentionPolicy := range retentionPolicy.KeepTags {
			if c.isTagsRetentionEnabled(tagRetentionPolicy) {
				needsMetaDB = true
			}
		}

		if c.isUntaggedRetentionEnabledForPolicy(retentionPolicy) {
			needsMetaDB = true
		}
	}

	for _, subpath := range c.Storage.SubPaths {
		for _, retentionPolicy := range subpath.Retention.Policies {
			for _, tagRetentionPolicy := range retentionPolicy.KeepTags {
				if c.isTagsRetentionEnabled(tagRetentionPolicy) {
					needsMetaDB = true
				}
			}

			if c.isUntaggedRetentionEnabledForPolicy(retentionPolicy) {
				needsMetaDB = true
			}
		}
	}

	return needsMetaDB
}

// isTagsRetentionEnabled checks if tags retention is enabled for a specific policy (internal use only).
func (c *Config) isTagsRetentionEnabled(tagRetentionPolicy KeepTagsPolicy) bool {
	if tagRetentionPolicy.MostRecentlyPulledCount != 0 ||
		tagRetentionPolicy.MostRecentlyPushedCount != 0 ||
		tagRetentionPolicy.PulledWithin != nil ||
		tagRetentionPolicy.PushedWithin != nil {
		return true
	}

	return false
}

func (c *Config) isUntaggedRetentionEnabled(untaggedRetentionPolicy KeepUntaggedPolicy) bool {
	if untaggedRetentionPolicy.MostRecentlyPulledCount != 0 ||
		untaggedRetentionPolicy.MostRecentlyPushedCount != 0 ||
		untaggedRetentionPolicy.PulledWithin != nil ||
		untaggedRetentionPolicy.PushedWithin != nil {
		return true
	}

	return false
}

func (c *Config) isUntaggedRetentionEnabledForPolicy(retentionPolicy RetentionPolicy) bool {
	return retentionPolicy.KeepUntagged != nil &&
		(retentionPolicy.DeleteUntagged == nil || *retentionPolicy.DeleteUntagged) &&
		c.isUntaggedRetentionEnabled(*retentionPolicy.KeepUntagged)
}

func isSensitiveConfigMapKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))

	switch normalized {
	case "accesskey", "secretkey", "password", "secret", "token",
		"clientsecret", "sessionhashkey", "sessionencryptkey", "sentinelpassword":
		return true
	default:
		return false
	}
}

func sanitizeStringMapValues(values map[string]string) {
	for key := range values {
		if isSensitiveConfigMapKey(key) {
			values[key] = "******"
		}
	}
}

func sanitizeMapValues(values map[string]any) {
	for key, value := range values {
		if isSensitiveConfigMapKey(key) {
			values[key] = "******"

			continue
		}

		switch typedVal := value.(type) {
		case map[string]any:
			sanitizeMapValues(typedVal)
		case map[string]string:
			sanitizeStringMapValues(typedVal)
		case []any:
			sanitizeSliceValues(typedVal)
		}
	}
}

func sanitizeSliceValues(values []any) {
	for _, value := range values {
		switch typedVal := value.(type) {
		case map[string]any:
			sanitizeMapValues(typedVal)
		case map[string]string:
			sanitizeStringMapValues(typedVal)
		case []any:
			sanitizeSliceValues(typedVal)
		}
	}
}

// Sanitize makes a sanitized copy of the config removing any secrets.
func (c *Config) Sanitize() *Config {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	sanitizedConfig := &Config{}

	if err := DeepCopy(c, sanitizedConfig); err != nil {
		panic(err)
	}

	if sanitizedConfig.Storage.StorageDriver != nil {
		sanitizeMapValues(sanitizedConfig.Storage.StorageDriver)
	}

	if sanitizedConfig.Storage.CacheDriver != nil {
		sanitizeMapValues(sanitizedConfig.Storage.CacheDriver)
	}

	for subPath, subPathCfg := range sanitizedConfig.Storage.SubPaths {
		if subPathCfg.StorageDriver != nil {
			sanitizeMapValues(subPathCfg.StorageDriver)
		}

		if subPathCfg.CacheDriver != nil {
			sanitizeMapValues(subPathCfg.CacheDriver)
		}

		sanitizedConfig.Storage.SubPaths[subPath] = subPathCfg
	}

	// Sanitize HTTP config
	if c.HTTP.Auth != nil {
		if sanitizedConfig.HTTP.Auth.SessionDriver != nil {
			sanitizeMapValues(sanitizedConfig.HTTP.Auth.SessionDriver)
		}

		// Sanitize LDAP bind password
		if c.HTTP.Auth.LDAP != nil && c.HTTP.Auth.LDAP.bindPassword != "" {
			sanitizedConfig.HTTP.Auth.LDAP = &LDAPConfig{}

			if err := DeepCopy(c.HTTP.Auth.LDAP, sanitizedConfig.HTTP.Auth.LDAP); err != nil {
				panic(err)
			}

			sanitizedConfig.HTTP.Auth.LDAP.bindPassword = "******"
		}

		// Sanitize OpenID client secrets
		if c.HTTP.Auth.OpenID != nil {
			sanitizedConfig.HTTP.Auth.OpenID = &OpenIDConfig{
				Providers:            make(map[string]OpenIDProviderConfig),
				CallbackAllowOrigins: slices.Clone(c.HTTP.Auth.OpenID.CallbackAllowOrigins),
			}

			for provider, config := range c.HTTP.Auth.OpenID.Providers {
				sanitizedConfig.HTTP.Auth.OpenID.Providers[provider] = OpenIDProviderConfig{
					Name:         config.Name,
					ClientID:     config.ClientID,
					ClientSecret: "******",
					KeyPath:      config.KeyPath,
					Issuer:       config.Issuer,
					AuthURL:      config.AuthURL,
					TokenURL:     config.TokenURL,
					Scopes:       config.Scopes,
					ClaimMapping: config.ClaimMapping,
				}
			}
		}
	}

	if c.Extensions.IsEventRecorderEnabled() {
		for i, sink := range c.Extensions.Events.Sinks {
			if sink.Credentials == nil {
				continue
			}

			if err := DeepCopy(&c.Extensions.Events.Sinks[i], &sanitizedConfig.Extensions.Events.Sinks[i]); err != nil {
				panic(err)
			}

			if sanitizedConfig.Extensions.Events.Sinks[i].Credentials.Password != "" {
				sanitizedConfig.Extensions.Events.Sinks[i].Credentials.Password = "******"
			}

			if sanitizedConfig.Extensions.Events.Sinks[i].Credentials.Token != "" {
				sanitizedConfig.Extensions.Events.Sinks[i].Credentials.Token = "******"
			}
		}
	}

	return sanitizedConfig
}

// UpdateReloadableConfig updates only the fields that can be reloaded at runtime.
func (c *Config) UpdateReloadableConfig(newConfig *Config) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update storage configuration
	c.Storage.GC = newConfig.Storage.GC
	c.Storage.Dedupe = newConfig.Storage.Dedupe
	c.Storage.RedirectBlobURL = newConfig.Storage.RedirectBlobURL
	c.Storage.GCDelay = newConfig.Storage.GCDelay
	c.Storage.GCInterval = newConfig.Storage.GCInterval

	// Only update retention if we have a metaDB already in place
	if c.isRetentionEnabledInternal() {
		c.Storage.Retention = newConfig.Storage.Retention
	}

	// Update storage subpaths configuration
	for subPath, storageConfig := range newConfig.Storage.SubPaths {
		subPathConfig, ok := c.Storage.SubPaths[subPath]
		if !ok {
			continue
		}

		subPathConfig.GC = storageConfig.GC
		subPathConfig.Dedupe = storageConfig.Dedupe
		subPathConfig.RedirectBlobURL = storageConfig.RedirectBlobURL
		subPathConfig.GCDelay = storageConfig.GCDelay
		subPathConfig.GCInterval = storageConfig.GCInterval

		// Only update retention if we have a metaDB already in place
		if c.isRetentionEnabledInternal() {
			subPathConfig.Retention = storageConfig.Retention
		}

		c.Storage.SubPaths[subPath] = subPathConfig
	}

	// Update authentication configuration
	if c.HTTP.Auth != nil && newConfig.HTTP.Auth != nil {
		c.HTTP.Auth.HTPasswd = newConfig.HTTP.Auth.HTPasswd
		c.HTTP.Auth.LDAP = newConfig.HTTP.Auth.LDAP
		c.HTTP.Auth.APIKey = newConfig.HTTP.Auth.APIKey
		c.HTTP.Auth.OpenID = newConfig.HTTP.Auth.OpenID
		c.HTTP.Auth.SecureSession = newConfig.HTTP.Auth.SecureSession
		c.HTTP.Auth.MTLS = newConfig.HTTP.Auth.MTLS
	}

	// Initialize and update AccessControlConfig
	if newConfig.HTTP.AccessControl != nil && c.HTTP.AccessControl == nil {
		c.HTTP.AccessControl = &AccessControlConfig{}
	}

	if newConfig.HTTP.AccessControl == nil {
		c.HTTP.AccessControl = nil
	} else {
		// Update AccessControlConfig fields directly
		c.HTTP.AccessControl.Repositories = newConfig.HTTP.AccessControl.Repositories
		c.HTTP.AccessControl.AdminPolicy = newConfig.HTTP.AccessControl.AdminPolicy
		c.HTTP.AccessControl.Metrics = newConfig.HTTP.AccessControl.Metrics
		c.HTTP.AccessControl.Groups = newConfig.HTTP.AccessControl.Groups
	}

	// Initialize and update ExtensionConfig
	if newConfig.Extensions != nil && c.Extensions == nil {
		c.Extensions = &extconf.ExtensionConfig{}
	}

	if newConfig.Extensions == nil {
		c.Extensions = nil
	} else if c.Extensions != nil {
		// Update sync extension
		c.Extensions.Sync = newConfig.Extensions.Sync

		// Update search extension
		if newConfig.Extensions.Search != nil && newConfig.Extensions.Search.CVE != nil {
			// Only update if search is enabled
			if c.Extensions.IsSearchEnabled() {
				if c.Extensions.Search != nil {
					c.Extensions.Search.CVE = newConfig.Extensions.Search.CVE
				}
			}
		} else {
			// Remove search CVE config if not present in new config
			if c.Extensions.Search != nil {
				c.Extensions.Search.CVE = nil
			}
		}

		// Update scrub extension
		c.Extensions.Scrub = newConfig.Extensions.Scrub
	}
}

// CopyAuthConfig returns a copy of the auth config if it exists.
func (c *Config) CopyAuthConfig() *AuthConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.Auth == nil {
		return nil
	}

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	authCopy := &AuthConfig{}
	_ = deepcopy.Copy(authCopy, c.HTTP.Auth)

	return authCopy
}

// CopyAccessControlConfig returns a copy of the access control config if it exists.
func (c *Config) CopyAccessControlConfig() *AccessControlConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.AccessControl == nil {
		return nil
	}

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	accessControlCopy := &AccessControlConfig{}
	_ = deepcopy.Copy(accessControlCopy, c.HTTP.AccessControl)

	// deepcopy skips unexported fields, so the compiled-conditions atomic
	// pointer would be empty in the copy. Carry it through by sharing the
	// pointer — compiled programs are immutable and concurrency-safe.
	if p := c.HTTP.AccessControl.compiledConditions.Load(); p != nil {
		accessControlCopy.compiledConditions.Store(p)
	}

	return accessControlCopy
}

// CopyStorageConfig returns a copy of the storage config.
func (c *Config) CopyStorageConfig() GlobalStorageConfig {
	if c == nil {
		return GlobalStorageConfig{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	storageCopy := GlobalStorageConfig{}
	_ = deepcopy.Copy(&storageCopy, &c.Storage)

	return storageCopy
}

// IsBlobRedirectEnabled returns whether blob redirect is enabled for a store path.
// If a matching subpath exists, its setting takes precedence over the global one.
func (c *Config) IsBlobRedirectEnabled(storePath string) bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if storePath != "/" {
		if subPathConfig, ok := c.Storage.SubPaths[storePath]; ok {
			return subPathConfig.RedirectBlobURL
		}
	}

	return c.Storage.RedirectBlobURL
}

// CopyExtensionsConfig returns a copy of the extensions config if it exists.
func (c *Config) CopyExtensionsConfig() *extconf.ExtensionConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Extensions == nil {
		return nil
	}

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	extensionsCopy := &extconf.ExtensionConfig{}
	_ = deepcopy.Copy(extensionsCopy, c.Extensions)

	return extensionsCopy
}

// CopyLogConfig returns a copy of the log config if it exists.
func (c *Config) CopyLogConfig() *LogConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Log == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	logCopy := *c.Log

	return &logCopy
}

// CopyClusterConfig returns a copy of the cluster config if it exists.
func (c *Config) CopyClusterConfig() *ClusterConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Cluster == nil {
		return nil
	}

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	clusterCopy := &ClusterConfig{}
	_ = deepcopy.Copy(clusterCopy, c.Cluster)

	return clusterCopy
}

// CopySchedulerConfig returns a copy of the scheduler config if it exists.
func (c *Config) CopySchedulerConfig() *SchedulerConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Scheduler == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	schedulerCopy := *c.Scheduler

	return &schedulerCopy
}

// CopyTLSConfig returns a copy of the TLS config.
func (c *Config) CopyTLSConfig() *TLSConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.TLS == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	tlsCopy := *c.HTTP.TLS

	return &tlsCopy
}

// CopyRatelimit returns a copy of the rate limit config.
func (c *Config) CopyRatelimit() *RatelimitConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.Ratelimit == nil {
		return nil
	}

	// Return a deep copy using tiendc/go-deepcopy to avoid race conditions
	ratelimitCopy := &RatelimitConfig{}
	_ = deepcopy.Copy(ratelimitCopy, c.HTTP.Ratelimit)

	return ratelimitCopy
}

// GetVersionInfo returns version information (read-only, safe to access directly).
func (c *Config) GetVersionInfo() (string, string, string, string) {
	if c == nil {
		return "", "", "", ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Commit, c.BinaryType, c.GoVersion, c.DistSpecVersion
}

// GetRealm returns the HTTP realm value.
func (c *Config) GetRealm() string {
	if c == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.HTTP.Realm
}

// IsFastRestartEnabled reports whether the controller may skip the startup
// storage walk when the metaDB fast-restart stamp matches the current binary
// and storage config. Defaults to false when unset.
func (c *Config) IsFastRestartEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Storage.FastRestart == nil {
		return false
	}

	return *c.Storage.FastRestart
}

// StorageFingerprint returns a stable SHA-256 of the storage config that influences the
// storage->metaDB walk. It is combined with this binary's identity (see meta.FastRestartStamp)
// into the fast-restart stamp: when it changes, the metaDB may no longer match storage and a full
// reparse is forced. FastRestart and the runtime-only GCMaxSchedulerDelay are excluded so
// toggling them never spuriously invalidates the stamp.
func (c *Config) StorageFingerprint() string {
	if c == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var norm GlobalStorageConfig
	if err := DeepCopy(c.Storage, &norm); err != nil {
		return ""
	}

	norm.FastRestart = nil
	norm.GCMaxSchedulerDelay = 0

	for name, subPath := range norm.SubPaths {
		subPath.GCMaxSchedulerDelay = 0
		norm.SubPaths[name] = subPath
	}

	// encoding/json sorts map keys, so the serialization is deterministic across restarts.
	blob, err := json.Marshal(norm)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(blob)

	return hex.EncodeToString(sum[:])
}

// GetCompat returns a copy of the compatibility config.
func (c *Config) GetCompat() []compat.MediaCompatibility {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.Compat == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	compatCopy := make([]compat.MediaCompatibility, len(c.HTTP.Compat))
	copy(compatCopy, c.HTTP.Compat)

	return compatCopy
}

// GetHTTPAddress returns the HTTP address.
func (c *Config) GetHTTPAddress() string {
	if c == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.HTTP.Address
}

// GetHTTPPort returns the HTTP port.
func (c *Config) GetHTTPPort() string {
	if c == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.HTTP.Port
}

// GetHTTPReadTimeout returns the configured HTTP server read timeout.
func (c *Config) GetHTTPReadTimeout() time.Duration {
	if c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.ReadTimeout == nil {
		return 0
	}

	return *c.HTTP.ReadTimeout
}

// GetHTTPWriteTimeout returns the configured HTTP server write timeout.
func (c *Config) GetHTTPWriteTimeout() time.Duration {
	if c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.WriteTimeout == nil {
		return 0
	}

	return *c.HTTP.WriteTimeout
}

// GetAllowOrigin returns the CORS allow origin configuration.
func (c *Config) GetAllowOrigin() string {
	if c == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.HTTP.AllowOrigin
}

// IsMTLSAuthEnabled checks if mTLS authentication is enabled.
func (c *Config) IsMTLSAuthEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// mTLS is enabled if TLS is configured with client CA certificates
	if c.HTTP.TLS != nil &&
		c.HTTP.TLS.Key != "" &&
		c.HTTP.TLS.Cert != "" &&
		c.HTTP.TLS.CACert != "" {
		return true
	}

	return false
}

// IsRetentionEnabled checks if tags retention is enabled.
func (c *Config) IsRetentionEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.isRetentionEnabledInternal()
}

func (c *Config) IsQuotaEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Storage.MaxRepos > 0
}

// IsCompatEnabled checks if compatibility mode is enabled.
func (c *Config) IsCompatEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.HTTP.Compat) > 0
}

// UseSecureSession returns whether cookies should have the Secure flag set.
// If TLS is configured, always returns true. Otherwise, returns the value
// of SecureSession if set, or false by default.
func (c *Config) UseSecureSession() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// If TLS is configured, cookies should be secure
	if c.HTTP.TLS != nil {
		return true
	}

	// If TLS is not configured, check if SecureSession is explicitly set in auth config
	if c.HTTP.Auth != nil && c.HTTP.Auth.SecureSession != nil {
		return *c.HTTP.Auth.SecureSession
	}

	// Default to false if TLS is not configured and no explicit setting
	return false
}

// IsOpenIDSupported checks if the provider supports OpenID.
func IsOpenIDSupported(provider string) bool {
	for _, supportedProvider := range openIDSupportedProviders {
		if supportedProvider == provider {
			return true
		}
	}

	return false
}

// IsOauth2Supported checks if the provider supports OAuth2.
func IsOauth2Supported(provider string) bool {
	for _, supportedProvider := range oauth2SupportedProviders {
		if supportedProvider == provider {
			return true
		}
	}

	return false
}

// SameFile compare two files.
// This method will first do the stat of two file and compare using os.SameFile method.
func SameFile(str1, str2 string) (bool, error) {
	sFile, err := os.Stat(str1)
	if err != nil {
		return false, err
	}

	tFile, err := os.Stat(str2)
	if err != nil {
		return false, err
	}

	return os.SameFile(sFile, tFile), nil
}

// DeepCopy performs a deep copy of src into dst using JSON marshaling/unmarshaling.
func DeepCopy(src, dst any) error {
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, dst)

	return err
}
