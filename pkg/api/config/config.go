package config

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	distspec "github.com/opencontainers/distribution-spec/specs-go"

	"zotregistry.dev/zot/pkg/compat"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
)

var (
	Commit     string //nolint: gochecknoglobals
	ReleaseTag string //nolint: gochecknoglobals
	BinaryType string //nolint: gochecknoglobals
	GoVersion  string //nolint: gochecknoglobals

	openIDSupportedProviders = [...]string{"google", "gitlab", "oidc"} //nolint: gochecknoglobals
	oauth2SupportedProviders = [...]string{"github"}                   //nolint: gochecknoglobals

)

type StorageConfig struct {
	RootDirectory string
	Dedupe        bool
	RemoteCache   bool
	GC            bool
	Commit        bool
	GCDelay       time.Duration // applied for blobs
	GCInterval    time.Duration
	Retention     ImageRetention
	StorageDriver map[string]interface{} `mapstructure:",omitempty"`
	CacheDriver   map[string]interface{} `mapstructure:",omitempty"`
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
}

type KeepTagsPolicy struct {
	Patterns                []string
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
	return a != nil && a.Bearer != nil && a.Bearer.Cert != "" && a.Bearer.Realm != "" && a.Bearer.Service != ""
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

// GetFailDelay returns the configured fail delay for authentication attempts.
func (a *AuthConfig) GetFailDelay() int {
	if a == nil {
		return 0
	}

	return a.FailDelay
}

type BearerConfig struct {
	Realm   string
	Service string
	Cert    string
}

type SessionKeys struct {
	HashKey    string
	EncryptKey string `mapstructure:",omitempty"`
}

type OpenIDConfig struct {
	Providers map[string]OpenIDProviderConfig
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
	Scopes          []string
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
	Address       string
	ExternalURL   string `mapstructure:",omitempty"`
	Port          string
	AllowOrigin   string // comma separated
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

// contains the scale-out configuration which is identical for all zot replicas.
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
	SubPaths      map[string]StorageConfig
}

type AccessControlConfig struct {
	mu           sync.RWMutex
	Repositories Repositories `json:"repositories" mapstructure:"repositories"`
	AdminPolicy  Policy
	Groups       Groups
	Metrics      Metrics
}

// IsAuthzEnabled checks if authorization is enabled (access control is configured).
func (config *AccessControlConfig) IsAuthzEnabled() bool {
	return config != nil
}

func (config *AccessControlConfig) AnonymousPolicyExists() bool {
	if config == nil {
		return false
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	for _, repository := range config.Repositories {
		if len(repository.AnonymousPolicy) > 0 {
			return true
		}
	}

	return false
}

// ContainsOnlyAnonymousPolicy checks if the access control configuration contains only anonymous policies.
func (config *AccessControlConfig) ContainsOnlyAnonymousPolicy() bool {
	if config == nil {
		return true
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

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

// SetRepositories safely sets the repositories configuration.
func (config *AccessControlConfig) SetRepositories(repositories Repositories) {
	if config == nil {
		return
	}

	config.mu.Lock()
	defer config.mu.Unlock()

	config.Repositories = repositories
}

// SetAdminPolicy safely sets the admin policy.
func (config *AccessControlConfig) SetAdminPolicy(policy Policy) {
	if config == nil {
		return
	}

	config.mu.Lock()
	defer config.mu.Unlock()

	config.AdminPolicy = policy
}

// SetMetrics safely sets the metrics configuration.
func (config *AccessControlConfig) SetMetrics(metrics Metrics) {
	if config == nil {
		return
	}

	config.mu.Lock()
	defer config.mu.Unlock()

	config.Metrics = metrics
}

// SetGroups safely sets the groups configuration.
func (config *AccessControlConfig) SetGroups(groups Groups) {
	if config == nil {
		return
	}

	config.mu.Lock()
	defer config.mu.Unlock()

	config.Groups = groups
}

// GetRepositories safely gets a copy of the repositories configuration.
func (config *AccessControlConfig) GetRepositories() Repositories {
	if config == nil {
		return nil
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	// Return a copy to avoid race conditions
	reposCopy := make(Repositories)
	for k, v := range config.Repositories {
		reposCopy[k] = v
	}

	return reposCopy
}

// GetAdminPolicy safely gets a copy of the admin policy.
func (config *AccessControlConfig) GetAdminPolicy() Policy {
	if config == nil {
		return Policy{}
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	return config.AdminPolicy
}

// GetMetrics safely gets a copy of the metrics configuration.
func (config *AccessControlConfig) GetMetrics() Metrics {
	if config == nil {
		return Metrics{}
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	return config.Metrics
}

// GetGroups safely gets a copy of the groups configuration.
func (config *AccessControlConfig) GetGroups() Groups {
	if config == nil {
		return nil
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	// Return a copy to avoid race conditions
	groupsCopy := make(Groups)
	for k, v := range config.Groups {
		groupsCopy[k] = v
	}

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
}

type Metrics struct {
	Users []string
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
		GoVersion:       GoVersion,
		Commit:          Commit,
		ReleaseTag:      ReleaseTag,
		BinaryType:      BinaryType,
		Storage: GlobalStorageConfig{
			StorageConfig: StorageConfig{
				Dedupe:     true,
				GC:         true,
				GCDelay:    storageConstants.DefaultGCDelay,
				GCInterval: storageConstants.DefaultGCInterval,
				Retention:  ImageRetention{},
			},
		},
		HTTP: HTTPConfig{Address: "127.0.0.1", Port: "8080", Auth: &AuthConfig{FailDelay: 0}},
		Log:  &LogConfig{Level: "debug"},
	}
}

func (expConfig StorageConfig) ParamsEqual(actConfig StorageConfig) bool {
	return expConfig.GC == actConfig.GC && expConfig.Dedupe == actConfig.Dedupe &&
		expConfig.GCDelay == actConfig.GCDelay && expConfig.GCInterval == actConfig.GCInterval
}

// =============================================================================
// INTERNAL METHODS (non-locking, for use by other methods that already hold locks)
// =============================================================================

// isSearchEnabledInternal checks if search is enabled without acquiring a lock (internal use only).
func (c *Config) isSearchEnabledInternal() bool {
	if c == nil {
		return false
	}

	return c.Extensions != nil && c.Extensions.Search != nil && *c.Extensions.Search.Enable
}

// isEventRecorderEnabledInternal checks if event recorder is enabled without acquiring a lock (internal use only).
func (c *Config) isEventRecorderEnabledInternal() bool {
	if c == nil {
		return false
	}

	return c.Extensions != nil && c.Extensions.Events != nil && *c.Extensions.Events.Enable
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
	}

	for _, subpath := range c.Storage.SubPaths {
		for _, retentionPolicy := range subpath.Retention.Policies {
			for _, tagRetentionPolicy := range retentionPolicy.KeepTags {
				if c.isTagsRetentionEnabled(tagRetentionPolicy) {
					needsMetaDB = true
				}
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

// isBasicAuthnEnabled checks if any basic authentication method is enabled (internal, no locking).
func (c *Config) isBasicAuthnEnabled() bool {
	if c == nil {
		return false
	}

	// Check HTPasswd
	if c.HTTP.Auth != nil && c.HTTP.Auth.HTPasswd.Path != "" {
		return true
	}

	// Check LDAP
	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil {
		return true
	}

	// Check API Key
	if c.HTTP.Auth != nil && c.HTTP.Auth.APIKey {
		return true
	}

	// Check OpenID
	if c.HTTP.Auth != nil && c.HTTP.Auth.OpenID != nil {
		for provider := range c.HTTP.Auth.OpenID.Providers {
			if isOpenIDAuthProviderEnabled(c, provider) {
				return true
			}
		}
	}

	return false
}

// isOpenIDAuthProviderEnabled checks if a specific OpenID provider is enabled (internal use only).
func isOpenIDAuthProviderEnabled(config *Config, provider string) bool {
	if providerConfig, ok := config.HTTP.Auth.OpenID.Providers[provider]; ok {
		if IsOpenIDSupported(provider) {
			if providerConfig.ClientID != "" || providerConfig.Issuer != "" ||
				len(providerConfig.Scopes) > 0 {
				return true
			}
		} else if IsOauth2Supported(provider) {
			if providerConfig.ClientID != "" || len(providerConfig.Scopes) > 0 {
				return true
			}
		}
	}

	return false
}

// =============================================================================
// PUBLIC THREAD-SAFE METHODS (acquire locks)
// =============================================================================

// =============================================================================
// CONFIGURATION MANAGEMENT METHODS
// =============================================================================

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

	// Sanitize HTTP config
	if c.HTTP.Auth != nil {
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
				Providers: make(map[string]OpenIDProviderConfig),
			}

			for provider, config := range c.HTTP.Auth.OpenID.Providers {
				sanitizedConfig.HTTP.Auth.OpenID.Providers[provider] = OpenIDProviderConfig{
					Name:         config.Name,
					ClientID:     config.ClientID,
					ClientSecret: "******",
					KeyPath:      config.KeyPath,
					Issuer:       config.Issuer,
					Scopes:       config.Scopes,
				}
			}
		}
	}

	if c.isEventRecorderEnabledInternal() {
		for i, sink := range c.Extensions.Events.Sinks {
			if sink.Credentials == nil {
				continue
			}

			if err := DeepCopy(&c.Extensions.Events.Sinks[i], &sanitizedConfig.Extensions.Events.Sinks[i]); err != nil {
				panic(err)
			}

			sanitizedConfig.Extensions.Events.Sinks[i].Credentials.Password = "******"
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

	// Capture values while holding the main lock
	var (
		newRepositories    Repositories
		newAdminPolicy     Policy
		newMetrics         Metrics
		newGroups          Groups
		newSyncConfig      *syncconf.Config
		newSearchCVEConfig *extconf.CVEConfig
		newScrubConfig     *extconf.ScrubConfig
	)

	if newConfig.HTTP.AccessControl != nil {
		// Access fields directly to avoid potential deadlock from calling getter methods
		// while holding the main Config lock
		newRepositories = newConfig.HTTP.AccessControl.Repositories
		newAdminPolicy = newConfig.HTTP.AccessControl.AdminPolicy
		newMetrics = newConfig.HTTP.AccessControl.Metrics
		newGroups = newConfig.HTTP.AccessControl.Groups
	}

	if newConfig.Extensions != nil {
		if newConfig.Extensions.Sync != nil {
			newSyncConfig = newConfig.Extensions.Sync
		}

		if newConfig.Extensions.Search != nil && newConfig.Extensions.Search.CVE != nil {
			newSearchCVEConfig = newConfig.Extensions.Search.CVE
		}

		if newConfig.Extensions.Scrub != nil {
			newScrubConfig = newConfig.Extensions.Scrub
		}
	}

	// Update basic fields while holding the main lock
	if c.HTTP.Auth != nil {
		c.HTTP.Auth.HTPasswd = newConfig.HTTP.Auth.HTPasswd
		c.HTTP.Auth.LDAP = newConfig.HTTP.Auth.LDAP
	}

	// Update storage config
	c.Storage.GC = newConfig.Storage.GC
	c.Storage.Dedupe = newConfig.Storage.Dedupe
	c.Storage.GCDelay = newConfig.Storage.GCDelay
	c.Storage.GCInterval = newConfig.Storage.GCInterval

	// Only if we have a metaDB already in place
	if c.isRetentionEnabledInternal() {
		c.Storage.Retention = newConfig.Storage.Retention
	}

	// Update subpaths
	for subPath, storageConfig := range newConfig.Storage.SubPaths {
		subPathConfig, ok := c.Storage.SubPaths[subPath]
		if ok {
			subPathConfig.GC = storageConfig.GC
			subPathConfig.Dedupe = storageConfig.Dedupe
			subPathConfig.GCDelay = storageConfig.GCDelay
			subPathConfig.GCInterval = storageConfig.GCInterval
			// only if we have a metaDB already in place
			if c.isRetentionEnabledInternal() {
				subPathConfig.Retention = storageConfig.Retention
			}
			c.Storage.SubPaths[subPath] = subPathConfig
		}
	}

	// Initialize ExtensionConfig if needed while holding the main lock
	if newConfig.Extensions != nil && c.Extensions == nil {
		c.Extensions = &extconf.ExtensionConfig{}
	}

	// Set ExtensionConfig to nil if new config doesn't have it
	if newConfig.Extensions == nil {
		c.Extensions = nil
	}

	// Initialize AccessControlConfig if needed while holding the main lock
	if newConfig.HTTP.AccessControl != nil && c.HTTP.AccessControl == nil {
		c.HTTP.AccessControl = &AccessControlConfig{}
	}

	// Set AccessControlConfig to nil if new config doesn't have it
	if newConfig.HTTP.AccessControl == nil {
		c.HTTP.AccessControl = nil
	}

	c.mu.Unlock() // Release the main lock before calling setter methods

	// Now update AccessControlConfig using its own thread-safe methods
	if newConfig.HTTP.AccessControl != nil {
		c.HTTP.AccessControl.SetRepositories(newRepositories)
		c.HTTP.AccessControl.SetAdminPolicy(newAdminPolicy)
		c.HTTP.AccessControl.SetMetrics(newMetrics)
		c.HTTP.AccessControl.SetGroups(newGroups)
	}

	// Now update ExtensionConfig using its own thread-safe methods
	if newConfig.Extensions != nil && c.Extensions != nil {
		// reload sync extension
		if newSyncConfig != nil {
			c.Extensions.SetSyncConfig(newSyncConfig)
		} else {
			// Remove sync extension if not present in new config
			c.Extensions.SetSyncConfig(nil)
		}

		// reload only if search is enabled and reloaded config has search extension
		if c.isSearchEnabledInternal() && newSearchCVEConfig != nil {
			c.Extensions.SetSearchCVEConfig(newSearchCVEConfig)
		} else {
			// Remove search CVE config if not present in new config
			c.Extensions.SetSearchCVEConfig(nil)
		}

		// reload scrub extension
		if newScrubConfig != nil {
			c.Extensions.SetScrubConfig(newScrubConfig)
		} else {
			// Remove scrub extension if not present in new config
			c.Extensions.SetScrubConfig(nil)
		}
	}
}

// =============================================================================
// THREAD-SAFE GETTER METHODS
// =============================================================================

// GetAuthConfig returns a copy of the auth config if it exists.
func (c *Config) GetAuthConfig() *AuthConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.Auth == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	authCopy := *c.HTTP.Auth

	return &authCopy
}

// GetAccessControlConfig returns the access control config if it exists
// The returned AccessControlConfig has its own mutex for thread-safety.
func (c *Config) GetAccessControlConfig() *AccessControlConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.AccessControl == nil {
		return nil
	}

	return c.HTTP.AccessControl
}

// GetHTTPConfig returns a copy of the HTTP config.
func (c *Config) GetHTTPConfig() HTTPConfig {
	if c == nil {
		return HTTPConfig{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to avoid race conditions
	httpCopy := c.HTTP

	return httpCopy
}

// GetStorageConfig returns a copy of the storage config.
func (c *Config) GetStorageConfig() GlobalStorageConfig {
	if c == nil {
		return GlobalStorageConfig{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to avoid race conditions
	storageCopy := c.Storage

	return storageCopy
}

// GetExtensionsConfig returns the extensions config if it exists.
// The returned ExtensionConfig has its own mutex for thread-safety.
func (c *Config) GetExtensionsConfig() *extconf.ExtensionConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Extensions == nil {
		return nil
	}

	return c.Extensions
}

// GetLogConfig returns a copy of the log config if it exists.
func (c *Config) GetLogConfig() *LogConfig {
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

// GetClusterConfig returns a copy of the cluster config if it exists.
func (c *Config) GetClusterConfig() *ClusterConfig {
	if c == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Cluster == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	clusterCopy := *c.Cluster

	return &clusterCopy
}

// GetSchedulerConfig returns a copy of the scheduler config if it exists.
func (c *Config) GetSchedulerConfig() *SchedulerConfig {
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

// GetVersionInfo returns version information (read-only, safe to access directly).
func (c *Config) GetVersionInfo() (string, string, string, string) {
	if c == nil {
		return "", "", "", ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.Commit, c.BinaryType, c.GoVersion, c.DistSpecVersion
}

// =============================================================================
// STATUS CHECK METHODS
// =============================================================================

// IsMTLSAuthEnabled checks if mTLS authentication is enabled.
func (c *Config) IsMTLSAuthEnabled() bool {
	if c == nil {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.HTTP.TLS != nil &&
		c.HTTP.TLS.Key != "" &&
		c.HTTP.TLS.Cert != "" &&
		c.HTTP.TLS.CACert != "" &&
		!c.isBasicAuthnEnabled() &&
		!c.HTTP.AccessControl.AnonymousPolicyExists() {
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

	var needsMetaDB bool

	for _, retentionPolicy := range c.Storage.Retention.Policies {
		for _, tagRetentionPolicy := range retentionPolicy.KeepTags {
			if c.isTagsRetentionEnabled(tagRetentionPolicy) {
				needsMetaDB = true
			}
		}
	}

	for _, subpath := range c.Storage.SubPaths {
		for _, retentionPolicy := range subpath.Retention.Policies {
			for _, tagRetentionPolicy := range retentionPolicy.KeepTags {
				if c.isTagsRetentionEnabled(tagRetentionPolicy) {
					needsMetaDB = true
				}
			}
		}
	}

	return needsMetaDB
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

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

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
func DeepCopy(src, dst interface{}) error {
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, dst)

	return err
}
