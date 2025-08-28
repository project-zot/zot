package config

import (
	"encoding/json"
	"os"
	"time"

	distspec "github.com/opencontainers/distribution-spec/specs-go"

	"zotregistry.dev/zot/pkg/compat"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
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
	return ldapConf.bindDN
}

func (ldapConf *LDAPConfig) SetBindDN(bindDN string) *LDAPConfig {
	ldapConf.bindDN = bindDN

	return ldapConf
}

func (ldapConf *LDAPConfig) BindPassword() string {
	return ldapConf.bindPassword
}

func (ldapConf *LDAPConfig) SetBindPassword(bindPassword string) *LDAPConfig {
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
	Repositories Repositories `json:"repositories" mapstructure:"repositories"`
	AdminPolicy  Policy
	Groups       Groups
	Metrics      Metrics
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
				Retention: ImageRetention{
					Delay: storageConstants.DefaultRetentionDelay,
				},
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

func DeepCopy(src, dst interface{}) error {
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, dst)

	return err
}

// Sanitize makes a sanitized copy of the config removing any secrets.
func (c *Config) Sanitize() *Config {
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

	if c.IsEventRecorderEnabled() {
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

func (c *Config) IsLdapAuthEnabled() bool {
	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil {
		return true
	}

	return false
}

func (c *Config) IsAuthzEnabled() bool {
	return c.HTTP.AccessControl != nil
}

func (c *Config) IsMTLSAuthEnabled() bool {
	if c.HTTP.TLS != nil &&
		c.HTTP.TLS.Key != "" &&
		c.HTTP.TLS.Cert != "" &&
		c.HTTP.TLS.CACert != "" &&
		!c.IsBasicAuthnEnabled() &&
		!c.HTTP.AccessControl.AnonymousPolicyExists() {
		return true
	}

	return false
}

func (c *Config) IsHtpasswdAuthEnabled() bool {
	if c.HTTP.Auth != nil && c.HTTP.Auth.HTPasswd.Path != "" {
		return true
	}

	return false
}

func (c *Config) IsBearerAuthEnabled() bool {
	if c.HTTP.Auth != nil &&
		c.HTTP.Auth.Bearer != nil &&
		c.HTTP.Auth.Bearer.Cert != "" &&
		c.HTTP.Auth.Bearer.Realm != "" &&
		c.HTTP.Auth.Bearer.Service != "" {
		return true
	}

	return false
}

func (c *Config) IsOpenIDAuthEnabled() bool {
	if c.HTTP.Auth != nil &&
		c.HTTP.Auth.OpenID != nil {
		for provider := range c.HTTP.Auth.OpenID.Providers {
			if isOpenIDAuthProviderEnabled(c, provider) {
				return true
			}
		}
	}

	return false
}

func (c *Config) IsAPIKeyEnabled() bool {
	if c.HTTP.Auth != nil && c.HTTP.Auth.APIKey {
		return true
	}

	return false
}

func (c *Config) IsBasicAuthnEnabled() bool {
	if c.IsHtpasswdAuthEnabled() || c.IsLdapAuthEnabled() ||
		c.IsOpenIDAuthEnabled() || c.IsAPIKeyEnabled() {
		return true
	}

	return false
}

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

func (c *Config) IsMetricsEnabled() bool {
	return c.Extensions != nil && c.Extensions.Metrics != nil && *c.Extensions.Metrics.Enable
}

func (c *Config) IsSearchEnabled() bool {
	return c.Extensions != nil && c.Extensions.Search != nil && *c.Extensions.Search.Enable
}

func (c *Config) IsCveScanningEnabled() bool {
	return c.IsSearchEnabled() && c.Extensions.Search.CVE != nil
}

func (c *Config) IsUIEnabled() bool {
	return c.Extensions != nil && c.Extensions.UI != nil && *c.Extensions.UI.Enable
}

func (c *Config) AreUserPrefsEnabled() bool {
	return c.IsSearchEnabled() && c.IsUIEnabled()
}

func (c *Config) IsMgmtEnabled() bool {
	return c.IsSearchEnabled()
}

func (c *Config) IsImageTrustEnabled() bool {
	return c.Extensions != nil && c.Extensions.Trust != nil && *c.Extensions.Trust.Enable
}

// check if tags retention is enabled.
func (c *Config) IsRetentionEnabled() bool {
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

func (c *Config) isTagsRetentionEnabled(tagRetentionPolicy KeepTagsPolicy) bool {
	if tagRetentionPolicy.MostRecentlyPulledCount != 0 ||
		tagRetentionPolicy.MostRecentlyPushedCount != 0 ||
		tagRetentionPolicy.PulledWithin != nil ||
		tagRetentionPolicy.PushedWithin != nil {
		return true
	}

	return false
}

func (c *Config) IsCosignEnabled() bool {
	return c.IsImageTrustEnabled() && c.Extensions.Trust.Cosign
}

func (c *Config) IsNotationEnabled() bool {
	return c.IsImageTrustEnabled() && c.Extensions.Trust.Notation
}

func (c *Config) IsSyncEnabled() bool {
	return c.Extensions != nil && c.Extensions.Sync != nil && *c.Extensions.Sync.Enable
}

func (c *Config) IsCompatEnabled() bool {
	return len(c.HTTP.Compat) > 0
}

func (c *Config) IsEventRecorderEnabled() bool {
	return c.Extensions != nil && c.Extensions.Events != nil && *c.Extensions.Events.Enable
}

func IsOpenIDSupported(provider string) bool {
	for _, supportedProvider := range openIDSupportedProviders {
		if supportedProvider == provider {
			return true
		}
	}

	return false
}

func IsOauth2Supported(provider string) bool {
	for _, supportedProvider := range oauth2SupportedProviders {
		if supportedProvider == provider {
			return true
		}
	}

	return false
}
