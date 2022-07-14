package config

import (
	"fmt"
	"time"

	"github.com/getlantern/deepcopy"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/spf13/viper"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/storage"
)

var (
	Commit     string // nolint: gochecknoglobals
	BinaryType string // nolint: gochecknoglobals
	GoVersion  string // nolint: gochecknoglobals
)

type StorageConfig struct {
	RootDirectory string
	GC            bool
	Dedupe        bool
	Commit        bool
	GCDelay       time.Duration
	GCInterval    time.Duration
	StorageDriver map[string]interface{} `mapstructure:",omitempty"`
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
	FailDelay int
	HTPasswd  AuthHTPasswd
	LDAP      *LDAPConfig
	Bearer    *BearerConfig
}

type BearerConfig struct {
	Realm   string
	Service string
	Cert    string
}

type MethodRatelimitConfig struct {
	Method string
	Rate   int
}

type RatelimitConfig struct {
	Rate    *int                    // requests per second
	Methods []MethodRatelimitConfig `mapstructure:",omitempty"`
}

type HTTPConfig struct {
	Address          string
	Port             string
	AllowOrigin      string // comma separated
	TLS              *TLSConfig
	Auth             *AuthConfig
	RawAccessControl map[string]interface{} `mapstructure:"accessControl,omitempty"`
	Realm            string
	Ratelimit        *RatelimitConfig `mapstructure:",omitempty"`
}

type LDAPConfig struct {
	Port          int
	Insecure      bool
	StartTLS      bool // if !Insecure, then StartTLS or LDAPs
	SkipVerify    bool
	SubtreeSearch bool
	Address       string
	BindDN        string
	BindPassword  string
	BaseDN        string
	UserAttribute string
	CACert        string
}

type LogConfig struct {
	Level  string
	Output string
	Audit  string
}

type GlobalStorageConfig struct {
	Dedupe        bool
	GC            bool
	Commit        bool
	GCDelay       time.Duration
	GCInterval    time.Duration
	RootDirectory string
	StorageDriver map[string]interface{} `mapstructure:",omitempty"`
	SubPaths      map[string]StorageConfig
}

type AccessControlConfig struct {
	Repositories Repositories
	AdminPolicy  Policy
}

type Repositories map[string]PolicyGroup

type PolicyGroup struct {
	Policies        []Policy
	DefaultPolicy   []string
	AnonymousPolicy []string
}

type Policy struct {
	Users   []string
	Actions []string
}

type Config struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	GoVersion       string
	Commit          string
	BinaryType      string
	AccessControl   *AccessControlConfig
	Storage         GlobalStorageConfig
	HTTP            HTTPConfig
	Log             *LogConfig
	Extensions      *extconf.ExtensionConfig
}

func New() *Config {
	return &Config{
		DistSpecVersion: distspec.Version,
		GoVersion:       GoVersion,
		Commit:          Commit,
		BinaryType:      BinaryType,
		Storage:         GlobalStorageConfig{GC: true, GCDelay: storage.DefaultGCDelay, Dedupe: true},
		HTTP:            HTTPConfig{Address: "127.0.0.1", Port: "8080", Auth: &AuthConfig{FailDelay: 0}},
		Log:             &LogConfig{Level: "debug"},
	}
}

// Sanitize makes a sanitized copy of the config removing any secrets.
func (c *Config) Sanitize() *Config {
	sanitizedConfig := &Config{}
	if err := deepcopy.Copy(sanitizedConfig, c); err != nil {
		panic(err)
	}

	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil && c.HTTP.Auth.LDAP.BindPassword != "" {
		sanitizedConfig.HTTP.Auth.LDAP = &LDAPConfig{}

		if err := deepcopy.Copy(sanitizedConfig.HTTP.Auth.LDAP, c.HTTP.Auth.LDAP); err != nil {
			panic(err)
		}

		sanitizedConfig.HTTP.Auth.LDAP.BindPassword = "******"
	}

	return sanitizedConfig
}

// LoadAccessControlConfig populates config.AccessControl struct with values from config.
func (c *Config) LoadAccessControlConfig(viperInstance *viper.Viper) error {
	if c.HTTP.RawAccessControl == nil {
		return nil
	}

	c.AccessControl = &AccessControlConfig{}
	c.AccessControl.Repositories = make(map[string]PolicyGroup)

	for policy := range c.HTTP.RawAccessControl {
		var policies []Policy

		var policyGroup PolicyGroup

		if policy == "adminpolicy" {
			adminPolicy := viperInstance.GetStringMapStringSlice("http::accessControl::adminPolicy")
			c.AccessControl.AdminPolicy.Actions = adminPolicy["actions"]
			c.AccessControl.AdminPolicy.Users = adminPolicy["users"]

			continue
		}

		err := viperInstance.UnmarshalKey(fmt.Sprintf("http::accessControl::%s::policies", policy), &policies)
		if err != nil {
			return err
		}

		defaultPolicy := viperInstance.GetStringSlice(fmt.Sprintf("http::accessControl::%s::defaultPolicy", policy))
		policyGroup.DefaultPolicy = defaultPolicy

		anonymousPolicy := viperInstance.GetStringSlice(fmt.Sprintf("http::accessControl::%s::anonymousPolicy", policy))
		policyGroup.Policies = policies
		policyGroup.AnonymousPolicy = anonymousPolicy
		c.AccessControl.Repositories[policy] = policyGroup
	}

	return nil
}
