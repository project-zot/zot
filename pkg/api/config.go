package api

import (
	"fmt"

	"github.com/anuvu/zot/errors"
	ext "github.com/anuvu/zot/pkg/extensions"
	"github.com/anuvu/zot/pkg/log"
	"github.com/getlantern/deepcopy"
	distspec "github.com/opencontainers/distribution-spec/specs-go"
	"github.com/spf13/viper"
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

type HTTPConfig struct {
	Address          string
	Port             string
	TLS              *TLSConfig
	Auth             *AuthConfig
	RawAccessControl map[string]interface{} `mapstructure:"accessControl,omitempty"`
	Realm            string
	AllowReadAccess  bool `mapstructure:",omitempty"`
	ReadOnly         bool `mapstructure:",omitempty"`
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
	RootDirectory string
	Dedupe        bool
	GC            bool
	SubPaths      map[string]StorageConfig
}

type Config struct {
	Version       string
	GoVersion     string
	Commit        string
	BinaryType    string
	AccessControl *AccessControlConfig
	Storage       GlobalStorageConfig
	HTTP          HTTPConfig
	Log           *LogConfig
	Extensions    *ext.ExtensionConfig
}

func NewConfig() *Config {
	return &Config{
		Version:    distspec.Version,
		GoVersion:  GoVersion,
		Commit:     Commit,
		BinaryType: BinaryType,
		Storage:    GlobalStorageConfig{GC: true, Dedupe: true},
		HTTP:       HTTPConfig{Address: "127.0.0.1", Port: "8080"},
		Log:        &LogConfig{Level: "debug"},
	}
}

// Sanitize makes a sanitized copy of the config removing any secrets.
func (c *Config) Sanitize() *Config {
	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil && c.HTTP.Auth.LDAP.BindPassword != "" {
		s := &Config{}
		if err := deepcopy.Copy(s, c); err != nil {
			panic(err)
		}

		s.HTTP.Auth.LDAP = &LDAPConfig{}

		if err := deepcopy.Copy(s.HTTP.Auth.LDAP, c.HTTP.Auth.LDAP); err != nil {
			panic(err)
		}

		s.HTTP.Auth.LDAP.BindPassword = "******"

		return s
	}

	return c
}

func (c *Config) Validate(log log.Logger) error {
	// LDAP configuration
	if c.HTTP.Auth != nil && c.HTTP.Auth.LDAP != nil {
		l := c.HTTP.Auth.LDAP
		if l.UserAttribute == "" {
			log.Error().Str("userAttribute", l.UserAttribute).Msg("invalid LDAP configuration")
			return errors.ErrLDAPConfig
		}
	}

	return nil
}

// LoadAccessControlConfig populates config.AccessControl struct with values from config.
func (c *Config) LoadAccessControlConfig() error {
	if c.HTTP.RawAccessControl == nil {
		return nil
	}

	c.AccessControl = &AccessControlConfig{}
	c.AccessControl.Repositories = make(map[string]PolicyGroup)

	for k := range c.HTTP.RawAccessControl {
		var policies []Policy

		var policyGroup PolicyGroup

		if k == "adminpolicy" {
			adminPolicy := viper.GetStringMapStringSlice("http.accessControl.adminPolicy")
			c.AccessControl.AdminPolicy.Actions = adminPolicy["actions"]
			c.AccessControl.AdminPolicy.Users = adminPolicy["users"]

			continue
		}

		err := viper.UnmarshalKey(fmt.Sprintf("http.accessControl.%s.policies", k), &policies)
		if err != nil {
			return err
		}

		defaultPolicy := viper.GetStringSlice(fmt.Sprintf("http.accessControl.%s.defaultPolicy", k))
		policyGroup.Policies = policies
		policyGroup.DefaultPolicy = defaultPolicy
		c.AccessControl.Repositories[k] = policyGroup
	}

	return nil
}
