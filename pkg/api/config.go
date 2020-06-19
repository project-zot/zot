package api

import (
	"time"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/getlantern/deepcopy"
	dspec "github.com/opencontainers/distribution-spec"
)

// Commit ...
var (
	Commit string //nolint: gochecknoglobals
)

const updateInterval = 24

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
	Address         string
	Port            string
	TLS             *TLSConfig
	Auth            *AuthConfig
	Realm           string
	AllowReadAccess bool `mapstructure:",omitempty"`
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
}

type ExtensionConfig struct {
	Search *SearchConfig
}

type SearchConfig struct {
	// CVE search
	CVE *CVEConfig
}

type CVEConfig struct {
	UpdateInterval time.Duration // should be 2 hours or more, if not specified default be kept as 24 hours
}

type Config struct {
	Version    string
	Commit     string
	Storage    StorageConfig
	HTTP       HTTPConfig
	Log        *LogConfig
	Extensions *ExtensionConfig
}

func NewConfig() *Config {
	return &Config{
		Version:    dspec.Version,
		Commit:     Commit,
		Storage:    StorageConfig{GC: true, Dedupe: true},
		HTTP:       HTTPConfig{Address: "127.0.0.1", Port: "8080"},
		Log:        &LogConfig{Level: "debug"},
		Extensions: &ExtensionConfig{&SearchConfig{CVE: &CVEConfig{UpdateInterval: updateInterval}}},
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
