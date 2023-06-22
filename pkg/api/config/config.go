package config

import (
	"os"
	"time"

	"github.com/getlantern/deepcopy"
	distspec "github.com/opencontainers/distribution-spec/specs-go"

	extconf "zotregistry.io/zot/pkg/extensions/config"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

var (
	Commit     string //nolint: gochecknoglobals
	ReleaseTag string //nolint: gochecknoglobals
	BinaryType string //nolint: gochecknoglobals
	GoVersion  string //nolint: gochecknoglobals
)

type StorageConfig struct {
	RootDirectory string
	Dedupe        bool
	RemoteCache   bool
	GC            bool
	Commit        bool
	GCDelay       time.Duration
	GCInterval    time.Duration
	StorageDriver map[string]interface{} `mapstructure:",omitempty"`
	CacheDriver   map[string]interface{} `mapstructure:",omitempty"`
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
	Address       string
	Port          string
	AllowOrigin   string // comma separated
	TLS           *TLSConfig
	Auth          *AuthConfig
	AccessControl *AccessControlConfig `mapstructure:"accessControl,omitempty"`
	Realm         string
	Ratelimit     *RatelimitConfig `mapstructure:",omitempty"`
}

type LDAPConfig struct {
	Port               int
	Insecure           bool
	StartTLS           bool // if !Insecure, then StartTLS or LDAPs
	SkipVerify         bool
	SubtreeSearch      bool
	Address            string
	BindDN             string
	UserGroupAttribute string
	BindPassword       string
	BaseDN             string
	UserAttribute      string
	CACert             string
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
}

func New() *Config {
	return &Config{
		DistSpecVersion: distspec.Version,
		GoVersion:       GoVersion,
		Commit:          Commit,
		ReleaseTag:      ReleaseTag,
		BinaryType:      BinaryType,
		Storage: GlobalStorageConfig{
			StorageConfig: StorageConfig{GC: true, GCDelay: storageConstants.DefaultGCDelay, Dedupe: true},
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
