package sync

import (
	"time"
)

// key is registry address.
type CredentialsFile map[string]Credentials

type Credentials struct {
	Username string
	Password string
}

type Config struct {
	Enable          *bool
	CredentialsFile string
	Registries      []RegistryConfig
}

type RegistryConfig struct {
	URLs         []string
	PollInterval time.Duration
	Content      []Content
	TLSVerify    *bool
	OnDemand     bool
	CertDir      string
	MaxRetries   *int
	RetryDelay   *time.Duration
	OnlySigned   *bool
}

type Content struct {
	Prefix      string
	Tags        *Tags
	Destination string `mapstructure:",omitempty"`
	StripPrefix bool
}

type Tags struct {
	Regex  *string
	Semver *bool
}
