package config

type QuotaConfig struct {
	BaseConfig `mapstructure:",squash"`

	MaxRepos int `json:"maxRepos,omitempty" mapstructure:"maxRepos,omitempty"`
}
