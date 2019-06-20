package api

import (
	dspec "github.com/opencontainers/distribution-spec"
)

type StorageConfig struct {
	RootDirectory string
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
}

type HTTPConfig struct {
	Address string
	Port    string
	TLS     TLSConfig  `mapstructure:",omitempty"`
	Auth    AuthConfig `mapstructure:",omitempty"`
	Realm   string
}

type LogConfig struct {
	Level  string
	Output string
}

type Config struct {
	Version string
	Storage StorageConfig
	HTTP    HTTPConfig
	Log     LogConfig `mapstructure:",omitempty"`
}

func NewConfig() *Config {
	return &Config{
		Version: dspec.Version,
		HTTP:    HTTPConfig{Address: "127.0.0.1", Port: "8080"},
		Log:     LogConfig{Level: "debug"},
	}
}
