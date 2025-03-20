package events

import (
	"time"
)

type SinkType string

func (s SinkType) String() string {
	return string(s)
}

const (
	HTTP SinkType = "http"
	NATS SinkType = "nats"
)

// Config holds configuration for the events extension.
type Config struct {
	Enable *bool
	Sinks  []SinkConfig
}

type SinkConfig struct {
	*Credentials
	*TLSConfig
	Type    SinkType
	Address string
	Channel string
	Timeout time.Duration
	Proxy   *string
}

type Credentials struct {
	Username string
	Password string
	File     *string
}

type TLSConfig struct {
	CACertFile string
	CertFile   string
	KeyFile    string
}
