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

func IsSupportedSink(sinkType SinkType) bool {
	supportedSinks := map[SinkType]struct{}{
		HTTP: {},
		NATS: {},
	}

	_, ok := supportedSinks[sinkType]

	return ok
}

// Config holds configuration for the events extension.
type Config struct {
	Enable *bool
	Sinks  []SinkConfig

	// Source overrides the CloudEvents source attribute on every event this
	// instance publishes. Empty keeps the built-in value. Set it when a
	// receiver has to tell one deployment, or one tenant, from another: the
	// built-in value is the same for every zot in existence.
	Source string

	// TypePrefix overrides the namespace event types are published under, so
	// image.updated becomes "<TypePrefix>.image.updated". Empty keeps the
	// built-in namespace.
	TypePrefix string
}

type SinkConfig struct {
	*Credentials
	*TLSConfig

	Type    SinkType
	Address string
	Channel string
	Timeout time.Duration
	Proxy   *string
	Headers map[string]string
}

type Credentials struct {
	Username string
	Password string
	File     *string
	Token    string
}

type TLSConfig struct {
	CACertFile string
	CertFile   string
	KeyFile    string
}
