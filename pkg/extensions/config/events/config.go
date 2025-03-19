package events

// Config holds configuration for the events extension.
type Config struct {
	Enable *bool
	NATS   *NATSConfig
}

type Credentials struct {
	Username *string
	Password *string
	File     *string
}

type TLSConfig struct {
	CACertFile string
	CertFile   string
	KeyFile    string
}

// NATSConfig holds configuration for a nats event service.
type NATSConfig struct {
	Enable      bool
	Server      string
	Credentials *Credentials
	TLSConfig   *TLSConfig
}
