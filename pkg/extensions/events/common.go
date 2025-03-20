package events

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
)

const (
	DefaultHTTPTimeout = 30 * time.Second
)

func getTLSConfig(config eventsconf.SinkConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if config.TLSConfig.CACertFile != "" {
		caCert, err := os.ReadFile(config.TLSConfig.CACertFile)
		if err != nil {
			return nil, err
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, err
		}
		tlsConfig.RootCAs = caCertPool
	}

	if config.TLSConfig.CertFile != "" && config.TLSConfig.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSConfig.CertFile, config.TLSConfig.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
