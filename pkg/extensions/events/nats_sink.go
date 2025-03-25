//go:build events
// +build events

package events

import (
	"context"
	"fmt"

	cenats "github.com/cloudevents/sdk-go/protocol/nats/v2"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/nats-io/nats.go"

	zerr "zotregistry.dev/zot/errors"
	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
)

// NATSSink implements a CloudEvents sink that publishes to NATS.
type NATSSink struct {
	cloudevents.Client
	conn   *nats.Conn
	config eventsconf.SinkConfig
}

// NewNATSSink creates a new NATS sink.
func NewNATSSink(config eventsconf.SinkConfig) (*NATSSink, error) {
	if config.Type != eventsconf.NATS {
		return nil, zerr.ErrInvalidEventSinkType
	}

	if config.Address == "" {
		return nil, zerr.ErrEventSinkAddressEmpty
	}

	opts := []nats.Option{
		nats.Name(EventSource),
		nats.Timeout(config.Timeout),
	}

	if config.Credentials != nil {
		if config.Credentials.File != nil && *config.Credentials.File != "" {
			opts = append(opts, nats.UserCredentials(*config.Credentials.File))
		} else if config.Credentials.Username != "" {
			opts = append(opts, nats.UserInfo(
				config.Credentials.Username,
				config.Credentials.Password,
			))
		}
	}

	if config.TLSConfig != nil && (config.TLSConfig.CACertFile != "" || config.TLSConfig.CertFile != "") {
		tlsConfig, err := getTLSConfig(config)
		if err != nil {
			return nil, err
		}

		opts = append(opts, nats.Secure(tlsConfig))
	}

	sender, err := cenats.NewSender(config.Address, config.Channel, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create NATS protocol: %w", err)
	}

	ceClient, err := cloudevents.NewClient(sender)
	if err != nil {
		return nil, fmt.Errorf("failed to create CloudEvents client: %w", err)
	}

	return &NATSSink{
		Client: ceClient,
		conn:   sender.Conn,
		config: config,
	}, nil
}

// Emit sends a CloudEvent to NATS.
func (s *NATSSink) Emit(event *cloudevents.Event) cloudevents.Result {
	if err := event.Validate(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	defer cancel()

	return s.Send(ctx, *event)
}

// Close closes the NATS connection.
func (s *NATSSink) Close() error {
	if s.conn != nil {
		s.conn.Close()
	}

	return nil
}
