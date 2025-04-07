//go:build events
// +build events

package events

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	cloudevents "github.com/cloudevents/sdk-go/v2"

	eventsconf "zotregistry.dev/zot/pkg/extensions/config/events"
	"zotregistry.dev/zot/pkg/log"
)

type eventRecorder struct {
	log   log.Logger
	sinks []Sink
}

var _ Recorder = (*eventRecorder)(nil)

func (r eventRecorder) publish(event *cloudevents.Event) error {
	for _, sink := range r.sinks {
		if response := sink.Emit(event); cloudevents.IsNACK(response) || cloudevents.IsUndelivered(response) {
			r.log.Error().Err(response).Msg("failed to publish event")

			return response
		}
	}

	r.log.Info().Msgf("event published successfully: %s", event.Type())

	return nil
}

func (r eventRecorder) RepositoryCreated(name string) error {
	event, err := newEventBuilder().
		WithEventType(RepositoryCreatedEventType).
		WithDataField("name", name).
		Build()
	if err != nil {
		return err
	}

	return r.publish(event)
}

func (r eventRecorder) ImageUpdated(name, reference, digest, mediaType, manifest string) error {
	event, err := newEventBuilder().
		WithEventType(ImageUpdatedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		Build()
	if err != nil {
		return err
	}

	return r.publish(event)
}

func (r eventRecorder) ImageDeleted(name, reference, digest, mediaType string) error {
	event, err := newEventBuilder().
		WithEventType(ImageDeletedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		Build()
	if err != nil {
		return err
	}

	return r.publish(event)
}

func (r eventRecorder) ImageLintFailed(name, reference, digest, mediaType, manifest string) error {
	event, err := newEventBuilder().
		WithEventType(ImageLintFailedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		Build()
	if err != nil {
		return err
	}

	return r.publish(event)
}

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
