//go:build events

package events

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	cloudevents "github.com/cloudevents/sdk-go/v2"

	eventsconf "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/log"
)

type eventRecorder struct {
	log   log.Logger
	sinks []Sink
}

var _ Recorder = (*eventRecorder)(nil)

func (r eventRecorder) Close() {
	err := r.closeSinks()
	if err != nil {
		r.log.Error().Err(err).Msg("failed to close sinks")
	}
}

func (r eventRecorder) closeSinks() error {
	var retErr error

	for _, sink := range r.sinks {
		if err := sink.Close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}

	return retErr
}

func (r eventRecorder) publish(event *cloudevents.Event) {
	go func() {
		succeeded := 0

		for _, sink := range r.sinks {
			if response := sink.Emit(event); cloudevents.IsNACK(response) || cloudevents.IsUndelivered(response) {
				r.log.Error().Err(response).Msg("failed to publish event")

				continue
			}

			succeeded++
		}

		logEvent := r.log.Info()
		msg := "event published successfully"

		if succeeded < len(r.sinks) {
			logEvent = r.log.Warn()
			msg = "event publish incomplete"

			if succeeded == 0 {
				msg = "event publish failed"
			}
		}

		logEvent.Str("eventType", event.Type()).
			Int("totalSinks", len(r.sinks)).
			Int("sinksSucceeded", succeeded).
			Int("sinksFailed", len(r.sinks)-succeeded).
			Msg(msg)
	}()
}

func (r eventRecorder) RepositoryCreated(name string, ectx *EventContext) {
	event, err := newEventBuilder().
		WithEventType(RepositoryCreatedEventType).
		WithDataField("name", name).
		WithEventContext(ectx).
		Build()
	if err != nil {
		r.log.Warn().Err(err).Msg("failed to create event")

		return
	}

	r.publish(event)
}

func (r eventRecorder) ImageUpdated(name, reference, digest, mediaType, manifest string, ectx *EventContext) {
	event, err := newEventBuilder().
		WithEventType(ImageUpdatedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		WithEventContext(ectx).
		Build()
	if err != nil {
		r.log.Warn().Err(err).Msg("failed to create event")

		return
	}

	r.publish(event)
}

func (r eventRecorder) ImageDeleted(name, reference, digest, mediaType string, ectx *EventContext) {
	event, err := newEventBuilder().
		WithEventType(ImageDeletedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithEventContext(ectx).
		Build()
	if err != nil {
		r.log.Warn().Err(err).Msg("failed to create event")

		return
	}

	r.publish(event)
}

func (r eventRecorder) ImageLintFailed(name, reference, digest, mediaType, manifest string, ectx *EventContext) {
	event, err := newEventBuilder().
		WithEventType(ImageLintFailedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		WithEventContext(ectx).
		Build()
	if err != nil {
		r.log.Warn().Err(err).Msg("failed to create event")

		return
	}

	r.publish(event)
}

func (r eventRecorder) ImageScanned(name, reference, digest, mediaType string,
	summary ImageScanSummary, ectx *EventContext,
) {
	event, err := newEventBuilder().
		WithEventType(ImageScannedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("summary", summary).
		WithEventContext(ectx).
		Build()
	if err != nil {
		r.log.Warn().Err(err).Msg("failed to create event")

		return
	}

	r.publish(event)
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
