//go:build events
// +build events

package extensions

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	eventsconfig "zotregistry.dev/zot/pkg/extensions/config/events"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/log"
)

func NewEventRecorder(config *config.Config, log log.Logger) (events.Recorder, error) {
	if !config.IsEventRecorderEnabled() {
		log.Warn().Msg("events disabled in configuration")

		return nil, zerr.ErrExtensionNotEnabled
	}

	eventConfig := config.Extensions.Events

	if len(eventConfig.Sinks) == 0 {
		return nil, zerr.ErrExtensionNotEnabled
	}

	sinks := make([]events.Sink, len(eventConfig.Sinks))

	for i, sinkConfig := range eventConfig.Sinks {
		switch sinkConfig.Type {
		case eventsconfig.HTTP:
			sink, err := events.NewHTTPSink(sinkConfig)
			if err != nil {
				return nil, err
			}
			sinks[i] = sink
		case eventsconfig.NATS:
			sink, err := events.NewNATSSink(sinkConfig)
			if err != nil {
				return nil, err
			}
			sinks[i] = sink
		}
	}

	return events.NewRecorder(log, sinks...)
}
