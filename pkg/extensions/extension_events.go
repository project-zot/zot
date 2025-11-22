//go:build events

package extensions

import (
	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	eventsconfig "zotregistry.dev/zot/v2/pkg/extensions/config/events"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/log"
)

func NewEventRecorder(config *config.Config, log log.Logger) (events.Recorder, error) {
	// Get extensions config safely
	extensionsConfig := config.CopyExtensionsConfig()
	if !extensionsConfig.IsEventRecorderEnabled() {
		log.Info().Msg("events disabled in configuration")

		return nil, zerr.ErrExtensionNotEnabled
	}

	eventConfig := extensionsConfig.GetEventsConfig()
	if eventConfig == nil || eventConfig.Sinks == nil || len(eventConfig.Sinks) == 0 {
		log.Info().Msg("no sinks provided, skipping events extension setup")

		return nil, zerr.ErrExtensionNotEnabled
	}

	var sinks []events.Sink

	log.Info().Msg("setting up event sinks")

	for _, sinkConfig := range eventConfig.Sinks {
		switch sinkConfig.Type {
		case eventsconfig.HTTP:
			sink, err := events.NewHTTPSink(sinkConfig)
			if err != nil {
				return nil, err
			}

			sinks = append(sinks, sink)
		case eventsconfig.NATS:
			sink, err := events.NewNATSSink(sinkConfig)
			if err != nil {
				return nil, err
			}

			sinks = append(sinks, sink)
		default:
			log.Warn().Msgf("skipping unsupported sink type: %s", sinkConfig.Type)
		}
	}

	if len(sinks) == 0 {
		log.Warn().Msg("no sinks provided, skipping events extension setup")

		return nil, zerr.ErrExtensionNotEnabled
	}

	return events.NewRecorder(log, sinks...)
}
