//go:build events
// +build events

package extensions

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/log"
)

func NewEventRecorder(config *config.Config, log log.Logger) (events.Recorder, error) {
	if !config.AreEventsEnabled() {
		sink := events.LogSink(log)

		return events.NewRecorder(sink, log)
	}

	return nil, zerr.ErrEventsExtensionDisabled
}
