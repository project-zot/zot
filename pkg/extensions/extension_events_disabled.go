//go:build !events
// +build !events

package extensions

import (
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/log"
)

func NewEventRecorder(config *config.Config, log log.Logger) (events.Recorder, error) {
	log.Warn().Msg("skipping setting up events because given zot binary doesn't include this feature, " +
		"please build a binary that does so")

	sink := events.LogSink(log)

	return events.NewRecorder(sink, log)
}
