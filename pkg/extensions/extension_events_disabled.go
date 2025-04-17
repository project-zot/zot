//go:build !events
// +build !events

package extensions

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/events"
	"zotregistry.dev/zot/pkg/log"
)

func NewEventRecorder(config *config.Config, log log.Logger) (events.Recorder, error) {
	if !config.IsEventRecorderEnabled() {
		log.Info().Msg("events disabled in configuration")

		return nil, zerr.ErrExtensionNotEnabled
	}

	log.Warn().Msg("skipping setting up events because given zot binary doesn't include this feature, " +
		"please build a binary that does so")

	return nil, zerr.ErrExtensionNotEnabled
}
