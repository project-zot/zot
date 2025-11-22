//go:build !events

package extensions

import (
	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
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

	log.Warn().Msg("skipping setting up events because given zot binary doesn't include this feature, " +
		"please build a binary that does so")

	return nil, zerr.ErrExtensionNotEnabled
}
