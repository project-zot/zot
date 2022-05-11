//go:build scrub
// +build scrub

package extensions

import (
	"time"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/scrub"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)


	func (e *Extensions) EnableScrubExtension(config *config.Config, storeController storage.StoreController,
		log log.Logger) {
		if config.Extensions.Scrub != nil &&
			config.Extensions.Scrub.Interval != 0 {
			minScrubInterval, _ := time.ParseDuration("2h")

			if config.Extensions.Scrub.Interval < minScrubInterval {
				config.Extensions.Scrub.Interval = minScrubInterval

				log.Warn().Msg("Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.") // nolint: lll
			}

			go func() {
				err := scrub.Run(log, config.Extensions.Scrub.Interval, storeController)
				if err != nil {
					log.Error().Err(err).Msg("error while trying to scrub")
				}
			}()
		} else {
			log.Info().Msg("Scrub config not provided, skipping scrub")
		}
	}

