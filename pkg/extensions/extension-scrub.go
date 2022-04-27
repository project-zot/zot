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

// EnableScrubExtension enables scrub extension.
func EnableScrubExtension(config *config.Config, log log.Logger, run bool, imgStore storage.ImageStore, repo string) {
	if !run {
		if config.Extensions.Scrub != nil &&
			config.Extensions.Scrub.Interval != 0 {
			minScrubInterval, _ := time.ParseDuration("2h")

			if config.Extensions.Scrub.Interval < minScrubInterval {
				config.Extensions.Scrub.Interval = minScrubInterval

				log.Warn().Msg("Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
			}
		} else {
			log.Info().Msg("Scrub config not provided, skipping scrub")
		}
	} else {
		scrub.RunScrubRepo(imgStore, repo, log)
	}
}
