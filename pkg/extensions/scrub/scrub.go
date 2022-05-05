//go:build extended || scrub
// +build extended scrub

package scrub

import (
	"time"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// Scrub Extension...
func Run(log log.Logger, scrubInterval time.Duration, storeController storage.StoreController) error {
	for {
		log.Info().Msg("executing scrub to check manifest/blob integrity")

		results, err := storeController.CheckAllBlobsIntegrity()
		if err != nil {
			return err
		}

		for _, result := range results.ScrubResults {
			if result.Status == "ok" {
				log.Info().
					Str("image", result.ImageName).
					Str("tag", result.Tag).
					Str("status", result.Status).
					Msg("scrub: blobs/manifest ok")
			} else {
				log.Warn().
					Str("image", result.ImageName).
					Str("tag", result.Tag).
					Str("status", result.Status).
					Str("error", result.Error).
					Msg("scrub: blobs/manifest affected")
			}
		}

		log.Info().Str("Scrub completed, next scrub scheduled after", scrubInterval.String()).Msg("")

		time.Sleep(scrubInterval)
	}
}
