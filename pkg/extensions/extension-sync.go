//go:build sync
// +build sync

package extensions

import (
	"context"
	goSync "sync"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func init() {
	 EnableSyncExtension = func(ctx context.Context, config *config.Config, wg *goSync.WaitGroup,
		storeController storage.StoreController, log log.Logger,
	) {
		if config.Extensions.Sync != nil && *config.Extensions.Sync.Enable {
			if err := sync.Run(ctx, *config.Extensions.Sync, storeController, wg, log); err != nil {
				log.Error().Err(err).Msg("Error encountered while setting up syncing")
			}
		} else {
			log.Info().Msg("Sync registries config not provided or disabled, skipping sync")
		}
	}

	SyncOneImage = func(config *config.Config, storeController storage.StoreController,
		repoName, reference string, isArtifact bool, log log.Logger,
	) error {
		log.Info().Msgf("syncing image %s:%s", repoName, reference)

		err := sync.OneImage(*config.Extensions.Sync, storeController, repoName, reference, isArtifact, log)

		return err
	}
}

// // nolint: deadcode,unused
// func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
// 	return nil
// }

// // EnableExtensions ...
// func EnableExtensions(config *config.Config, log log.Logger, rootDir string) {
// 	log.Warn().Msg("skipping enabling extensions because given zot binary doesn't support " +
// 		"any extensions, please build zot full binary for this feature")
// }

// // EnableScrubExtension ...
// func EnableScrubExtension(config *config.Config, storeController storage.StoreController,
// 	log log.Logger,
// ) {
// 	log.Warn().Msg("skipping enabling scrub extension because given zot binary doesn't support any extensions," +
// 		"please build zot full binary for this feature")
// }

// // SetupRoutes ...
// func SetupRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController, log log.Logger) {
// 	log.Warn().Msg("skipping setting up extensions routes because given zot binary doesn't support " +
// 		"any extensions, please build zot full binary for this feature")
// }
