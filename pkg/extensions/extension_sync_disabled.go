//go:build !sync
// +build !sync

package extensions

import (
	"context"
	goSync "sync"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// EnableSyncExtension ...
func EnableSyncExtension(ctx context.Context,
	config *config.Config, wg *goSync.WaitGroup,
	storeController storage.StoreController, log log.Logger,
) {
	log.Warn().Msg("skipping enabling sync extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}

// SyncOneImage ...
func SyncOneImage(ctx context.Context, config *config.Config, storeController storage.StoreController,
	repoName, reference string, artifactType string, log log.Logger,
) error {
	log.Warn().Msg("skipping syncing on demand because given zot binary doesn't include this feature," +
		"please build a binary that does so")

	return nil
}
