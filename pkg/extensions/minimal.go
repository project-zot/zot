//go:build minimal
// +build minimal

package extensions

import (
	goSync "sync"
	"time"

	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// nolint: deadcode,unused
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

// EnableExtensions ...
func EnableExtensions(config *config.Config, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling extensions because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature")
}

// EnableSyncExtension ...
func EnableSyncExtension(config *config.Config, wg *goSync.WaitGroup,
	storeController storage.StoreController, log log.Logger) {
	log.Warn().Msg("skipping enabling sync extension because given zot binary doesn't support any extensions," +
		"please build zot full binary for this feature")
}

// SetupRoutes ...
func SetupRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController,
	pathPrefix string, log log.Logger) {
	log.Warn().Msg("skipping setting up extensions routes because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature")
}

// SyncOneImage ...
func SyncOneImage(config *config.Config, storeController storage.StoreController,
	repoName, reference string, isArtifact bool, log log.Logger) error {
	log.Warn().Msg("skipping syncing on demand because given zot binary doesn't support any extensions," +
		"please build zot full binary for this feature")

	return nil
}
