// +build minimal

package extensions

import (
	"time"

	"github.com/anuvu/zot/pkg/api/config"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
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

// SetupRoutes ...
func SetupRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController, log log.Logger) {
	log.Warn().Msg("skipping setting up extensions routes because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature")
}

// SyncOneImage...
func SyncOneImage(config *config.Config, log log.Logger, repoName, reference string) (bool, error) {
	log.Warn().Msg("skipping syncing on demand because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature")
	return false, nil
}
