// +build minimal

package extensions

import (
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
)

// DownloadTrivyDB ...
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

// EnableExtensions ...
func EnableExtensions(extension *ExtensionConfig, log log.Logger, rootDir string) {
	log.Warn().Msg("skipping enabling extensions because given zot binary doesn't support any extensions, please build zot full binary for this feature")
}

// SetupRoutes ...
func SetupRoutes(extension *ExtensionConfig, router *mux.Router, storeController storage.StoreController, log log.Logger) {
	log.Warn().Msg("skipping setting up extensions routes because given zot binary doesn't support any extensions, please build zot full binary for this feature")
}
