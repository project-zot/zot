// +build minimal

package extensions

import (
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
)

// nolint: deadcode,unused
func downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

// EnableExtensions ...
func EnableExtensions(extension *ExtensionConfig, log log.Logger, rootDir string) {
	msg := "skipping enabling extensions because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature"
	log.Warn().Msg(msg)
}

// SetupRoutes ...
func SetupRoutes(extension *ExtensionConfig, router *mux.Router,
	storeController storage.StoreController, log log.Logger) {
	msg := "skipping setting up extensions routes because given zot binary doesn't support " +
		"any extensions, please build zot full binary for this feature"
	log.Warn().Msg(msg)
}
