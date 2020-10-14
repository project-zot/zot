// +build minimal

package extensions

import (
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/mux"
)

// DownloadTrivyDB ...
func DownloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

func EnableExtension(extension *ExtensionConfig, log log.Logger, rootDir string) {
	log.Info().Msg("given zot binary doesn't support any extensions, please build zot full binary for this feature")
}

func SetupRoutes(router *mux.Router, rootDir string, imgStore *storage.ImageStore, log log.Logger) {
}
