package extensions

import (
	"context"
	goSync "sync"
	"time"

	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type Extension interface {
	downloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error
	EnableExtensions(config *config.Config, log log.Logger, rootDir string)
	EnableSyncExtension(ctx context.Context, config *config.Config, wg *goSync.WaitGroup,
		storeController storage.StoreController, log log.Logger)
	EnableScrubExtension(config *config.Config, storeController storage.StoreController,
		log log.Logger)
	SetupRoutes(*config.Config, *mux.Router, storage.StoreController, log.Logger)
	SyncOneImage(config *config.Config, storeController storage.StoreController,
		repoName, reference string, isArtifact bool, log log.Logger) error
}

type ExtensionObj struct{

}


