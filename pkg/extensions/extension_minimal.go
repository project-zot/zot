// +build minimal

package extensions

import (
	"net/http"
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
)

// ExtensionServer ...
type ExtensionServer struct {
	GraphqlServer http.Handler
}

// DownloadTrivyDB ...
func DownloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	return nil
}

// ExtensionHandler ...
func ExtensionHandler(rootDir string, log log.Logger, imgStore *storage.ImageStore) *ExtensionServer {
	return &ExtensionServer{}
}
