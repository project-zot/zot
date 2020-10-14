// +build extended

package extensions

import (
	"github.com/anuvu/zot/pkg/extensions/search"
	"github.com/anuvu/zot/pkg/storage"

	"time"

	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"

	"github.com/anuvu/zot/pkg/log"
)

// Extension Server for graphql...
type ExtensionServer struct {
	GraphqlServer *gqlHandler.Server
}

// DownloadTrivyDB ...
func DownloadTrivyDB(dbDir string, log log.Logger, updateInterval time.Duration) error {
	for {
		log.Info().Msg("Updating the CVE database")

		err := cveinfo.UpdateCVEDb(dbDir, log)
		if err != nil {
			return err
		}

		log.Info().Str("Db update completed, next update scheduled after", updateInterval.String()).Msg("")

		time.Sleep(updateInterval)
	}
}

// ExtensionHandler ...
func ExtensionHandler(rootDir string, log log.Logger, imgStore *storage.ImageStore) *ExtensionServer {
	extensionServer := &ExtensionServer{}
	resConfig := search.GetResolverConfig(rootDir, log, imgStore)
	extensionServer.GraphqlServer = gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig))

	return extensionServer
}
