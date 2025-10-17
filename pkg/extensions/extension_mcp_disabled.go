//go:build !mcp
// +build !mcp

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

// EnableMcpExtension ...
func EnableMcpExtension(config *config.Config, log log.Logger, rootDir string) error {
	log.Warn().Msg("skipping enabling mcp extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")

		return nil
}

func SetupMCPRoutes(conf *config.Config, router *mux.Router,
authnFunc, authzFunc mux.MiddlewareFunc, log log.Logger,
) {
}
	log.Warn().Msg("skipping setting up mcp routes because given zot binary doesn't include this feature," +
		"please build a binary that does so")
