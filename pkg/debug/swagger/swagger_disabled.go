//go:build !debug
// +build !debug

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

package debug

import (
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log" //nolint:goimports
	// as required by swaggo.
	_ "zotregistry.io/zot/swagger"
)

func SetupSwaggerRoutes(conf *config.Config, router *mux.Router, authFunc mux.MiddlewareFunc,
	log log.Logger,
) {
	// swagger swagger "/swagger/v2/index.html"
	log.Warn().Msg("skipping enabling swagger because given zot binary" +
		"doesn't include this feature, please build a binary that does so")
}
