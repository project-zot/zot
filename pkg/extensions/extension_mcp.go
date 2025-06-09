//go:build mcp
// +build mcp

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/mcp"
	"zotregistry.dev/zot/pkg/log"
)

// SetupMCPRoutes sets up the MCP GraphQL endpoint on the router.
func SetupMCPRoutes(conf *config.Config, router *mux.Router, log log.Logger) {

	log.Info().Msg("setting up MCP routes")

	allowedMethods := zcommon.AllowedMethods(http.MethodGet, http.MethodPost)

	extRouter := router.PathPrefix(constants.ExtMCPPrefix).Subrouter()
	extRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	extRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	extRouter.Use(zcommon.AddExtensionSecurityHeaders())
	extRouter.Methods(allowedMethods...).
		Handler(mcp.NewMCPServer(router)) //nolint: staticcheck

	log.Info().Msg("finished setting up MCP routes")
}
