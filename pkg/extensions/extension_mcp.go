//go:build mcp
// +build mcp

package extensions

import (
	"net/http"

	"github.com/gorilla/mux"
	gmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/extensions/mcp"
	"zotregistry.dev/zot/v2/pkg/log"
)

func SetupMCPRoutes(conf *config.Config, router *mux.Router,
	authnFunc mux.MiddlewareFunc, log log.Logger,
) {
	log.Info().Msg("setting up mcp routes")

	// Create an MCP server.
	server := gmcp.NewServer(&gmcp.Implementation{
		Name:    "zot-mcp-server",
		Version: "1.0.0",
	}, nil)

	// Add the cityTime tool.
	gmcp.AddTool(server, &gmcp.Tool{
		Name:        "buildImage",
		Description: "Build a OCI container image",
	}, mcp.BuildImage)

	// Create the streamable HTTP handler.
	handler := gmcp.NewStreamableHTTPHandler(func(req *http.Request) *gmcp.Server {
		return server
	}, nil)

	if conf.IsMCPEnabled() {
		extRouter := router.PathPrefix(constants.DefaultMCPExtensionRoute).Subrouter()
		extRouter.Use(authnFunc)
		extRouter.Methods("POST").Handler(handler)
	}
}
