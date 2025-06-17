//go:build !mcp
// +build !mcp

package extensions

import (
	"github.com/gorilla/mux"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
)

// IsBuiltWithMCPExtension returns false if the MCP extension is not built in.
func IsBuiltWithMCPExtension() bool {
	return false
}

// SetupMCPRoutes is a no-op if the MCP extension is not built in.
func SetupMCPRoutes(conf *config.Config, router *mux.Router, log log.Logger) {
	log.Warn().Msg("skipping setting up MCP routes because given zot binary doesn't include this feature, please build a binary that does so")
}
