package mcp

import (
	"net/http"

	"github.com/gorilla/mux"
	mcp "github.com/metoro-io/mcp-golang"
)

type mcpRouter struct {
	router *mux.Router
}

func (m *mcpRouter) Close() error {
	return nil
}

// NewMCPServer returns an HTTP handler for the MCP GraphQL API
func NewMCPServer(router *mux.Router) http.Handler {
	// Create a new server with the transport
	transport := NewGinTransport()
	srv := mcp.NewServer(transport)
	if srv == nil {
		return nil
	}

	/*
		// Register a simple tool
		err := srv.RegisterTool("time", "Returns the current time in the specified format", func(args TimeArgs) (*mcp_golang.ToolResponse, error) {
			format := args.Format
			return mcp_golang.NewToolResponse(mcp_golang.NewTextContent(time.Now().Format(format))), nil
		})
		if err != nil {
			panic(err)
		}*/

	return router
}
