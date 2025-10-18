//go:build mcp
// +build mcp

package mcp

import (
	gmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"context"
)

type BuildImageParams struct {
	BaseImage string `json:"base" jsonschema: "Base Image to use"`
}

// buildImage implements the tool that returns the current time for a given city.
func BuildImage(ctx context.Context, req *gmcp.CallToolRequest, params *BuildImageParams) (*gmcp.CallToolResult, any, error) {
	response := ""
	return &gmcp.CallToolResult{
		Content: []gmcp.Content{
			&gmcp.TextContent{Text: response},
		},
	}, nil, nil
}
