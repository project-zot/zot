//go:build mcp
// +build mcp

package extensions

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/extensions/search/gql_generated"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

func IsBuiltWithMCPExtension() bool {
	return true
}

// MCP (Model Context Protocol) server implementation for zot registry
type MCPServer struct {
	Conf            *config.Config
	Log             log.Logger
	MetaDB          mTypes.MetaDB
	StoreController storage.StoreController
}

// MCPResource represents a resource exposed via MCP
type MCPResource struct {
	URI         string            `json:"uri"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	MimeType    string            `json:"mimeType"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// MCPToolCall represents a tool call request
type MCPToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// MCPToolResult represents a tool call result
type MCPToolResult struct {
	Content []MCPContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

// MCPContent represents content in MCP responses
type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	Data string `json:"data,omitempty"`
}

// MCPListResourcesResponse represents the response for listing resources
type MCPListResourcesResponse struct {
	Resources []MCPResource `json:"resources"`
}

// MCPGetResourceResponse represents the response for getting a resource
type MCPGetResourceResponse struct {
	Contents []MCPContent `json:"contents"`
}

// MCPListToolsResponse represents available tools
type MCPListToolsResponse struct {
	Tools []MCPTool `json:"tools"`
}

// MCPTool represents an available MCP tool
type MCPTool struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// SetupMCPRoutes sets up MCP extension routes
func SetupMCPRoutes(conf *config.Config, router *mux.Router, storeController storage.StoreController,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	log.Info().Msg("setting up MCP routes")

	if !conf.IsSearchEnabled() {
		log.Warn().Msg("MCP extension requires search extension to be enabled")
		return
	}

	mcpServer := &MCPServer{
		Conf:            conf,
		Log:             log,
		MetaDB:          metaDB,
		StoreController: storeController,
	}

	allowedMethods := zcommon.AllowedMethods(http.MethodGet, http.MethodPost)

	mcpRouter := router.PathPrefix(constants.ExtMCP).Subrouter()
	mcpRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	mcpRouter.Use(zcommon.AddExtensionSecurityHeaders())
	mcpRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))

	// MCP endpoints
	mcpRouter.Methods(http.MethodGet).Path("/resources").HandlerFunc(mcpServer.ListResources)
	mcpRouter.Methods(http.MethodGet).Path("/resources/{uri}").HandlerFunc(mcpServer.GetResource)
	mcpRouter.Methods(http.MethodGet).Path("/tools").HandlerFunc(mcpServer.ListTools)
	mcpRouter.Methods(http.MethodPost).Path("/tools/{name}").HandlerFunc(mcpServer.CallTool)

	log.Info().Msg("finished setting up MCP routes")
}

// ListResources lists all available MCP resources
func (mcp *MCPServer) ListResources(w http.ResponseWriter, r *http.Request) {
	resources := []MCPResource{
		{
			URI:         "registry://repositories",
			Name:        "Registry Repositories",
			Description: "List of all repositories in the registry",
			MimeType:    "application/json",
			Metadata: map[string]string{
				"type": "repository_list",
			},
		},
		{
			URI:         "registry://images",
			Name:        "Registry Images",
			Description: "List of all images in the registry",
			MimeType:    "application/json",
			Metadata: map[string]string{
				"type": "image_list",
			},
		},
		{
			URI:         "registry://vulnerabilities",
			Name:        "CVE Information",
			Description: "Vulnerability information for registry images",
			MimeType:    "application/json",
			Metadata: map[string]string{
				"type": "cve_list",
			},
		},
		{
			URI:         "registry://annotations",
			Name:        "Image Annotations",
			Description: "Annotations and metadata for registry images",
			MimeType:    "application/json",
			Metadata: map[string]string{
				"type": "annotation_list",
			},
		},
	}

	response := MCPListResourcesResponse{
		Resources: resources,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetResource retrieves a specific MCP resource
func (mcp *MCPServer) GetResource(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uri := vars["uri"]

	var contents []MCPContent
	var err error

	switch uri {
	case "registry://repositories":
		contents, err = mcp.getRepositoriesResource()
	case "registry://images":
		contents, err = mcp.getImagesResource()
	case "registry://vulnerabilities":
		contents, err = mcp.getVulnerabilitiesResource()
	case "registry://annotations":
		contents, err = mcp.getAnnotationsResource()
	default:
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	if err != nil {
		mcp.Log.Error().Err(err).Str("uri", uri).Msg("failed to get MCP resource")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := MCPGetResourceResponse{
		Contents: contents,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ListTools lists available MCP tools
func (mcp *MCPServer) ListTools(w http.ResponseWriter, r *http.Request) {
	tools := []MCPTool{
		{
			Name:        "search_repositories",
			Description: "Search for repositories in the registry",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query string",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of results to return",
						"default":     10,
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "search_images",
			Description: "Search for images in the registry",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query string",
					},
					"tag": map[string]interface{}{
						"type":        "string",
						"description": "Filter by specific tag",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of results to return",
						"default":     10,
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "get_cve_info",
			Description: "Get CVE information for a specific image",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"repository": map[string]interface{}{
						"type":        "string",
						"description": "Repository name",
					},
					"tag": map[string]interface{}{
						"type":        "string",
						"description": "Image tag",
					},
				},
				"required": []string{"repository", "tag"},
			},
		},
	}

	response := MCPListToolsResponse{
		Tools: tools,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CallTool handles MCP tool calls
func (mcp *MCPServer) CallTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	toolName := vars["name"]

	var toolCall MCPToolCall
	if err := json.NewDecoder(r.Body).Decode(&toolCall); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var result MCPToolResult
	var err error

	switch toolName {
	case "search_repositories":
		result, err = mcp.handleSearchRepositories(toolCall.Arguments)
	case "search_images":
		result, err = mcp.handleSearchImages(toolCall.Arguments)
	case "get_cve_info":
		result, err = mcp.handleGetCVEInfo(toolCall.Arguments)
	default:
		result = MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Tool not found",
			}},
			IsError: true,
		}
	}

	if err != nil {
		mcp.Log.Error().Err(err).Str("tool", toolName).Msg("failed to execute MCP tool")
		result = MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Internal server error: " + err.Error(),
			}},
			IsError: true,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Helper methods for getting resources

func (mcp *MCPServer) getRepositoriesResource() ([]MCPContent, error) {
	if mcp.MetaDB == nil {
		return []MCPContent{{
			Type: "text",
			Text: "MetaDB not available - search extension may not be enabled",
		}}, nil
	}

	// Get repositories from MetaDB
	repoMetas, err := mcp.MetaDB.GetAllRepoNames()
	if err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(map[string]interface{}{
		"repositories": repoMetas,
		"count":        len(repoMetas),
		"timestamp":    time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	return []MCPContent{{
		Type: "text",
		Text: string(data),
	}}, nil
}

func (mcp *MCPServer) getImagesResource() ([]MCPContent, error) {
	if mcp.MetaDB == nil {
		return []MCPContent{{
			Type: "text",
			Text: "MetaDB not available - search extension may not be enabled",
		}}, nil
	}

	// Get basic image information
	repoMetas, err := mcp.MetaDB.GetAllRepoNames()
	if err != nil {
		return nil, err
	}

	var imageList []map[string]interface{}
	for _, repoName := range repoMetas {
		// For each repo, get basic tag information
		repoMeta, err := mcp.MetaDB.GetRepoMeta(r.Context(), repoName)
		if err != nil {
			continue
		}

		for tag := range repoMeta.Tags {
			imageList = append(imageList, map[string]interface{}{
				"repository": repoName,
				"tag":        tag,
			})
		}
	}

	data, err := json.MarshalIndent(map[string]interface{}{
		"images":    imageList,
		"count":     len(imageList),
		"timestamp": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	return []MCPContent{{
		Type: "text",
		Text: string(data),
	}}, nil
}

func (mcp *MCPServer) getVulnerabilitiesResource() ([]MCPContent, error) {
	// Placeholder for CVE information
	// In a real implementation, this would integrate with the CVE scanner
	data, err := json.MarshalIndent(map[string]interface{}{
		"message":   "CVE scanning requires additional configuration",
		"timestamp": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	return []MCPContent{{
		Type: "text",
		Text: string(data),
	}}, nil
}

func (mcp *MCPServer) getAnnotationsResource() ([]MCPContent, error) {
	// Placeholder for annotations
	data, err := json.MarshalIndent(map[string]interface{}{
		"message":   "Annotations information available through image metadata",
		"timestamp": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return nil, err
	}

	return []MCPContent{{
		Type: "text",
		Text: string(data),
	}}, nil
}

// Helper methods for tool calls

func (mcp *MCPServer) handleSearchRepositories(args map[string]interface{}) (MCPToolResult, error) {
	query, ok := args["query"].(string)
	if !ok {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Query parameter is required",
			}},
			IsError: true,
		}, nil
	}

	limit := 10
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	if mcp.MetaDB == nil {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Search not available - MetaDB not initialized",
			}},
			IsError: true,
		}, nil
	}

	// Search repositories
	repoMetas, err := mcp.MetaDB.SearchRepos(r.Context(), query)
	if err != nil {
		return MCPToolResult{}, err
	}

	// Limit results
	if len(repoMetas) > limit {
		repoMetas = repoMetas[:limit]
	}

	// Convert to simple format
	var results []map[string]interface{}
	for _, repo := range repoMetas {
		results = append(results, map[string]interface{}{
			"name":        repo.Name,
			"lastUpdated": repo.LastUpdatedImage.LastUpdated,
			"size":        repo.Size,
			"platforms":   repo.Platforms,
		})
	}

	data, err := json.MarshalIndent(map[string]interface{}{
		"query":     query,
		"results":   results,
		"count":     len(results),
		"timestamp": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return MCPToolResult{}, err
	}

	return MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

func (mcp *MCPServer) handleSearchImages(args map[string]interface{}) (MCPToolResult, error) {
	query, ok := args["query"].(string)
	if !ok {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Query parameter is required",
			}},
			IsError: true,
		}, nil
	}

	limit := 10
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	if mcp.MetaDB == nil {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Search not available - MetaDB not initialized",
			}},
			IsError: true,
		}, nil
	}

	// Search images
	imageMetas, err := mcp.MetaDB.SearchTags(r.Context(), query)
	if err != nil {
		return MCPToolResult{}, err
	}

	// Limit results
	if len(imageMetas) > limit {
		imageMetas = imageMetas[:limit]
	}

	// Convert to simple format
	var results []map[string]interface{}
	for _, image := range imageMetas {
		results = append(results, map[string]interface{}{
			"repository":  image.Repo,
			"tag":         image.Tag,
			"digest":      image.Digest,
			"lastUpdated": image.LastUpdated,
			"size":        image.Size,
		})
	}

	data, err := json.MarshalIndent(map[string]interface{}{
		"query":     query,
		"results":   results,
		"count":     len(results),
		"timestamp": time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return MCPToolResult{}, err
	}

	return MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}

func (mcp *MCPServer) handleGetCVEInfo(args map[string]interface{}) (MCPToolResult, error) {
	repository, ok := args["repository"].(string)
	if !ok {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Repository parameter is required",
			}},
			IsError: true,
		}, nil
	}

	tag, ok := args["tag"].(string)
	if !ok {
		return MCPToolResult{
			Content: []MCPContent{{
				Type: "text",
				Text: "Tag parameter is required",
			}},
			IsError: true,
		}, nil
	}

	// Placeholder for CVE information
	// In a real implementation, this would integrate with the CVE scanner
	data, err := json.MarshalIndent(map[string]interface{}{
		"repository": repository,
		"tag":        tag,
		"message":    "CVE scanning requires CVE scanner to be configured and enabled",
		"timestamp":  time.Now().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return MCPToolResult{}, err
	}

	return MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: string(data),
		}},
	}, nil
}
