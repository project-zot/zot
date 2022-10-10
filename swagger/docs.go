// GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag at
// 2022-05-20 22:28:21.990630149 +0000 UTC m=+0.151110280

package swagger

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/alecthomas/template"
	"github.com/swaggo/swag"
)

var doc = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{.Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "API Support",
            "url": "http://www.swagger.io/support",
            "email": "support@swagger.io"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/oras/artifacts/v1/{name": {
            "get": {
                "description": "Get references for an image given a digest and artifact type",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Get references for an image",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "image digest",
                        "name": "digest",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "artifact type",
                        "name": "artifactType",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/": {
            "get": {
                "description": "Check if this API version is supported",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Check API support",
                "responses": {
                    "200": {
                        "description": "ok\".",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/_catalog": {
            "get": {
                "description": "List all image repositories",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "List image repositories",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.RepositoryList"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/_oci/ext/discover": {
            "get": {
                "description": "List all extensions present on registry",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "List Registry level extensions",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.ExtensionList"
                        }
                    }
                }
            }
        },
        "/v2/{name}/blobs/uploads": {
            "post": {
                "description": "Create a new image blob/layer upload",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Create image blob/layer upload",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "202": {
                        "description": "accepted",
                        "schema": {
                            "type": "string"
                        },
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "/v2/{name}/blobs/uploads/{session_id}"
                            },
                            "Range": {
                                "type": "string",
                                "description": "0-0"
                            }
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/{name}/blobs/uploads/{session_id}": {
            "get": {
                "description": "Get an image's blob/layer upload given a session_id",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Get image blob/layer upload",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "upload session_id",
                        "name": "session_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "no content",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "put": {
                "description": "Update and finish an image's blob/layer upload given a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Update image blob/layer upload",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "upload session_id",
                        "name": "session_id",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "blob/layer digest",
                        "name": "digest",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "201": {
                        "description": "created",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "delete": {
                "description": "Delete an image's blob/layer given a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Delete image blob/layer",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "upload session_id",
                        "name": "session_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "patch": {
                "description": "Resume an image's blob/layer upload given an session_id",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Resume image blob/layer upload",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "upload session_id",
                        "name": "session_id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "202": {
                        "description": "accepted",
                        "schema": {
                            "type": "string"
                        },
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "/v2/{name}/blobs/uploads/{session_id}"
                            },
                            "Range": {
                                "type": "string",
                                "description": "bytes=0-128"
                            }
                        }
                    },
                    "400": {
                        "description": "bad request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "416": {
                        "description": "range not satisfiable",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/{name}/blobs/{digest}": {
            "get": {
                "description": "Get an image's blob/layer given a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                ],
                "summary": "Get image blob/layer",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "blob/layer digest",
                        "name": "digest",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.ImageManifest"
                        }
                    }
                }
            },
            "delete": {
                "description": "Delete an image's blob/layer given a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Delete image blob/layer",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "blob/layer digest",
                        "name": "digest",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "202": {
                        "description": "accepted",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "head": {
                "description": "Check an image's blob/layer given a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Check image blob/layer",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "blob/layer digest",
                        "name": "digest",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.ImageManifest"
                        },
                        "headers": {
                            "constants.DistContentDigestKey": {
                                "type": "object",
                                "description": "OK"
                            }
                        }
                    }
                }
            }
        },
        "/v2/{name}/manifests/{reference}": {
            "get": {
                "description": "Get an image's manifest given a reference or a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/vnd.oci.image.manifest.v1+json"
                ],
                "summary": "Get image manifest",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "image reference or digest",
                        "name": "reference",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.ImageManifest"
                        },
                        "headers": {
                            "constants.DistContentDigestKey": {
                                "type": "object",
                                "description": "OK"
                            }
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "put": {
                "description": "Update an image's manifest given a reference or a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Update image manifest",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "image reference or digest",
                        "name": "reference",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "201": {
                        "description": "created",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "bad request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "delete": {
                "description": "Delete an image's manifest given a reference or a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Delete image manifest",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "image reference or digest",
                        "name": "reference",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            },
            "head": {
                "description": "Check an image's manifest given a reference or a digest",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "Check image manifest",
                "parameters": [
                    {
                        "type": "string",
                        "description": "repository name",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "image reference or digest",
                        "name": "reference",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {
                            "type": "string"
                        },
                        "headers": {
                            "cosntants.DistContentDigestKey": {
                                "type": "object",
                                "description": "OK"
                            }
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "internal server error\".",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/v2/{name}/tags/list": {
            "get": {
                "description": "List all image tags in a repository",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "summary": "List image tags",
                "parameters": [
                    {
                        "type": "string",
                        "description": "test",
                        "name": "name",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "integer",
                        "description": "limit entries for pagination",
                        "name": "n",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "last tag value for pagination",
                        "name": "last",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/api.ImageTags"
                        }
                    },
                    "400": {
                        "description": "bad request\".",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "not found",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "api.ExtensionList": {
            "type": "object"
        },
        "api.ImageManifest": {
            "type": "object"
        },
        "api.ImageTags": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "tags": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        },
        "api.RepositoryList": {
            "type": "object",
            "properties": {
                "repositories": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            }
        }
    }
}`

type swaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = swaggerInfo{
	Version:     "v0.1.0-dev",
	Host:        "",
	BasePath:    "",
	Schemes:     []string{},
	Title:       "Open Container Initiative Distribution Specification",
	Description: "APIs for Open Container Initiative Distribution Specification",
}

type s struct{}

func New() *s {
	return &s{}
}

func (s *s) ReadDoc() string {
	sInfo := SwaggerInfo
	sInfo.Description = strings.Replace(sInfo.Description, "\n", "\\n", -1)

	t, err := template.New("swagger_info").Funcs(template.FuncMap{
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
	}).Parse(doc)
	if err != nil {
		return doc
	}

	var tpl bytes.Buffer
	if err := t.Execute(&tpl, sInfo); err != nil {
		return doc
	}

	return tpl.String()
}

func init() {
	swag.Register(swag.Name, &s{})
}
