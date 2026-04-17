package server_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	. "github.com/smartystreets/goconvey/convey"

	cli "zotregistry.dev/zot/v2/pkg/cli/server"
)

func TestSchemaAllowsNullForPointerFields(t *testing.T) {
	Convey("generated schema allows explicit null for pointer-backed config fields", t, func() {
		cmd := cli.NewServerRootCmd()
		buf := bytes.NewBuffer(nil)

		cmd.SetArgs([]string{"schema"})
		cmd.SetOut(buf)

		err := cmd.Execute()
		So(err, ShouldBeNil)

		var schemaDoc map[string]any
		err = json.Unmarshal(buf.Bytes(), &schemaDoc)
		So(err, ShouldBeNil)

		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft7)

		err = compiler.AddResource("zot://config-schema.json", schemaDoc)
		So(err, ShouldBeNil)

		compiledSchema, err := compiler.Compile("zot://config-schema.json")
		So(err, ShouldBeNil)

		configWithNullPointers := map[string]any{
			"http": map[string]any{
				"auth": map[string]any{
					"secureSession": nil,
					"mtls":          nil,
				},
			},
			"storage": map[string]any{
				"retention": map[string]any{
					"policies": []any{
						map[string]any{
							"deleteUntagged": nil,
							"keepTags": []any{
								map[string]any{
									"pulledWithin": nil,
									"pushedWithin": nil,
								},
							},
						},
					},
				},
			},
			"extensions": map[string]any{
				"sync": map[string]any{
					"enable": nil,
					"registries": []any{
						map[string]any{
							"tlsVerify":            nil,
							"retryDelay":           nil,
							"onlySigned":           nil,
							"syncLegacyCosignTags": nil,
						},
					},
				},
			},
			"cluster": nil,
		}

		err = compiledSchema.Validate(configWithNullPointers)
		So(err, ShouldBeNil)

		err = compiledSchema.Validate(map[string]any{
			"storage": map[string]any{
				"rootDirectory": "/tmp/zot",
			},
			"http": map[string]any{
				"address": "127.0.0.1",
				"port":    "8080",
			},
		})
		So(err, ShouldBeNil)
	})
}
