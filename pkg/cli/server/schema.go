package server

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spf13/cobra"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func newSchemaCmd() *cobra.Command {
	schemaCmd := &cobra.Command{
		Use:   "schema",
		Short: "`schema` dumps JSON Schema for zot config",
		Long:  "`schema` dumps JSON Schema for zot config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			schemaDoc := buildConfigSchemaDocument()

			schemaJSON, err := json.MarshalIndent(schemaDoc, "", "  ")
			if err != nil {
				return err
			}

			compiler := jsonschema.NewCompiler()
			compiler.DefaultDraft(jsonschema.Draft7)

			if err := compiler.AddResource("zot://config-schema.json", schemaDoc); err != nil {
				return err
			}

			if _, err := compiler.Compile("zot://config-schema.json"); err != nil {
				return fmt.Errorf("generated schema is invalid: %w", err)
			}

			if _, err := cmd.OutOrStdout().Write(schemaJSON); err != nil {
				return err
			}

			_, err = cmd.OutOrStdout().Write([]byte("\n"))

			return err
		},
	}

	return schemaCmd
}

func buildConfigSchemaDocument() map[string]any {
	gen := newSchemaGenerator()

	configSchema := gen.schemaForType(reflect.TypeFor[config.Config]())

	doc := map[string]any{
		"$schema":     "http://json-schema.org/draft-07/schema#",
		"title":       "zot config schema",
		"$ref":        configSchema["$ref"],
		"definitions": gen.defs,
	}

	return doc
}

type schemaGenerator struct {
	defs map[string]any
}

func newSchemaGenerator() *schemaGenerator {
	return &schemaGenerator{defs: map[string]any{}}
}

func (g *schemaGenerator) schemaForType(reflectType reflect.Type) map[string]any {
	if reflectType.Kind() == reflect.Pointer {
		return nullableSchema(g.schemaForType(derefPointerType(reflectType)))
	}

	if reflectType.PkgPath() == "time" && reflectType.Name() == "Duration" {
		return map[string]any{"type": "string"}
	}

	switch reflectType.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Slice, reflect.Array:
		return map[string]any{
			"type":  "array",
			"items": g.schemaForType(reflectType.Elem()),
		}
	case reflect.Map:
		return map[string]any{
			"type":                 "object",
			"additionalProperties": g.schemaForType(reflectType.Elem()),
		}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Struct:
		return g.schemaForStruct(reflectType)
	default:
		return map[string]any{}
	}
}

func (g *schemaGenerator) schemaForStruct(reflectType reflect.Type) map[string]any {
	defName := schemaDefName(reflectType)
	if defName != "." {
		if _, ok := g.defs[defName]; ok {
			return map[string]any{"$ref": "#/definitions/" + schemaDefRefToken(defName)}
		}

		g.defs[defName] = map[string]any{}
	}

	properties := map[string]any{}

	for i := range reflectType.NumField() {
		field := reflectType.Field(i)

		if !field.IsExported() {
			continue
		}

		fieldName, squash, skip := schemaFieldName(field)
		if skip {
			continue
		}

		fieldSchema := g.schemaForType(field.Type)

		if squash {
			if ref, ok := fieldSchema["$ref"].(string); ok {
				defKey := schemaDefFromRefToken(strings.TrimPrefix(ref, "#/definitions/"))
				if def, ok := g.defs[defKey].(map[string]any); ok {
					mergeProperties(properties, def)
				}
			} else {
				mergeProperties(properties, fieldSchema)
			}

			continue
		}

		properties[fieldName] = fieldSchema
		for _, alias := range schemaFieldAliases(fieldName) {
			if _, exists := properties[alias]; !exists {
				properties[alias] = fieldSchema
			}
		}
	}

	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}

	if defName == "." {
		return schema
	}

	g.defs[defName] = schema

	return map[string]any{"$ref": "#/definitions/" + schemaDefRefToken(defName)}
}

func schemaFieldName(field reflect.StructField) (string, bool, bool) {
	jsonName, _, jsonSkip := parseStructTag(field.Tag.Get("json"))
	if jsonSkip {
		return "", false, true
	}

	mapstructureName, mapstructureFlags, mapstructureSkip := parseStructTag(field.Tag.Get("mapstructure"))
	if mapstructureSkip {
		return "", false, true
	}

	yamlName, yamlFlags, yamlSkip := parseStructTag(field.Tag.Get("yaml"))
	if yamlSkip {
		return "", false, true
	}

	if hasFlag(mapstructureFlags, "squash") || hasFlag(yamlFlags, "inline") {
		return "", true, false
	}

	if jsonName != "" {
		return jsonName, false, false
	}

	if mapstructureName != "" {
		return mapstructureName, false, false
	}

	if yamlName != "" {
		return yamlName, false, false
	}

	if field.Anonymous {
		return "", true, false
	}

	return lowerCamelCase(field.Name), false, false
}

func parseStructTag(tag string) (string, []string, bool) {
	if tag == "" {
		return "", nil, false
	}

	parts := strings.Split(tag, ",")
	flags := []string(nil)
	if parts[0] == "-" {
		return "", nil, true
	}

	if len(parts) > 1 {
		flags = parts[1:]
	}

	return parts[0], flags, false
}

func hasFlag(flags []string, target string) bool {
	return slices.Contains(flags, target)
}

func mergeProperties(dst map[string]any, schema map[string]any) {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}

	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		dst[key] = props[key]
	}
}

func lowerCamelCase(input string) string {
	if input == "" {
		return ""
	}

	upperPrefixLen := 0
	for upperPrefixLen < len(input) && input[upperPrefixLen] >= 'A' && input[upperPrefixLen] <= 'Z' {
		upperPrefixLen++
	}

	if upperPrefixLen == 0 {
		return input
	}

	if upperPrefixLen == len(input) {
		return strings.ToLower(input)
	}

	if upperPrefixLen == 1 {
		return strings.ToLower(input[:1]) + input[1:]
	}

	return strings.ToLower(input[:upperPrefixLen-1]) + input[upperPrefixLen-1:]
}

func schemaFieldAliases(fieldName string) []string {
	aliases := []string{}

	lower := strings.ToLower(fieldName)
	if lower != fieldName {
		aliases = append(aliases, lower)
	}

	collapsed := collapseUppercaseRuns(fieldName)
	if collapsed != fieldName && collapsed != lower {
		aliases = append(aliases, collapsed)
	}

	return aliases
}

func collapseUppercaseRuns(input string) string {
	if input == "" {
		return ""
	}

	builder := strings.Builder{}
	builder.Grow(len(input))

	for i := 0; i < len(input); {
		uppercaseEnd := i
		for uppercaseEnd < len(input) && input[uppercaseEnd] >= 'A' && input[uppercaseEnd] <= 'Z' {
			uppercaseEnd++
		}

		if uppercaseEnd-i >= 2 {
			builder.WriteByte(input[i])
			builder.WriteString(strings.ToLower(input[i+1 : uppercaseEnd]))
			i = uppercaseEnd

			continue
		}

		builder.WriteByte(input[i])
		i++
	}

	return builder.String()
}

func schemaDefName(reflectType reflect.Type) string {
	if reflectType.Name() == "" {
		return "."
	}

	name := reflectType.PkgPath() + "." + reflectType.Name()

	// Keep definition keys safe/collision-free using RFC 6901 escaping.
	// "~" becomes "~0" and "/" becomes "~1".
	replacer := strings.NewReplacer("~", "~0", "/", "~1")

	return replacer.Replace(name)
}

func schemaDefRefToken(defName string) string {
	// $ref uses JSON Pointer tokens, which decode "~1"->"/" and "~0"->"~".
	// Since defName is already RFC 6901-escaped for storage, escape it once more for pointer usage.
	replacer := strings.NewReplacer("~", "~0", "/", "~1")

	return replacer.Replace(defName)
}

func schemaDefFromRefToken(token string) string {
	// Decode one JSON Pointer token level back to the stored definition key.
	replacer := strings.NewReplacer("~1", "/", "~0", "~")

	return replacer.Replace(token)
}

func derefPointerType(reflectType reflect.Type) reflect.Type {
	for reflectType.Kind() == reflect.Pointer {
		reflectType = reflectType.Elem()
	}

	return reflectType
}

func nullableSchema(schema map[string]any) map[string]any {
	if schemaType, ok := schema["type"].(string); ok {
		nullable := mapsClone(schema)
		nullable["type"] = []any{schemaType, "null"}

		return nullable
	}

	return map[string]any{
		"anyOf": []any{
			schema,
			map[string]any{"type": "null"},
		},
	}
}

func mapsClone(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	maps.Copy(dst, src)

	return dst
}
