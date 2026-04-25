package meta

import (
	"testing"

	"zotregistry.dev/zot/v2/pkg/log"
)

func TestGetDynamoParamsWithTableNamePrefix(t *testing.T) {
	t.Parallel()

	params := getDynamoParams(map[string]any{
		"endpoint":        "http://localhost:4566",
		"region":          "us-east-2",
		"tablenamePrefix": "Zot",
	}, log.NewTestLogger())

	expectedTables := map[string]string{
		"RepoMetaTablename":      "ZotRepoMetadataTable",
		"RepoBlobsInfoTablename": "ZotRepoBlobsInfoTable",
		"ImageMetaTablename":     "ZotImageMetaTable",
		"UserDataTablename":      "ZotUserDataTable",
		"APIKeyTablename":        "ZotApiKeyDataTable",
		"VersionTablename":       "ZotVersionTable",
	}

	actualTables := map[string]string{
		"RepoMetaTablename":      params.RepoMetaTablename,
		"RepoBlobsInfoTablename": params.RepoBlobsInfoTablename,
		"ImageMetaTablename":     params.ImageMetaTablename,
		"UserDataTablename":      params.UserDataTablename,
		"APIKeyTablename":        params.APIKeyTablename,
		"VersionTablename":       params.VersionTablename,
	}

	for table, expected := range expectedTables {
		if actualTables[table] != expected {
			t.Fatalf("%s = %q, want %q", table, actualTables[table], expected)
		}
	}
}

func TestGetDynamoParamsPrefersExplicitTableNames(t *testing.T) {
	t.Parallel()

	params := getDynamoParams(map[string]any{
		"endpoint":           "http://localhost:4566",
		"region":             "us-east-2",
		"tablenamePrefix":    "Zot",
		"imagemetatablename": "CustomImageMetaTable",
	}, log.NewTestLogger())

	if params.ImageMetaTablename != "CustomImageMetaTable" {
		t.Fatalf("ImageMetaTablename = %q, want %q", params.ImageMetaTablename, "CustomImageMetaTable")
	}

	if params.RepoMetaTablename != "ZotRepoMetadataTable" {
		t.Fatalf("RepoMetaTablename = %q, want %q", params.RepoMetaTablename, "ZotRepoMetadataTable")
	}
}

func TestGetDynamoParamsRejectsInvalidTableNamePrefix(t *testing.T) {
	t.Parallel()

	tests := map[string]any{
		"empty":     "",
		"nonString": false,
	}

	for name, prefix := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			requirePanic(t, func() {
				getDynamoParams(map[string]any{
					"endpoint":        "http://localhost:4566",
					"region":          "us-east-2",
					"tablenamePrefix": prefix,
				}, log.NewTestLogger())
			})
		})
	}
}

func requirePanic(t *testing.T, fn func()) {
	t.Helper()

	defer func() {
		if recover() == nil {
			t.Fatal("function did not panic")
		}
	}()

	fn()
}
