package storage

import (
	"testing"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestGetDynamoParamsWithTableNamePrefix(t *testing.T) {
	t.Parallel()

	storageConfig := &config.StorageConfig{
		CacheDriver: map[string]any{
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": "Zot",
		},
	}

	params, err := getDynamoParams(storageConfig)
	if err != nil {
		t.Fatalf("getDynamoParams() error = %v", err)
	}

	if params.TableName != "ZotBlobTable" {
		t.Fatalf("params.TableName = %q, want %q", params.TableName, "ZotBlobTable")
	}
}

func TestGetDynamoParamsPrefersExplicitCacheTableName(t *testing.T) {
	t.Parallel()

	storageConfig := &config.StorageConfig{
		CacheDriver: map[string]any{
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": "Zot",
			"cachetablename":  "CustomBlobTable",
		},
	}

	params, err := getDynamoParams(storageConfig)
	if err != nil {
		t.Fatalf("getDynamoParams() error = %v", err)
	}

	if params.TableName != "CustomBlobTable" {
		t.Fatalf("params.TableName = %q, want %q", params.TableName, "CustomBlobTable")
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

			storageConfig := &config.StorageConfig{
				CacheDriver: map[string]any{
					"endpoint":        "http://localhost:4566",
					"region":          "us-east-2",
					"tablenamePrefix": prefix,
				},
			}

			_, err := getDynamoParams(storageConfig)
			if err == nil {
				t.Fatal("getDynamoParams() error = nil, want error")
			}
		})
	}
}
