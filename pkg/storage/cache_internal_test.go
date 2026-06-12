package storage

import (
	"errors"
	"testing"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestGetDynamoParamsWithTableNamePrefix(t *testing.T) {
	t.Parallel()

	params, err := getDynamoParams(&config.StorageConfig{
		CacheDriver: map[string]any{
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": "Zot",
		},
	})
	if err != nil {
		t.Fatalf("getDynamoParams() error = %v", err)
	}

	if params.TableName != "ZotBlobTable" {
		t.Fatalf("TableName = %q, want %q", params.TableName, "ZotBlobTable")
	}
}

func TestGetDynamoParamsPrefersExplicitCacheTableName(t *testing.T) {
	t.Parallel()

	params, err := getDynamoParams(&config.StorageConfig{
		CacheDriver: map[string]any{
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": "Zot",
			"cacheTablename":  "CustomBlobTable",
		},
	})
	if err != nil {
		t.Fatalf("getDynamoParams() error = %v", err)
	}

	if params.TableName != "CustomBlobTable" {
		t.Fatalf("TableName = %q, want %q", params.TableName, "CustomBlobTable")
	}
}

func TestGetDynamoParamsRejectsInvalidDynamoTableConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]any{
		"missing explicit table and prefix": {
			"endpoint": "http://localhost:4566",
			"region":   "us-east-2",
		},
		"empty prefix": {
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": "",
		},
		"non string prefix": {
			"endpoint":        "http://localhost:4566",
			"region":          "us-east-2",
			"tablenamePrefix": false,
		},
		"empty explicit table": {
			"endpoint":       "http://localhost:4566",
			"region":         "us-east-2",
			"cacheTablename": "",
		},
		"non string explicit table": {
			"endpoint":       "http://localhost:4566",
			"region":         "us-east-2",
			"cacheTablename": false,
		},
	}

	for name, cacheDriver := range tests {
		name := name
		cacheDriver := cacheDriver

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := getDynamoParams(&config.StorageConfig{CacheDriver: cacheDriver})
			if !errors.Is(err, zerr.ErrBadConfig) {
				t.Fatalf("getDynamoParams() error = %v, want ErrBadConfig", err)
			}
		})
	}
}
