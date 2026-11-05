package storage

import "testing"

func TestRemoteStorageTargetKeyIncludesAzureServiceURL(t *testing.T) {
	first := map[string]any{
		"name":          "azure",
		"accountname":   "account",
		"container":     "container",
		"rootdirectory": "/zot",
		"serviceurl":    "https://one.example.test",
	}
	second := map[string]any{
		"name":          "azure",
		"accountname":   "account",
		"container":     "container",
		"rootdirectory": "/zot",
		"serviceurl":    "https://two.example.test",
	}

	firstKey, err := remoteStorageTargetKey(first)
	if err != nil {
		t.Fatal(err)
	}

	secondKey, err := remoteStorageTargetKey(second)
	if err != nil {
		t.Fatal(err)
	}

	if firstKey == secondKey {
		t.Fatalf("remote storage target key ignored Azure serviceurl: %q", firstKey)
	}
}
