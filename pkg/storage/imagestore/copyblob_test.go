package imagestore_test

// copyBlob is CheckBlob's cache-miss-but-cache-hit self-heal path: a repo that has
// never seen a digest locally, but the cache (populated by a push to a different
// repo) can resolve it - CheckBlob links/copies the content in on read. Previously
// entirely untested (0%).

import (
	"bytes"
	"context"
	"testing"

	godigest "github.com/opencontainers/go-digest"
)

func TestCheckBlobSelfHealsViaCopyBlob(t *testing.T) {
	imgStore := newDedupeStoreForLockTests(t)

	content := []byte("copyblob-selfheal-content")
	digest := godigest.FromBytes(content)

	if _, _, err := imgStore.FullBlobUpload(context.Background(), "repoa", bytes.NewReader(content), digest); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	// repob has never seen this digest: its blob path doesn't exist, but the cache
	// (populated by repoa's push) resolves it, so CheckBlob must self-heal by
	// copying/linking the content into repob via copyBlob.
	ok, size, err := imgStore.CheckBlob(context.Background(), "repob", digest)
	if err != nil {
		t.Fatalf("CheckBlob: %v", err)
	}

	if !ok {
		t.Fatal("expected blob to be found via cache self-heal")
	}

	if size != int64(len(content)) {
		t.Fatalf("expected size %d, got %d", len(content), size)
	}

	blobContent, err := imgStore.GetBlobContent("repob", digest)
	if err != nil {
		t.Fatalf("GetBlobContent: %v", err)
	}

	if !bytes.Equal(blobContent, content) {
		t.Fatal("content copied into repob does not match original")
	}
}

func TestCheckBlobSelfHealCopyBlobFailsOnInvalidRepo(t *testing.T) {
	imgStore := newDedupeStoreForLockTests(t)

	content := []byte("copyblob-invalid-repo-content")
	digest := godigest.FromBytes(content)

	if _, _, err := imgStore.FullBlobUpload(context.Background(), "repoa", bytes.NewReader(content), digest); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	// copyBlob's initRepo call must fail fast on an invalid repo name, surfacing as
	// a not-found result rather than a partial/successful self-heal.
	ok, _, err := imgStore.CheckBlob(context.Background(), "!!!invalid!!!", digest)
	if err == nil {
		t.Fatal("expected an error for an invalid repo name")
	}

	if ok {
		t.Fatal("expected blob not found for an invalid repo name")
	}
}
