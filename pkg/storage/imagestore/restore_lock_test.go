package imagestore_test

import (
	"bytes"
	"context"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	testImage "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

type restoreLockDriver struct {
	storageTypes.Driver
}

func (driver *restoreLockDriver) Name() string {
	return storageConstants.S3StorageDriverName
}

func newRestoreLockTestStore(t *testing.T) (*imagestore.ImageStore, storageTypes.Cache) {
	t.Helper()

	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	blobCache, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
		RootDir: rootDir, Name: "cache", UseRelPaths: false,
	}, log)
	if err != nil || blobCache == nil {
		t.Fatalf("create blob cache: %v", err)
	}

	metrics := monitoring.NewNopMetricServer()
	store, ok := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
		&restoreLockDriver{Driver: local.New(true)}, blobCache, nil, nil).(*imagestore.ImageStore)
	if !ok {
		t.Fatal("create image store")
	}

	store.RunDedupeBlobs(time.Hour, scheduler.NewScheduler(config.New(), metrics, log))

	return store, blobCache
}

func TestDeleteBlobWaitsForOtherRepoDuringRestore(t *testing.T) {
	store, blobCache := newRestoreLockTestStore(t)
	content := bytes.Repeat([]byte("x"), 4096)
	digest := godigest.FromBytes(content)

	for _, repo := range []string{"repo-a", "repo-b"} {
		if err := store.InitRepo(context.Background(), repo); err != nil {
			t.Fatal(err)
		}

		blobPath := store.BlobPath(repo, digest)
		if err := os.MkdirAll(path.Dir(blobPath), 0o755); err != nil {
			t.Fatal(err)
		}

		var data []byte
		if repo == "repo-a" {
			data = content
		}

		if err := os.WriteFile(blobPath, data, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := blobCache.PutBlob(digest, blobPath); err != nil {
			t.Fatal(err)
		}
	}

	var readLatency time.Time

	store.RLockRepo("repo-b", &readLatency)
	unlocked := false
	defer func() {
		if !unlocked {
			store.RUnlockRepo("repo-b", &readLatency)
		}
	}()

	done := make(chan error, 1)
	started := make(chan struct{})

	go func() {
		close(started)
		done <- store.DeleteBlob("repo-a", digest)
	}()

	<-started

	select {
	case err := <-done:
		t.Fatalf("delete crossed repo-b's read lock during restore: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	info, err := os.Stat(store.BlobPath("repo-b", digest))
	if err != nil || info.Size() != 0 {
		t.Fatalf("placeholder changed while read-locked: info=%v err=%v", info, err)
	}

	store.RUnlockRepo("repo-b", &readLatency)
	unlocked = true

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delete did not finish after releasing repo-b")
	}

	actual, err := os.ReadFile(store.BlobPath("repo-b", digest))
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatalf("placeholder content was not preserved: bytes=%d err=%v", len(actual), err)
	}
}

func TestBlobWriteUnlockSurvivesRestoreCompletion(t *testing.T) {
	for _, lock := range []struct {
		name    string
		acquire func(*imagestore.ImageStore, string, *time.Time) func()
	}{
		{name: "blob-write", acquire: (*imagestore.ImageStore).LockBlobWrite},
	} {
		t.Run(lock.name, func(t *testing.T) {
			store, _ := newRestoreLockTestStore(t)

			var lockLatency time.Time

			unlock := lock.acquire(store, "repo-a", &lockLatency)
			marker := path.Join(store.RootDir(), storageConstants.DedupeRestoreCompleteMarker)
			if err := os.WriteFile(marker, []byte(storageConstants.DedupeRestoreMarkerComplete), 0o600); err != nil {
				unlock()
				t.Fatal(err)
			}

			store.RunDedupeBlobs(time.Hour, nil)
			unlock()

			if !finishes(func() {
				var storeLatency time.Time

				store.Lock(&storeLatency)
				store.Unlock(&storeLatency)
			}) {
				t.Fatal("store remained locked after restoration completed")
			}

			unlock = lock.acquire(store, "repo-a", &lockLatency)
			defer unlock()

			if !finishes(func() {
				var readLatency time.Time

				store.RLockRepo("repo-b", &readLatency)
				store.RUnlockRepo("repo-b", &readLatency)
			}) {
				t.Fatal("repo-b blocked after restoration completed with dedupe disabled")
			}
		})
	}
}

func TestGCLockStaysStoreWideDuringRestore(t *testing.T) {
	store, _ := newRestoreLockTestStore(t)

	var readLatency time.Time

	store.RLockRepo("repo-b", &readLatency)
	done := make(chan struct{})
	started := make(chan struct{})

	go func() {
		close(started)
		_ = store.WithRepoCleanupLock("repo-a", func() error { return nil })
		close(done)
	}()

	<-started

	select {
	case <-done:
		store.RUnlockRepo("repo-b", &readLatency)
		t.Fatal("GC crossed repo-b's read lock during restore")
	case <-time.After(100 * time.Millisecond):
	}

	store.RUnlockRepo("repo-b", &readLatency)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GC did not finish after releasing repo-b")
	}
}

func TestCleanupLockSurvivesRestoreCompletion(t *testing.T) {
	store, _ := newRestoreLockTestStore(t)
	_ = store.WithRepoCleanupLock("repo-a", func() error {
		marker := path.Join(store.RootDir(), storageConstants.DedupeRestoreCompleteMarker)
		if err := os.WriteFile(marker, []byte(storageConstants.DedupeRestoreMarkerComplete), 0o600); err != nil {
			t.Fatal(err)
		}

		store.RunDedupeBlobs(time.Hour, nil)

		return nil
	})

	if !finishes(func() {
		_ = store.WithBlobstoreLock(func() error { return nil })
	}) {
		t.Fatal("store remained locked after restoration completed")
	}

	_ = store.WithRepoCleanupLock("repo-a", func() error {
		if !finishes(func() {
			_ = store.WithRepoReadLock("repo-b", func() error { return nil })
		}) {
			t.Fatal("repo-b blocked after restoration completed with dedupe disabled")
		}

		return nil
	})
}

func TestManifestRepairWaitsForOtherRepoWithDedupe(t *testing.T) {
	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	blobCache, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
		RootDir: rootDir, Name: "cache", UseRelPaths: false,
	}, log)
	if err != nil || blobCache == nil {
		t.Fatalf("create blob cache: %v", err)
	}

	store, ok := imagestore.NewImageStore(rootDir, "", true, false, log, monitoring.NewNopMetricServer(), nil,
		&remoteNamedDriver{Driver: local.New(true)}, blobCache, nil, nil).(*imagestore.ImageStore)
	if !ok {
		t.Fatal("create image store")
	}

	image := testImage.CreateDefaultImage()

	ctx := context.Background()
	for _, repo := range []string{"repo-a", "repo-b"} {
		if err := store.InitRepo(ctx, repo); err != nil {
			t.Fatal(err)
		}

		for _, blob := range []struct {
			digest  godigest.Digest
			content []byte
		}{
			{digest: image.Manifest.Config.Digest, content: image.ConfigDescriptor.Data},
		} {
			if _, _, err := store.FullBlobUpload(ctx, repo, bytes.NewReader(blob.content), blob.digest); err != nil {
				t.Fatal(err)
			}
		}

		for position, layer := range image.Manifest.Layers {
			if _, _, err := store.FullBlobUpload(ctx, repo, bytes.NewReader(image.Layers[position]), layer.Digest); err != nil {
				t.Fatal(err)
			}
		}

		if _, _, err := store.PutImageManifest(ctx, repo, "v1", image.ManifestDescriptor.MediaType,
			image.ManifestDescriptor.Data, nil); err != nil {
			t.Fatal(err)
		}
	}

	digest := image.ManifestDescriptor.Digest
	origin := store.BlobPath("repo-a", digest)
	placeholder := store.BlobPath("repo-b", digest)
	if err := store.RunDedupeForDigest(ctx, digest, true, []string{origin, placeholder}); err != nil {
		t.Fatal(err)
	}

	corrupt := bytes.Repeat([]byte("x"), len(image.ManifestDescriptor.Data))
	if err := os.WriteFile(origin, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	var readLatency time.Time

	store.RLockRepo("repo-b", &readLatency)
	unlocked := false
	defer func() {
		if !unlocked {
			store.RUnlockRepo("repo-b", &readLatency)
		}
	}()

	done := make(chan error, 1)

	go func() {
		_, _, err := store.PutImageManifest(ctx, "repo-a", "v1", image.ManifestDescriptor.MediaType,
			image.ManifestDescriptor.Data, nil)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("manifest repair crossed repo-b's read lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	actual, err := os.ReadFile(origin)
	if err != nil || !bytes.Equal(actual, corrupt) {
		t.Fatalf("shared manifest changed while read-locked: err=%v", err)
	}

	store.RUnlockRepo("repo-b", &readLatency)
	unlocked = true

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("manifest repair did not finish after releasing repo-b")
	}

	actual, err = store.GetBlobContent("repo-b", digest)
	if err != nil || !bytes.Equal(actual, image.ManifestDescriptor.Data) {
		t.Fatalf("shared manifest was not repaired: err=%v", err)
	}
}
