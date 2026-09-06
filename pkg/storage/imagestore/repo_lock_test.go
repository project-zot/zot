package imagestore_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	testImage "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// slowDriver is the local driver with writes to one repository stalled, standing
// in for the round-trip latency a remote driver has on every call.
type slowDriver struct {
	storageTypes.Driver

	slowRepo string
	delay    time.Duration
}

func (d *slowDriver) WriteFile(filepath string, content []byte) (int, error) {
	if strings.Contains(filepath, d.slowRepo) {
		time.Sleep(d.delay)
	}

	return d.Driver.WriteFile(filepath, content)
}

// finishes reports whether fn returns before the deadline.
func finishes(fn func()) bool {
	done := make(chan struct{})

	go func() {
		fn()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// A write to one repository must not stall reads of another. The store held a
// single RWMutex: PutImageManifest took it exclusively across every storage
// round-trip, so GetImageManifest on an unrelated repository queued behind it.
func TestWriteToOneRepoDoesNotBlockReadsOfAnother(t *testing.T) {
	const (
		slowRepo = "slow-repo"
		fastRepo = "fast-repo"
		delay    = 2 * time.Second
	)

	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()
	driver := &slowDriver{Driver: local.New(true), slowRepo: slowRepo, delay: delay}
	store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
		driver, nil, nil, nil)
	ctrl := storage.StoreController{DefaultStore: store}
	ctx := context.Background()

	if err := testImage.WriteImageToFileSystem(testImage.CreateDefaultImage(), fastRepo, "v1", ctrl); err != nil {
		t.Fatalf("seeding %s: %v", fastRepo, err)
	}

	slowImage := testImage.CreateRandomImage()

	var wg sync.WaitGroup

	wg.Add(1)

	started := make(chan struct{})

	go func() {
		defer wg.Done()
		close(started)
		// Stalls inside the driver for `delay`; the result is irrelevant, the hold is not.
		_, _, _ = store.PutImageManifest(ctx, slowRepo, "v1",
			slowImage.Manifest.MediaType, slowImage.ManifestDescriptor.Data, nil)
	}()

	<-started
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	body, _, _, err := store.GetImageManifest(fastRepo, "v1")
	blocked := time.Since(start)

	wg.Wait()

	if err != nil || len(body) == 0 {
		t.Fatalf("reading %s: %v", fastRepo, err)
	}

	if blocked > delay/4 {
		t.Fatalf("read of %s blocked %v behind a write to %s", fastRepo, blocked, slowRepo)
	}
}

// A GC pass over one repository must not stall the others when dedupe is off,
// and must still protect the repository it is collecting.
func TestGCLockIsRepoScopedWithoutDedupe(t *testing.T) {
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()
	store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
		local.New(true), nil, nil, nil)

	var gcLatency time.Time

	store.GCLock("repo-a", &gcLatency)
	defer store.GCUnlock("repo-a", &gcLatency)

	if !finishes(func() {
		var t2 time.Time

		store.RLockRepo("repo-b", &t2)
		store.RUnlockRepo("repo-b", &t2)
	}) {
		t.Fatal("read of repo-b blocked behind GC of repo-a")
	}

	if finishes(func() {
		var t2 time.Time

		store.LockRepo("repo-a", &t2)
		store.UnlockRepo("repo-a", &t2)
	}) {
		t.Fatal("write to repo-a proceeded during its own GC pass")
	}
}

// Remote storage creates a cache even with dedupe off; the cache alone must not
// widen the GC lock back to the whole store.
func TestGCLockIsRepoScopedWithCacheButDedupeOff(t *testing.T) {
	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	boltCache, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
		RootDir: rootDir, Name: "cache", UseRelPaths: true,
	}, log)
	if err != nil || boltCache == nil {
		t.Skipf("boltdb cache unavailable: %v", err)
	}

	var c storageTypes.Cache = boltCache

	store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
		local.New(true), c, nil, nil)

	var gcLatency time.Time

	store.GCLock("repo-a", &gcLatency)
	defer store.GCUnlock("repo-a", &gcLatency)

	if !finishes(func() {
		var t2 time.Time

		store.RLockRepo("repo-b", &t2)
		store.RUnlockRepo("repo-b", &t2)
	}) {
		t.Fatal("repo-b blocked behind GC of repo-a with dedupe off")
	}
}

// With dedupe on, blobs are shared across repositories and a GC pass must keep
// holding the whole store.
func TestGCLockStaysStoreWideWithDedupe(t *testing.T) {
	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	boltCache, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
		RootDir: rootDir, Name: "cache", UseRelPaths: true,
	}, log)
	if err != nil || boltCache == nil {
		t.Skipf("boltdb cache unavailable: %v", err)
	}

	var c storageTypes.Cache = boltCache

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		local.New(true), c, nil, nil)

	var gcLatency time.Time

	store.GCLock("repo-a", &gcLatency)
	defer store.GCUnlock("repo-a", &gcLatency)

	if finishes(func() {
		var t2 time.Time

		store.RLockRepo("repo-b", &t2)
		store.RUnlockRepo("repo-b", &t2)
	}) {
		t.Fatal("repo-b proceeded during a dedupe-enabled GC pass")
	}
}

// With dedupe active, the same blob uploaded to many repositories at once
// links every copy through the shared dedupe cache, so those writes are
// cross-repository and must still serialise; each copy has to land.
func TestDedupedConcurrentUploadsOfOneBlobAllLand(t *testing.T) {
	const repos = 12

	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	boltCache, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
		RootDir: rootDir, Name: "cache", UseRelPaths: true,
	}, log)
	if err != nil || boltCache == nil {
		t.Skipf("boltdb cache unavailable: %v", err)
	}

	var c storageTypes.Cache = boltCache

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		local.New(true), c, nil, nil)

	content := []byte(strings.Repeat("shared-layer-", 4096))
	digest := godigest.FromBytes(content)

	var wg sync.WaitGroup

	errs := make([]error, repos)

	for i := range repos {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			repo := fmt.Sprintf("repo-%d", i)
			if err := store.InitRepo(context.Background(), repo); err != nil {
				errs[i] = err

				return
			}

			_, _, errs[i] = store.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("upload to repo-%d failed: %v", i, err)
		}
	}

	for i := range repos {
		ok, _, err := store.CheckBlob(context.Background(), fmt.Sprintf("repo-%d", i), digest)
		if err != nil || !ok {
			t.Fatalf("blob missing from repo-%d after concurrent deduped uploads: ok=%v err=%v", i, ok, err)
		}
	}
}
