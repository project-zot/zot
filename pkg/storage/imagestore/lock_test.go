package imagestore_test

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// These tests target the blobstore-lock-before-repo-lock ordering added to replace
// the single global ImageStore lock (see the locking design doc referenced from
// PR #3927). A prior per-repo-locking attempt (PR #2968) was abandoned after
// hitting deadlocks in real cluster testing; these tests reproduce the shapes of
// concurrent access that would trigger an AB-BA deadlock if the ordering
// invariant were violated, so they must always be run with -race and rely on
// withDeadline to fail fast (with a full goroutine dump) instead of hanging CI.

// newDedupeStoreForLockTests builds a filesystem-backed, dedupe-enabled image store
// with a real BoltDB cache (not a mock), so DedupeBlob/CheckBlob exercise their
// actual global-blobstore linking logic under concurrent access.
func newDedupeStoreForLockTests(t *testing.T) storageTypes.ImageStore {
	t.Helper()

	rootDir := t.TempDir()
	cacheDir := t.TempDir()
	log := zlog.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)
	t.Cleanup(metrics.Stop)

	cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     cacheDir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)
	if err != nil {
		t.Fatalf("create cache driver: %v", err)
	}

	storeDriver := local.New(true)

	return imagestore.NewImageStore(rootDir, cacheDir, true, true, log, metrics, nil,
		storeDriver, cacheDriver, nil, nil)
}

// withDeadline runs work in a goroutine and fails the test - dumping every
// goroutine's stack - if it hasn't finished within timeout. A lock-ordering
// deadlock would otherwise just hang the test run until CI's own timeout kills
// it with far less diagnostic information.
func withDeadline(t *testing.T, timeout time.Duration, work func()) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		defer close(done)
		work()
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("workload did not complete within %s, possible deadlock:\n%s", timeout, buf[:n])
	}
}

// TestLockOrderFuzz throws many goroutines at a small, fixed pool of repos and
// digests, mixing FullBlobUpload (dedupe write path: blobstore+repo lock),
// CheckBlob (dedupe read path: blobstore-read+repo lock) and DeleteBlob
// (blobstore+repo lock) so most calls need both lock domains at once. Errors
// from individual calls are expected under this much concurrency (e.g. a
// delete racing an upload of the same digest) and are not asserted on; what
// this test actually checks is the absence of a deadlock (via withDeadline)
// and the absence of data races (via -race).
func TestLockOrderFuzz(t *testing.T) {
	t.Parallel()

	imgStore := newDedupeStoreForLockTests(t)

	const (
		numGoroutines = 40
		numIterations = 25
	)

	repos := []string{"repo0", "repo1", "repo2", "repo3", "repo4"}

	contents := [][]byte{[]byte("blob-fuzz-a"), []byte("blob-fuzz-b"), []byte("blob-fuzz-c")}

	digests := make([]godigest.Digest, len(contents))
	for i, content := range contents {
		digests[i] = godigest.FromBytes(content)
	}

	withDeadline(t, 60*time.Second, func() {
		var wg sync.WaitGroup

		for goroutineIdx := range numGoroutines {
			wg.Add(1)

			go func(seed int) {
				defer wg.Done()

				for i := range numIterations {
					repo := repos[(seed+i)%len(repos)]
					idx := (seed*7 + i) % len(contents)
					digest := digests[idx]
					content := contents[idx]

					switch (seed + i) % 3 {
					case 0:
						_, _, _ = imgStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
					case 1:
						_, _, _ = imgStore.CheckBlob(context.Background(), repo, digest)
					case 2:
						_ = imgStore.DeleteBlob(repo, digest)
					}
				}
			}(goroutineIdx)
		}

		wg.Wait()
	})
}

// TestLockOrderReversedRolesDedupe is the literal scenario the two-tier design
// exists to make safe: one goroutine pushes digest A to repo, then digest B to
// repo B; a second goroutine does the same two pushes in the opposite order,
// concurrently and repeatedly. Under the old design (or the alphabetical-sort
// ordering tried on the abandoned `blobstore` branch), two arbitrary repo locks
// held in opposite orders by two goroutines is a textbook AB-BA deadlock. Here
// every call that needs both locks always takes blobstore-then-repo (never
// repo-then-repo), so no ordering conflict is possible regardless of which
// repo/digest pairing either goroutine starts with.
func TestLockOrderReversedRolesDedupe(t *testing.T) {
	t.Parallel()

	imgStore := newDedupeStoreForLockTests(t)

	contentA := []byte("blob-reversed-a")
	contentB := []byte("blob-reversed-b")
	digestA := godigest.FromBytes(contentA)
	digestB := godigest.FromBytes(contentB)

	const iterations = 200

	withDeadline(t, 60*time.Second, func() {
		var wg sync.WaitGroup

		wg.Add(2)

		go func() {
			defer wg.Done()

			for range iterations {
				_, _, _ = imgStore.FullBlobUpload(context.Background(), "repoA", bytes.NewReader(contentA), digestA)
				_, _, _ = imgStore.FullBlobUpload(context.Background(), "repoB", bytes.NewReader(contentB), digestB)
			}
		}()

		go func() {
			defer wg.Done()

			for range iterations {
				_, _, _ = imgStore.FullBlobUpload(context.Background(), "repoB", bytes.NewReader(contentB), digestB)
				_, _, _ = imgStore.FullBlobUpload(context.Background(), "repoA", bytes.NewReader(contentA), digestA)
			}
		}()

		wg.Wait()
	})
}

// TestLockOrderDedupeRebuildStress emulates the real topology behind #2968's
// production deadlock report: many repos sharing a small set of digests (base
// image layers), with a dedupe-rebuild walk (RunDedupeBlobs, which drives
// dedupeBlobs/restoreDedupedBlobs per-digest) running concurrently against
// ongoing push/check/delete traffic across those same repos and digests.
func TestLockOrderDedupeRebuildStress(t *testing.T) {
	t.Parallel()

	imgStore := newDedupeStoreForLockTests(t)

	const (
		numRepos    = 50
		numDigests  = 5
		numWorkers  = 10
		numRebuilds = 5
	)

	contents := make([][]byte, numDigests)
	digests := make([]godigest.Digest, numDigests)

	for i := range contents {
		contents[i] = fmt.Appendf(nil, "blob-stress-%d", i)
		digests[i] = godigest.FromBytes(contents[i])
	}

	repos := make([]string, numRepos)
	for i := range repos {
		repos[i] = fmt.Sprintf("stress-repo-%d", i)
	}

	// Seed every repo with every digest up front so the rebuild walk has real
	// cross-repo duplicate sets to process, not just single-copy blobs.
	for _, repo := range repos {
		for i, digest := range digests {
			reader := bytes.NewReader(contents[i])

			if _, _, err := imgStore.FullBlobUpload(context.Background(), repo, reader, digest); err != nil {
				t.Fatalf("seed upload: %v", err)
			}
		}
	}

	log := zlog.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)
	t.Cleanup(metrics.Stop)

	taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
	taskScheduler.RateLimit = 10 * time.Millisecond
	taskScheduler.RunScheduler()
	t.Cleanup(taskScheduler.Shutdown)

	var stop atomic.Bool

	withDeadline(t, 90*time.Second, func() {
		var wg sync.WaitGroup

		for workerIdx := range numWorkers {
			wg.Add(1)

			go func(seed int) {
				defer wg.Done()

				i := 0
				for !stop.Load() {
					repo := repos[(seed+i)%numRepos]
					idx := (seed + i) % numDigests
					digest := digests[idx]
					content := contents[idx]

					switch i % 3 {
					case 0:
						_, _, _ = imgStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
					case 1:
						_, _, _ = imgStore.CheckBlob(context.Background(), repo, digest)
					case 2:
						_ = imgStore.DeleteBlob(repo, digest)
					}

					i++
				}
			}(workerIdx)
		}

		// Drive several rebuild passes, mirroring what RunDedupeBlobs's scheduled
		// generator does over time, while traffic keeps running concurrently.
		for range numRebuilds {
			imgStore.RunDedupeBlobs(0, taskScheduler)
			time.Sleep(50 * time.Millisecond)
		}

		stop.Store(true)
		wg.Wait()
	})
}
