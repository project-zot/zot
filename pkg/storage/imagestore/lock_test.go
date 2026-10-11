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
	. "github.com/smartystreets/goconvey/convey"

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

// These tests target the blobstore-lock-before-repo-lock ordering: every call
// needing both locks must take blobstore then repo, never repo-then-repo, or
// concurrent access across repos can AB-BA deadlock. Run with -race; rely on
// withDeadline to fail fast instead of hanging CI.

// newDedupeStoreForLockTests uses a real BoltDB cache (not a mock) so
// DedupeBlob/CheckBlob exercise their actual global-blobstore linking logic.
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
// goroutine's stack - if it hasn't finished within timeout, giving a deadlock
// far better diagnostics than letting CI's own timeout kill the run. This is a
// timeout/deadlock guard on the test harness itself, not a behavioral assertion on
// the store, so it stays t.Fatalf rather than a Convey So() even in the Convey-style
// tests below - same rationale as other setup-can't-proceed failures in this package.
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

// TestLockOrderFuzz mixes FullBlobUpload, CheckBlob and DeleteBlob across a small,
// fixed pool of repos and digests so most calls need both lock domains at once.
// Per-call errors are expected under this concurrency and are not asserted on;
// only the absence of a deadlock (withDeadline) and data races (-race) matter.
func TestLockOrderFuzz(t *testing.T) {
	t.Parallel()

	Convey("Concurrent mixed traffic across repos does not deadlock", t, func() {
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
				wg.Go(func() {
					seed := goroutineIdx

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
				})
			}

			wg.Wait()
		})
	})
}

// TestLockOrderReversedRolesDedupe is the textbook AB-BA shape: one goroutine
// pushes repo-a then repo-b, another pushes repo-b then repo-a, concurrently and
// repeatedly. Two arbitrary repo locks taken in opposite orders would deadlock
// under per-repo-only locking; the blobstore-then-repo ordering rules it out
// regardless of which repo/digest pairing either goroutine starts with.
func TestLockOrderReversedRolesDedupe(t *testing.T) {
	t.Parallel()

	Convey("Two goroutines pushing repo-a/repo-b in reversed order do not deadlock", t, func() {
		imgStore := newDedupeStoreForLockTests(t)

		contentA := []byte("blob-reversed-a")
		contentB := []byte("blob-reversed-b")
		digestA := godigest.FromBytes(contentA)
		digestB := godigest.FromBytes(contentB)

		const iterations = 200

		withDeadline(t, 60*time.Second, func() {
			var wg sync.WaitGroup

			wg.Go(func() {
				for range iterations {
					_, _, _ = imgStore.FullBlobUpload(context.Background(), "repo-a", bytes.NewReader(contentA), digestA)
					_, _, _ = imgStore.FullBlobUpload(context.Background(), "repo-b", bytes.NewReader(contentB), digestB)
				}
			})

			wg.Go(func() {
				for range iterations {
					_, _, _ = imgStore.FullBlobUpload(context.Background(), "repo-b", bytes.NewReader(contentB), digestB)
					_, _, _ = imgStore.FullBlobUpload(context.Background(), "repo-a", bytes.NewReader(contentA), digestA)
				}
			})

			wg.Wait()
		})

		// Push errors above are deliberately discarded, but that must not hide every
		// push failing outright - confirm real content actually landed.
		blobContent, err := imgStore.GetBlobContent("repo-a", digestA)
		So(err, ShouldBeNil)
		So(blobContent, ShouldResemble, contentA)

		blobContent, err = imgStore.GetBlobContent("repo-b", digestB)
		So(err, ShouldBeNil)
		So(blobContent, ShouldResemble, contentB)
	})
}

// TestLockOrderDedupeRebuildStress emulates many repos sharing a small set of
// digests (base image layers), with a dedupe-rebuild walk (RunDedupeBlobs)
// running concurrently against ongoing push/check/delete traffic on those same
// repos and digests - the topology most likely to expose a lock-ordering bug.
func TestLockOrderDedupeRebuildStress(t *testing.T) {
	t.Parallel()

	Convey("A dedupe-rebuild walk racing ongoing traffic does not deadlock", t, func() {
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
				wg.Go(func() {
					seed := workerIdx

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
				})
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
	})
}

// TestLockOrderDedupeFastPathRace targets DedupeBlob's fast path (blobstore READ
// lock, for a digest that already has a resolvable copy) racing its slow path
// (blobstore WRITE lock, for a brand-new digest's first writer). For each digest,
// every repo races to push it at once: exactly one goroutine wins the slow path
// while the rest queue behind it or land on the fast path once the blob is
// promoted. A second round then hammers the now-settled digest with concurrent
// pushes and reads, which should mostly take the fast path on both sides.
func TestLockOrderDedupeFastPathRace(t *testing.T) {
	t.Parallel()

	Convey("DedupeBlob's fast and slow paths racing does not deadlock", t, func() {
		imgStore := newDedupeStoreForLockTests(t)

		const (
			numDigests = 20
			numRepos   = 15
		)

		repos := make([]string, numRepos)
		for i := range repos {
			repos[i] = fmt.Sprintf("fastpath-repo-%d", i)
		}

		withDeadline(t, 60*time.Second, func() {
			for d := range numDigests {
				content := fmt.Appendf(nil, "blob-fastpath-%d", d)
				digest := godigest.FromBytes(content)

				var wg sync.WaitGroup

				// Round 1: every repo races to push this brand-new digest at once, forcing
				// the first-writer race onto the slow (write-locked) path.
				for _, repo := range repos {
					wg.Go(func() {
						_, _, _ = imgStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
					})
				}

				wg.Wait()

				// Round 2: the digest is now settled in _blobstore, so these pushes should
				// mostly take the fast (read-locked) path, concurrently with CheckBlob reads
				// racing the same digest across the same repos.
				for _, repo := range repos {
					wg.Go(func() {
						_, _, _ = imgStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
					})

					wg.Go(func() {
						_, _, _ = imgStore.CheckBlob(context.Background(), repo, digest)
					})
				}

				wg.Wait()
			}
		})
	})
}
