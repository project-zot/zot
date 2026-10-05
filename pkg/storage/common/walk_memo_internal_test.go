package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// concurrentPrefetchStore is ConcurrentReadSafe and records how many GetBlobContent
// calls overlap so Prefetch's semaphore can be checked without wall-clock timing.
type concurrentPrefetchStore struct {
	mocks.MockedImageStore

	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	release     chan struct{}
}

func (s *concurrentPrefetchStore) ConcurrentReadSafe() bool {
	return true
}

func TestPrefetchRespectsParallelismBound(t *testing.T) {
	const (
		parallelism = 2
		descs       = 6
	)

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	store := &concurrentPrefetchStore{release: make(chan struct{})}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		cur := store.inFlight.Add(1)

		for {
			old := store.maxInFlight.Load()
			if cur <= old || store.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}

		<-store.release

		store.inFlight.Add(-1)

		return emptyIndex, nil
	}

	descriptors := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("prefetch-idx-%d", i)),
		})
	}

	memo := NewWalkMemo()
	memo.prefetchParallelism = parallelism
	log := zlog.NewTestLogger()

	var wg sync.WaitGroup

	wg.Go(func() {
		memo.Prefetch(context.Background(), store, "repo", descriptors, log)
	})

	deadline := time.Now().Add(2 * time.Second)
	for store.maxInFlight.Load() < int64(parallelism) {
		if time.Now().After(deadline) {
			close(store.release)
			wg.Wait()
			t.Fatalf("timed out waiting for %d in-flight reads; max=%d", parallelism, store.maxInFlight.Load())
		}

		time.Sleep(time.Millisecond)
	}

	// Hold the gate so a broken (unbounded) Prefetch would push maxInFlight above
	// parallelism, then release.
	time.Sleep(20 * time.Millisecond)

	if got := store.maxInFlight.Load(); got != int64(parallelism) {
		close(store.release)
		wg.Wait()
		t.Fatalf("max in-flight reads = %d, want %d", got, parallelism)
	}

	close(store.release)
	wg.Wait()

	if got := store.maxInFlight.Load(); got != int64(parallelism) {
		t.Fatalf("after Prefetch, max in-flight reads = %d, want %d", got, parallelism)
	}
}

func TestPrefetchDedupesDuplicatesDoesNotStarveUniques(t *testing.T) {
	const (
		parallelism = 2
		dupes       = 8
		uniques     = 4
	)

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var calls atomic.Int64

	store := &concurrentPrefetchStore{release: make(chan struct{})}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		calls.Add(1)

		cur := store.inFlight.Add(1)

		for {
			old := store.maxInFlight.Load()
			if cur <= old || store.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}

		<-store.release

		store.inFlight.Add(-1)

		return emptyIndex, nil
	}

	shared := godigest.FromString("shared-alias")
	descriptors := make([]ispec.Descriptor, 0, dupes+uniques)

	for range dupes {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    shared,
		})
	}

	for i := range uniques {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("unique-idx-%d", i)),
		})
	}

	memo := NewWalkMemo()
	memo.prefetchParallelism = parallelism
	log := zlog.NewTestLogger()

	var wg sync.WaitGroup

	wg.Go(func() {
		memo.Prefetch(context.Background(), store, "repo", descriptors, log)
	})

	// Without per-digest reservation, the duplicate aliases would occupy every
	// semaphore slot and maxInFlight would stay at 1 (singleflight) until the
	// shared read finishes. With reservation, a unique digest can take the
	// second slot and overlap.
	deadline := time.Now().Add(2 * time.Second)
	for store.maxInFlight.Load() < int64(parallelism) {
		if time.Now().After(deadline) {
			close(store.release)
			wg.Wait()
			t.Fatalf("timed out waiting for %d overlapping reads with mixed duplicates; max=%d",
				parallelism, store.maxInFlight.Load())
		}

		time.Sleep(time.Millisecond)
	}

	time.Sleep(20 * time.Millisecond)

	if got := store.maxInFlight.Load(); got != int64(parallelism) {
		close(store.release)
		wg.Wait()
		t.Fatalf("max in-flight reads = %d, want %d", got, parallelism)
	}

	close(store.release)
	wg.Wait()

	wantCalls := int64(1 + uniques) // shared once + each unique
	if got := calls.Load(); got != wantCalls {
		t.Fatalf("GetBlobContent calls = %d, want %d (duplicates must schedule once)", got, wantCalls)
	}
}

func TestPrefetchParallelismOneIsSerial(t *testing.T) {
	const descs = 4

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	store := &concurrentPrefetchStore{}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		cur := store.inFlight.Add(1)

		for {
			old := store.maxInFlight.Load()
			if cur <= old || store.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}

		store.inFlight.Add(-1)

		return emptyIndex, nil
	}

	descriptors := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("serial-idx-%d", i)),
		})
	}

	memo := NewWalkMemo()
	memo.prefetchParallelism = 1
	memo.Prefetch(context.Background(), store, "repo", descriptors, zlog.NewTestLogger())

	if got := store.maxInFlight.Load(); got != 1 {
		t.Fatalf("max in-flight reads = %d, want 1 (serial Prefetch)", got)
	}
}

func TestPrefetchStopsAfterNonMissingError(t *testing.T) {
	const (
		descs       = 20
		parallelism = 2
	)

	var calls atomic.Int64

	store := &concurrentPrefetchStore{}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		n := calls.Add(1)
		if n == 1 {
			return nil, errclass.MarkTransient(errors.New("backend outage"))
		}

		// Slow success so a non-cancelling Prefetch would keep scheduling.
		time.Sleep(5 * time.Millisecond)

		return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
	}

	descriptors := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("abort-idx-%d", i)),
		})
	}

	memo := NewWalkMemo()
	memo.prefetchParallelism = parallelism
	memo.Prefetch(context.Background(), store, "repo", descriptors, zlog.NewTestLogger())

	got := calls.Load()
	// First failure sets stop; at most a small batch already in flight may finish.
	if got >= int64(descs) {
		t.Fatalf("Prefetch issued %d reads for %d descriptors after a Transient; expected early stop", got, descs)
	}

	if got > int64(parallelism*2) {
		t.Fatalf("Prefetch issued %d reads after Transient; want at most ~%d in-flight leftovers", got, parallelism*2)
	}
}

func TestPrefetchStopsOnContextCancel(t *testing.T) {
	const (
		descs       = 20
		parallelism = 2
	)

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var calls atomic.Int64

	store := &concurrentPrefetchStore{release: make(chan struct{})}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		calls.Add(1)

		cur := store.inFlight.Add(1)
		for {
			old := store.maxInFlight.Load()
			if cur <= old || store.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}

		<-store.release
		store.inFlight.Add(-1)

		return emptyIndex, nil
	}

	descriptors := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("cancel-idx-%d", i)),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())

	memo := NewWalkMemo()
	memo.prefetchParallelism = parallelism

	var wg sync.WaitGroup

	wg.Go(func() {
		memo.Prefetch(ctx, store, "repo", descriptors, zlog.NewTestLogger())
	})

	deadline := time.Now().Add(2 * time.Second)
	for store.maxInFlight.Load() < int64(parallelism) {
		if time.Now().After(deadline) {
			cancel()
			close(store.release)
			wg.Wait()
			t.Fatalf("timed out waiting for in-flight Prefetch workers")
		}

		time.Sleep(time.Millisecond)
	}

	cancel()
	// Hold briefly so a non-cancelling Prefetch would keep filling the pool.
	time.Sleep(20 * time.Millisecond)
	close(store.release)
	wg.Wait()

	got := calls.Load()
	if got >= int64(descs) {
		t.Fatalf("Prefetch issued %d reads for %d descriptors after cancel; expected early stop", got, descs)
	}

	if got > int64(parallelism*2) {
		t.Fatalf("Prefetch issued %d reads after cancel; want at most ~%d in-flight leftovers", got, parallelism*2)
	}
}

func TestGetIndexCoalescesConcurrentDuplicateDigests(t *testing.T) {
	const callers = 8

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var calls atomic.Int64

	release := make(chan struct{})
	entered := make(chan struct{})

	store := &concurrentPrefetchStore{}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}

		<-release

		return emptyIndex, nil
	}

	memo := NewWalkMemo()
	digest := godigest.FromString("shared-index")
	log := zlog.NewTestLogger()

	var wg sync.WaitGroup

	errs := make(chan error, callers)

	for range callers {
		wg.Go(func() {
			_, err := memo.GetIndex(store, "repo", digest, log)
			errs <- err
		})
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("timed out waiting for GetBlobContent")
	}

	// Hold the gate so every concurrent GetIndex joins the same singleflight.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("GetIndex: %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("GetBlobContent calls = %d, want 1 (singleflight must coalesce duplicate digests)", got)
	}
}

func TestPrefetchContinuesOnMissing(t *testing.T) {
	const descs = 8

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var (
		calls   atomic.Int64
		missing = godigest.FromString("missing-idx")
	)

	store := &concurrentPrefetchStore{}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		calls.Add(1)

		if digest == missing {
			return nil, errclass.MarkMissing(errors.New("gone"))
		}

		return emptyIndex, nil
	}

	descriptors := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		dgst := godigest.FromString(fmt.Sprintf("ok-idx-%d", i))
		if i == 2 {
			dgst = missing
		}

		descriptors = append(descriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    dgst,
		})
	}

	memo := NewWalkMemo()
	memo.prefetchParallelism = 2
	memo.Prefetch(context.Background(), store, "repo", descriptors, zlog.NewTestLogger())

	if got := calls.Load(); got != int64(descs) {
		t.Fatalf("Prefetch issued %d reads, want %d (Missing must not abort the batch)", got, descs)
	}
}

func TestPrefetchUsesDefaultParallelismWhenUnset(t *testing.T) {
	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var calls atomic.Int64

	store := &concurrentPrefetchStore{}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		calls.Add(1)

		return emptyIndex, nil
	}

	descriptors := []ispec.Descriptor{{
		MediaType: ispec.MediaTypeImageIndex,
		Digest:    godigest.FromString("default-parallelism-idx"),
	}}

	memo := NewWalkMemo()
	memo.prefetchParallelism = 0 // force the default walkReadParallelism branch
	memo.Prefetch(context.Background(), store, "repo", descriptors, zlog.NewTestLogger())

	if got := calls.Load(); got != 1 {
		t.Fatalf("Prefetch issued %d reads, want 1", got)
	}
}

func TestGetReferencedBlobsWithMemoReturnsCanceledAfterPrefetch(t *testing.T) {
	const (
		descs       = 8
		parallelism = 2
	)

	emptyIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	rootManifests := make([]ispec.Descriptor, 0, descs)
	for i := range descs {
		rootManifests = append(rootManifests, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    godigest.FromString(fmt.Sprintf("refblobs-cancel-%d", i)),
		})
	}

	rootIndex, err := json.Marshal(ispec.Index{SchemaVersion: 2, Manifests: rootManifests})
	if err != nil {
		t.Fatalf("marshal root index: %v", err)
	}

	store := &concurrentPrefetchStore{release: make(chan struct{})}
	store.RootDirFn = func() string { return "/tmp" }
	store.GetIndexContentFn = func(repo string) ([]byte, error) {
		return rootIndex, nil
	}
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		cur := store.inFlight.Add(1)
		for {
			old := store.maxInFlight.Load()
			if cur <= old || store.maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}

		<-store.release
		store.inFlight.Add(-1)

		return emptyIndex, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	memo := NewWalkMemo()
	memo.prefetchParallelism = parallelism

	errCh := make(chan error, 1)

	go func() {
		_, err := GetReferencedBlobsWithMemo(ctx, memo, store, "repo", zlog.NewTestLogger())
		errCh <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for store.maxInFlight.Load() < int64(parallelism) {
		if time.Now().After(deadline) {
			cancel()
			close(store.release)
			<-errCh
			t.Fatalf("timed out waiting for Prefetch workers")
		}

		time.Sleep(time.Millisecond)
	}

	cancel()
	close(store.release)

	err = <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetReferencedBlobsWithMemo error = %v, want context.Canceled", err)
	}
}
