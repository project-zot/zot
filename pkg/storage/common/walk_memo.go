package storage

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/singleflight"

	"zotregistry.dev/zot/v2/pkg/compat"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// walkReadParallelism bounds concurrent Prefetch workers (and thus in-flight
// blob reads) when a repository-wide walk warms its memo. Remote drivers are
// latency-bound, so a modest fan-out collapses a long sequential walk without
// swamping the backend or parking one goroutine per descriptor.
const walkReadParallelism = 32

// concurrentReader is implemented by stores whose reads are safe to issue from
// many goroutines at once. Anything else, such as a test double, is read
// sequentially with unchanged semantics.
type concurrentReader interface {
	ConcurrentReadSafe() bool
}

// WalkMemo holds the manifests and indexes one repository-wide walk has parsed,
// so a digest referenced many times within that walk is read from storage once.
// It lives for a single walk: a GC pass or one manifest update. Across walks,
// storage stays authoritative, so a blob altered or removed between them is
// seen. A nil *WalkMemo reads through without memoising.
type WalkMemo struct {
	mu                  sync.Mutex
	indexes             map[godigest.Digest]ispec.Index
	manifests           map[godigest.Digest]ispec.Manifest
	flight              singleflight.Group
	prefetchParallelism int
}

// NewWalkMemo returns an empty memo for one walk.
func NewWalkMemo() *WalkMemo {
	return &WalkMemo{
		indexes:             map[godigest.Digest]ispec.Index{},
		manifests:           map[godigest.Digest]ispec.Manifest{},
		prefetchParallelism: walkReadParallelism,
	}
}

// GetIndex is GetImageIndex through the memo.
//
//nolint:dupl // intentionally mirrors GetManifest for index digests
func (m *WalkMemo) GetIndex(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zlog.Logger,
) (ispec.Index, error) {
	if m == nil {
		return GetImageIndex(imgStore, repo, digest, log)
	}

	m.mu.Lock()
	idx, ok := m.indexes[digest]
	m.mu.Unlock()

	if ok {
		return idx, nil
	}

	result, err, _ := m.flight.Do("i:"+digest.String(), func() (any, error) {
		m.mu.Lock()
		if cached, hit := m.indexes[digest]; hit {
			m.mu.Unlock()

			return cached, nil
		}
		m.mu.Unlock()

		fetched, err := GetImageIndex(imgStore, repo, digest, log)
		if err != nil {
			return nil, err
		}

		m.mu.Lock()
		m.indexes[digest] = fetched
		m.mu.Unlock()

		return fetched, nil
	})
	if err != nil {
		return ispec.Index{}, err
	}

	idx, ok = result.(ispec.Index)
	if !ok {
		return ispec.Index{}, fmt.Errorf("walk memo GetIndex: unexpected type %T", result) //nolint:err113
	}

	return idx, nil
}

// GetManifest is GetImageManifest through the memo.
//
//nolint:dupl // intentionally mirrors GetIndex for manifest digests
func (m *WalkMemo) GetManifest(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zlog.Logger,
) (ispec.Manifest, error) {
	if m == nil {
		return GetImageManifest(imgStore, repo, digest, log)
	}

	m.mu.Lock()
	man, ok := m.manifests[digest]
	m.mu.Unlock()

	if ok {
		return man, nil
	}

	result, err, _ := m.flight.Do("m:"+digest.String(), func() (any, error) {
		m.mu.Lock()
		if cached, hit := m.manifests[digest]; hit {
			m.mu.Unlock()

			return cached, nil
		}
		m.mu.Unlock()

		fetched, err := GetImageManifest(imgStore, repo, digest, log)
		if err != nil {
			return nil, err
		}

		m.mu.Lock()
		m.manifests[digest] = fetched
		m.mu.Unlock()

		return fetched, nil
	})
	if err != nil {
		return ispec.Manifest{}, err
	}

	man, ok = result.(ispec.Manifest)
	if !ok {
		return ispec.Manifest{}, fmt.Errorf("walk memo GetManifest: unexpected type %T", result) //nolint:err113
	}

	return man, nil
}

// Prefetch warms the memo concurrently so the following walk avoids one
// storage round-trip per descriptor. Errors are not cached (the walk re-reads).
// Scheduling stops on ctx cancel or a non-Missing error; in-flight workers are
// still waited on. Duplicate digests are scheduled once; stores that are not
// ConcurrentReadSafe are skipped.
func (m *WalkMemo) Prefetch(ctx context.Context, imgStore storageTypes.ImageStore, repo string,
	descs []ispec.Descriptor, log zlog.Logger,
) {
	if m == nil {
		return
	}

	if reader, ok := imgStore.(concurrentReader); !ok || !reader.ConcurrentReadSafe() {
		return
	}

	parallelism := m.prefetchParallelism
	if parallelism <= 0 {
		parallelism = walkReadParallelism
	}

	var (
		wg   sync.WaitGroup
		stop atomic.Bool
	)

	sem := make(chan struct{}, parallelism)
	// scheduled reserves one Prefetch worker per (kind, digest) before taking
	// a semaphore slot, so a run of alias rows for the same digest cannot fill
	// the pool while unique digests wait.
	scheduled := make(map[string]struct{}, len(descs))

	for _, desc := range descs {
		if stop.Load() || ctx.Err() != nil {
			break
		}

		isIndex := compat.IsImageIndexMediaType(desc.MediaType)
		isManifest := compat.IsImageManifestMediaType(desc.MediaType)

		if !isIndex && !isManifest {
			continue
		}

		m.mu.Lock()
		_, haveIdx := m.indexes[desc.Digest]
		_, haveMan := m.manifests[desc.Digest]
		m.mu.Unlock()

		if (isIndex && haveIdx) || (isManifest && haveMan) {
			continue
		}

		keyPrefix := "m:"
		if isIndex {
			keyPrefix = "i:"
		}

		key := keyPrefix + desc.Digest.String()
		if _, ok := scheduled[key]; ok {
			continue
		}

		scheduled[key] = struct{}{}

		dgst := desc.Digest
		fetchIndex := isIndex

		// Take the slot before spawning so Prefetch never parks one goroutine
		// per descriptor on a large repository; at most `parallelism` workers run.
		// Also select on ctx so cancel does not block behind a full semaphore.
		// A bare break inside select only leaves the select, so use acquired
		// to stop the for loop without a labeled break.
		acquired := false
		select {
		case sem <- struct{}{}:
			acquired = true
		case <-ctx.Done():
		}
		if !acquired {
			break
		}

		if stop.Load() || ctx.Err() != nil {
			<-sem

			break
		}

		wg.Go(func() {
			defer func() { <-sem }()

			var err error
			if fetchIndex {
				_, err = m.GetIndex(imgStore, repo, dgst, log)
			} else {
				_, err = m.GetManifest(imgStore, repo, dgst, log)
			}

			if err != nil && !errclass.IsBlobUnavailable(err) {
				stop.Store(true)
			}
		})
	}

	wg.Wait()
}
