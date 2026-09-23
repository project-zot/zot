//go:build metrics

package monitoring

import "sync"

// repoLabelTracker tracks which repos have been touched in the current and
// previous generations. Touches only need to record activity in a
// concurrent-safe map; they never block on each other or on a sweep in
// progress. A sweep briefly takes an exclusive lock only to swap generations,
// then evicts stale labels outside the lock.
type repoLabelTracker struct {
	mu       sync.RWMutex // guards swapping the current/previous pointers
	current  *sync.Map
	previous *sync.Map
}

var labelTracker = &repoLabelTracker{ //nolint: gochecknoglobals
	current:  &sync.Map{},
	previous: &sync.Map{},
}

// touchAndObserve marks repo active for the current generation and runs
// observe. observe() itself is not gated by the tracker lock - metric vecs
// already handle their own concurrency - so steady-state writers never
// serialize behind each other or behind a sweep.
func (t *repoLabelTracker) touchAndObserve(tracking bool, repo string, observe func()) {
	if !tracking {
		observe()

		return
	}

	t.mu.RLock()
	cur := t.current
	t.mu.RUnlock()

	cur.Store(repo, struct{}{})
	observe()
}

// expire deletes repos untouched across the last two generations, then
// rotates. The generation swap is the only part done under an exclusive
// lock; the scan and evict() calls happen afterward against the (now
// immutable) previous generation, so they never block touches.
func (t *repoLabelTracker) expire(evict func(repo string)) {
	next := &sync.Map{}

	t.mu.Lock()
	prev, cur := t.previous, t.current
	t.previous, t.current = cur, next
	t.mu.Unlock()

	prev.Range(func(key, _ any) bool {
		repo, _ := key.(string)
		if _, ok := cur.Load(repo); !ok {
			evict(repo)
		}

		return true
	})
}

// ExpireRepoMetrics evicts stale per-repo label values from repo-labeled metric vecs.
// A repo is considered stale if it wasn't touched between the two most recent sweeps.
func ExpireRepoMetrics(ms MetricServer) {
	ms.ForceSendMetric(func() {
		vecs := []interface {
			DeleteLabelValues(lvs ...string) bool
		}{
			httpRepoLatency,
			uploadCounter,
			downloadCounter,
		}

		labelTracker.expire(func(repo string) {
			for _, vec := range vecs {
				vec.DeleteLabelValues(repo)
			}
		})
	})
}
