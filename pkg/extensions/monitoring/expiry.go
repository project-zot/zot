//go:build metrics

package monitoring

import "sync"

// repoLabelTracker guards the transition between "a repo is being observed right now"
// and "a repo's series are being evicted" with a single mutex, so a sweep can never
// delete a label value that a concurrent request is in the middle of writing to.
// touchAndObserve and expire are the only entry points and both hold t.mu for their
// full duration, including the actual metric mutation/deletion, not just the
// bookkeeping maps.
type repoLabelTracker struct {
	mu       sync.Mutex
	current  map[string]struct{}
	previous map[string]struct{}
}

var labelTracker = &repoLabelTracker{ //nolint: gochecknoglobals
	current:  map[string]struct{}{},
	previous: map[string]struct{}{},
}

// touchAndObserve marks repo as active for the current generation and performs
// observe (the actual WithLabelValues(...).Inc()/Observe() call) atomically with
// that bookkeeping, so a concurrent expire() sweep can never delete the series
// observe is about to write to out from under it.
func (t *repoLabelTracker) touchAndObserve(repo string, observe func()) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.current[repo] = struct{}{}
	observe()
}

// expire deletes the label values that were not touched since the sweep before last
// (i.e. survived neither the previous nor the current generation) via delete, then
// rotates generations. Because it holds t.mu for the entire computation and every
// delete call, no touchAndObserve for one of the stale repos can be in flight
// concurrently: it either completed strictly before this call (and is therefore
// legitimately stale) or will run strictly after (and will simply recreate the
// series fresh, which is the normal generational-eviction boundary case, not data
// loss for an active series).
func (t *repoLabelTracker) expire(delete func(repo string)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for repo := range t.previous {
		if _, ok := t.current[repo]; !ok {
			delete(repo)
		}
	}

	t.previous = t.current
	t.current = map[string]struct{}{}
}

// ExpireRepoMetrics evicts stale per-repo label values from repo-labeled metric vecs.
// A repo is considered stale if it wasn't touched between the two most recent sweeps.
func ExpireRepoMetrics(ms MetricServer) {
	ms.ForceSendMetric(func() {
		// Every call site touching these vecs uses inline WithLabelValues(...).Observe()/.Inc()
		// rather than holding a child Observer/Counter across calls, so DeleteLabelValues here
		// cannot orphan a live child. If a future refactor hoists a child metric out of a hot
		// path, it must not survive across a sweep.
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
