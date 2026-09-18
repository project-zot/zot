//go:build metrics

package monitoring

import "sync"

// repoLabelTracker's mutex covers touchAndObserve and expire for their full duration
// (including the metric mutation/deletion), so a sweep can never delete a label value
// a concurrent request is writing to.
type repoLabelTracker struct {
	mu       sync.Mutex
	current  map[string]struct{}
	previous map[string]struct{}
}

var labelTracker = &repoLabelTracker{ //nolint: gochecknoglobals
	current:  map[string]struct{}{},
	previous: map[string]struct{}{},
}

// touchAndObserve marks repo active for the current generation and runs observe
// atomically with that bookkeeping. If tracking is disabled, it just runs observe -
// no map write, no lock.
func (t *repoLabelTracker) touchAndObserve(tracking bool, repo string, observe func()) {
	if !tracking {
		observe()

		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.current[repo] = struct{}{}
	observe()
}

// expire deletes repos untouched across the last two generations, then rotates.
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
		// No call site holds a child Observer/Counter across calls, so this can't orphan one.
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
