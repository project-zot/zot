//go:build metrics

package monitoring

import "sync"

type repoLabelTracker struct {
	mu       sync.Mutex
	current  map[string]struct{}
	previous map[string]struct{}
}

var labelTracker = &repoLabelTracker{ //nolint: gochecknoglobals
	current:  map[string]struct{}{},
	previous: map[string]struct{}{},
}

func (t *repoLabelTracker) touch(repo string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.current[repo] = struct{}{}
}

func (t *repoLabelTracker) sweep() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	stale := make([]string, 0, len(t.previous))

	for repo := range t.previous {
		if _, ok := t.current[repo]; !ok {
			stale = append(stale, repo)
		}
	}

	t.previous = t.current
	t.current = map[string]struct{}{}

	return stale
}

// ExpireRepoMetrics evicts stale per-repo label values from repo-labeled metric vecs.
// A repo is considered stale if it wasn't touched between the two most recent sweeps.
func ExpireRepoMetrics(ms MetricServer) {
	ms.ForceSendMetric(func() {
		staleRepos := labelTracker.sweep()

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

		for _, repo := range staleRepos {
			for _, vec := range vecs {
				vec.DeleteLabelValues(repo)
			}
		}
	})
}
