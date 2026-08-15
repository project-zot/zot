//go:build sync

package sync

import (
	"sync"
	"time"
)

// minEvictPeriod bounds how often the tracker sweeps expired entries, so that a short
// manifestCheckInterval does not turn every MarkChecked call into a full map walk.
const minEvictPeriod = 10 * time.Minute

// manifestCheckTracker remembers when an upstream manifest check last succeeded for a
// repo:reference, so that on-demand requests arriving within manifestCheckInterval can be
// served from local storage without contacting upstream.
//
// Entries are dropped lazily on lookup and swept in an amortized pass from MarkChecked, which
// keeps the map bounded to the references seen within the interval without a background
// goroutine to own and shut down.
type manifestCheckTracker struct {
	store     map[string]time.Time
	interval  time.Duration
	lastEvict time.Time
	mu        sync.Mutex
}

func newManifestCheckTracker(interval time.Duration) *manifestCheckTracker {
	return &manifestCheckTracker{
		store:     make(map[string]time.Time),
		interval:  interval,
		lastEvict: time.Now(),
	}
}

// trackerKey joins repo and reference with a byte that cannot appear in either, so that
// distinct pairs can never collide on the same key.
func trackerKey(repo, reference string) string {
	return repo + "\x00" + reference
}

// ShouldCheckUpstream reports whether an upstream check is due for repo:reference.
// An expired entry is dropped on the way out, which is the common path for references
// that are requested once per interval.
func (t *manifestCheckTracker) ShouldCheckUpstream(repo, reference string) bool {
	key := trackerKey(repo, reference)

	t.mu.Lock()
	defer t.mu.Unlock()

	lastChecked, ok := t.store[key]
	if !ok {
		return true
	}

	if time.Since(lastChecked) >= t.interval {
		delete(t.store, key)

		return true
	}

	return false
}

// MarkChecked records that an upstream check just succeeded for repo:reference.
func (t *manifestCheckTracker) MarkChecked(repo, reference string) {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.store[trackerKey(repo, reference)] = now

	if now.Sub(t.lastEvict) >= t.evictPeriod() {
		t.evictExpired(now)
		t.lastEvict = now
	}
}

// evictPeriod returns the sweep period, never shorter than minEvictPeriod.
func (t *manifestCheckTracker) evictPeriod() time.Duration {
	if t.interval > minEvictPeriod {
		return t.interval
	}

	return minEvictPeriod
}

// evictExpired drops every entry past the interval. Caller must hold the lock.
func (t *manifestCheckTracker) evictExpired(now time.Time) {
	for key, lastChecked := range t.store {
		if now.Sub(lastChecked) >= t.interval {
			delete(t.store, key)
		}
	}
}
