package features

import (
	"sync"
	"time"
)

const defaultExpireMinutes = 10

type featureKey struct {
	kind string
	repo string
}

type featureVal struct {
	enabled bool
	expire  time.Time
}

type Map struct {
	store       map[featureKey]*featureVal
	expireAfter time.Duration
	mu          *sync.Mutex
}

func New() *Map {
	return &Map{
		store:       make(map[featureKey]*featureVal),
		expireAfter: defaultExpireMinutes * time.Minute,
		mu:          new(sync.Mutex),
	}
}

// returns if registry supports this feature and if ok.
func (f *Map) Get(kind, repo string) (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if feature, ok := f.store[featureKey{kind, repo}]; ok {
		if time.Now().Before(feature.expire) {
			return feature.enabled, true
		}
	}

	// feature expired or not found
	return false, false
}

func (f *Map) Set(kind, repo string, enabled bool) {
	f.mu.Lock()
	f.store[featureKey{kind: kind, repo: repo}] = &featureVal{enabled: enabled, expire: time.Now().Add(f.expireAfter)}
	f.mu.Unlock()
}
