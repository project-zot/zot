//go:build sync

package sync

import (
	"sync"
	"time"
)

type tagsVal struct {
	tags     []string
	expireAt time.Time
}

type tagsCache struct {
	store       map[string]*tagsVal
	expireAfter time.Duration
	mu          *sync.Mutex
}

func newTagsCache(expireAfter time.Duration) *tagsCache {
	return &tagsCache{
		store:       make(map[string]*tagsVal),
		expireAfter: expireAfter,
		mu:          new(sync.Mutex),
	}
}

// Get returns true if still valid (not expired) and tags list.
func (c *tagsCache) Get(repo string) (bool, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if tags, ok := c.store[repo]; ok {
		if time.Now().Before(tags.expireAt) {
			return true, tags.tags
		}

		return false, tags.tags
	}

	return false, nil
}

func (c *tagsCache) Set(repo string, tags []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store[repo] = &tagsVal{
		expireAt: time.Now().Add(c.expireAfter),
		tags:     tags,
	}
}
