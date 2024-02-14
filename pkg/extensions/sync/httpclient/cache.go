package client

import (
	"sync"
)

// Key:Value store for bearer tokens, key is namespace, value is token.
// We are storing only pull scoped tokens, the http client is for pulling only.
type TokenCache struct {
	entries sync.Map
}

func NewTokenCache() *TokenCache {
	return &TokenCache{
		entries: sync.Map{},
	}
}

func (c *TokenCache) Set(namespace string, token *bearerToken) {
	if c == nil || token == nil {
		return
	}

	defer c.prune()

	c.entries.Store(namespace, token)
}

func (c *TokenCache) Get(namespace string) *bearerToken {
	if c == nil {
		return nil
	}

	val, ok := c.entries.Load(namespace)
	if !ok {
		return nil
	}

	bearerToken, ok := val.(*bearerToken)
	if !ok {
		return nil
	}

	return bearerToken
}

func (c *TokenCache) prune() {
	c.entries.Range(func(key, val any) bool {
		bearerToken, ok := val.(*bearerToken)
		if ok {
			if bearerToken.isExpired() {
				c.entries.Delete(key)
			}
		}

		return true
	})
}
