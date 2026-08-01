package cache

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

type CveCache struct {
	cache *lru.Cache[string, map[string]common.CVE]
	log   log.Logger
}

func NewCveCache(size int, log log.Logger) *CveCache {
	cache, _ := lru.New[string, map[string]common.CVE](size)

	return &CveCache{cache: cache, log: log}
}

func (cveCache *CveCache) Add(image string, cveMap map[string]common.CVE) {
	cveCache.cache.Add(image, cveMap)
}

func (cveCache *CveCache) Contains(image string) bool {
	return cveCache.cache.Contains(image)
}

func (cveCache *CveCache) Get(image string) map[string]common.CVE {
	cveMap, ok := cveCache.cache.Get(image)
	if !ok {
		return nil
	}

	return cveMap
}

func (cveCache *CveCache) Purge() {
	cveCache.cache.Purge()
}
