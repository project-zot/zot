package cache

import (
	lru "github.com/hashicorp/golang-lru/v2"

	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
)

type CveCache struct {
	cache *lru.Cache[string, map[string]cvemodel.CVE]
	log   log.Logger
}

func NewCveCache(size int, log log.Logger) *CveCache {
	cache, _ := lru.New[string, map[string]cvemodel.CVE](size)

	return &CveCache{cache: cache, log: log}
}

func (cveCache *CveCache) Add(image string, cveMap map[string]cvemodel.CVE) {
	cveCache.cache.Add(image, cveMap)
}

func (cveCache *CveCache) Contains(image string) bool {
	return cveCache.cache.Contains(image)
}

func (cveCache *CveCache) Get(image string) map[string]cvemodel.CVE {
	cveMap, ok := cveCache.cache.Get(image)
	if !ok {
		return nil
	}

	return cveMap
}

func (cveCache *CveCache) Purge() {
	cveCache.cache.Purge()
}
