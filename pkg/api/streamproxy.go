package api

import (
	"fmt"
	"sync"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/streamcache"
)

// StreamProxyManager manages stream proxies for different registries
type StreamProxyManager struct {
	proxies         map[string]*streamcache.StreamProxy
	cache           *streamcache.StreamCache
	storeController storage.StoreController
	log             log.Logger
	mu              sync.RWMutex
}

// NewStreamProxyManager creates a new StreamProxyManager
func NewStreamProxyManager(
	syncConfig *syncconf.Config,
	storeController storage.StoreController,
	log log.Logger,
) (*StreamProxyManager, error) {
	if syncConfig == nil {
		return nil, nil
	}

	mgr := &StreamProxyManager{
		proxies:         make(map[string]*streamcache.StreamProxy),
		storeController: storeController,
		log:             log,
	}

	// Check if stream cache is enabled for any registry
	var streamCacheEnabled bool
	var cacheDir string
	var maxSize int64

	for _, regConfig := range syncConfig.Registries {
		if regConfig.StreamCache != nil && regConfig.StreamCache.Enable != nil && *regConfig.StreamCache.Enable {
			streamCacheEnabled = true
			cacheDir = regConfig.StreamCache.CacheDir
			maxSize = regConfig.StreamCache.MaxSize
			break
		}
	}

	if !streamCacheEnabled {
		log.Info().Msg("stream cache not enabled for any registry")
		return nil, nil
	}

	// Create global cache
	cache, err := streamcache.NewStreamCache(cacheDir, maxSize, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream cache: %w", err)
	}

	mgr.cache = cache

	// Create proxies for each registry with stream cache enabled
	credentialsFile, err := getCredentialsFile(syncConfig.CredentialsFile, log)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load credentials file")
	}

	for _, regConfig := range syncConfig.Registries {
		if regConfig.StreamCache == nil || regConfig.StreamCache.Enable == nil || !*regConfig.StreamCache.Enable {
			continue
		}

		for _, url := range regConfig.URLs {
			credentials := streamcache.Credentials{}
			if credentialsFile != nil {
				if creds, ok := credentialsFile[url]; ok {
					credentials.Username = creds.Username
					credentials.Password = creds.Password
				}
			}

			imageStore := storeController.GetDefaultImageStore()

			proxy := streamcache.NewStreamProxy(
				cache,
				imageStore,
				url,
				credentials,
				log,
			)

			mgr.mu.Lock()
			mgr.proxies[url] = proxy
			mgr.mu.Unlock()

			log.Info().
				Str("registry", url).
				Str("cacheDir", cacheDir).
				Msg("stream proxy initialized for registry")
		}
	}

	return mgr, nil
}

// GetProxy returns the proxy for a specific registry URL
func (mgr *StreamProxyManager) GetProxy(registryURL string) (*streamcache.StreamProxy, bool) {
	if mgr == nil {
		return nil, false
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	proxy, exists := mgr.proxies[registryURL]
	return proxy, exists
}

// HasProxy checks if a proxy exists for the specified registry
func (mgr *StreamProxyManager) HasProxy(registryURL string) bool {
	if mgr == nil {
		return false
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	_, exists := mgr.proxies[registryURL]
	return exists
}

// IsEnabled checks if the stream proxy manager is active
func (mgr *StreamProxyManager) IsEnabled() bool {
	return mgr != nil && len(mgr.proxies) > 0
}

// GetCache returns the stream cache
func (mgr *StreamProxyManager) GetCache() *streamcache.StreamCache {
	if mgr == nil {
		return nil
	}
	return mgr.cache
}

// getCredentialsFile loads credentials from file
func getCredentialsFile(credentialsPath string, log log.Logger) (map[string]syncconf.Credentials, error) {
	if credentialsPath == "" {
		return nil, nil
	}

	// This function would need to load credentials - simplified for now
	// In the real implementation this would load the file
	log.Debug().Str("path", credentialsPath).Msg("loading credentials file")
	return make(map[string]syncconf.Credentials), nil
}
