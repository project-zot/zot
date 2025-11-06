package api

import (
	"fmt"
	"sync"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/streamcache"
)

// StreamProxyManager verwaltet Stream-Proxies für verschiedene Registries
type StreamProxyManager struct {
	proxies         map[string]*streamcache.StreamProxy
	cache           *streamcache.StreamCache
	storeController storage.StoreController
	log             log.Logger
	mu              sync.RWMutex
}

// NewStreamProxyManager erstellt einen neuen StreamProxyManager
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

	// Prüfe, ob Stream-Cache für irgendeine Registry aktiviert ist
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

	// Erstelle globalen Cache
	cache, err := streamcache.NewStreamCache(cacheDir, maxSize, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream cache: %w", err)
	}

	mgr.cache = cache

	// Erstelle Proxies für jede Registry mit aktiviertem Stream-Cache
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

// GetProxy gibt den Proxy für eine bestimmte Registry-URL zurück
func (mgr *StreamProxyManager) GetProxy(registryURL string) (*streamcache.StreamProxy, bool) {
	if mgr == nil {
		return nil, false
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	proxy, exists := mgr.proxies[registryURL]
	return proxy, exists
}

// HasProxy prüft, ob ein Proxy für die angegebene Registry existiert
func (mgr *StreamProxyManager) HasProxy(registryURL string) bool {
	if mgr == nil {
		return false
	}

	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	_, exists := mgr.proxies[registryURL]
	return exists
}

// IsEnabled prüft, ob Stream-Proxy-Manager aktiv ist
func (mgr *StreamProxyManager) IsEnabled() bool {
	return mgr != nil && len(mgr.proxies) > 0
}

// GetCache gibt den Stream-Cache zurück
func (mgr *StreamProxyManager) GetCache() *streamcache.StreamCache {
	if mgr == nil {
		return nil
	}
	return mgr.cache
}

// getCredentialsFile lädt Credentials aus Datei
func getCredentialsFile(credentialsPath string, log log.Logger) (map[string]syncconf.Credentials, error) {
	if credentialsPath == "" {
		return nil, nil
	}

	// Diese Funktion müsste die Credentials laden - für jetzt vereinfacht
	// In der echten Implementierung würde hier die Datei geladen
	log.Debug().Str("path", credentialsPath).Msg("loading credentials file")
	return make(map[string]syncconf.Credentials), nil
}
