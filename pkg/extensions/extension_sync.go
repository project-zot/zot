//go:build sync

package extensions

import (
	"net"
	"net/url"
	"slices"
	"strings"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, log log.Logger,
) (SyncOnDemand, error) {
	// Get extensions config safely
	extensionsConfig := config.CopyExtensionsConfig()
	httpAddress := config.GetHTTPAddress()
	httpPort := config.GetHTTPPort()

	if extensionsConfig.IsSyncEnabled() {
		log.Info().Msg("sync extension is enabled")

		onDemand := sync.NewOnDemand(log)
		syncConfig := extensionsConfig.GetSyncConfig()

		// One stream manager is shared by every streaming-enabled registry (streams are keyed by
		// blob digest, not by registry, so pulls of the same blob from different upstreams still
		// collapse onto one in-flight download). Built lazily, and only once, on first use below,
		// so a config with no streaming registries never creates the "_stream" staging directory.
		var streamManager sync.StreamManager

		for _, registryConfig := range syncConfig.Registries {
			if len(registryConfig.URLs) > 1 {
				if err := removeSelfURLs(httpAddress, httpPort, &registryConfig, log); err != nil {
					return nil, err
				}
			}

			if len(registryConfig.URLs) == 0 {
				log.Error().Err(zerr.ErrSyncNoURLsLeft).Msg("failed to start sync extension")

				return nil, zerr.ErrSyncNoURLsLeft
			}

			isPeriodical := len(registryConfig.Content) != 0 && registryConfig.PollInterval != 0
			isOnDemand := registryConfig.OnDemand

			if !(isPeriodical || isOnDemand) {
				continue
			}

			tmpDir := syncConfig.DownloadDir
			credsPath := syncConfig.CredentialsFile
			// Get cluster config safely
			clusterConfig := config.CopyClusterConfig()

			registryConfig.SetDockerCompat(config.IsDockerCompatEnabled())

			// The concurrent-stream cap is a property of the single shared stream manager, not of
			// a registry, so only the FIRST streaming-enabled registry's MaxConcurrentStreams (in
			// config order) takes effect; a different value on a later streaming registry is
			// ignored, since by then the manager already exists.
			if registryConfig.IsStreamEnabled() && streamManager == nil {
				maxConcurrentStreams := 0
				if registryConfig.MaxConcurrentStreams != nil {
					maxConcurrentStreams = *registryConfig.MaxConcurrentStreams
				}

				streamManager = sync.NewChunkingStreamManager(storeController, maxConcurrentStreams, log)
				onDemand.SetStreamManager(streamManager)
			}

			// streamManager, once created, is passed to every registry's service from here on -
			// including ones with Stream unset - since it is a single shared instance rather than
			// built per-registry. BaseService.syncImage deliberately gates its RemoveStreamingImage
			// purge on "streamManager != nil" rather than this registry's own IsStreamEnabled():
			// BaseOnDemand's background sync (after FetchManifestForStream stages a manifest) can
			// end up completing via a different, non-streaming registry's service - see the "known
			// gap" noted on IsStreamingEnabledForRepo - so every service sharing this manager must
			// still attempt the purge for cleanup to be reliable. The common case where nothing was
			// ever staged is a cheap no-op (goroutine + lock + a Debug-level log), not a warning.
			service, err := sync.New(registryConfig, credsPath, clusterConfig, tmpDir, storeController,
				streamManager, metaDB, log)
			if err != nil {
				log.Error().Err(err).Msg("failed to initialize sync extension")

				return nil, err
			}

			if isPeriodical {
				// add to task scheduler periodic sync
				interval := registryConfig.PollInterval

				gen := sync.NewTaskGenerator(service, interval, log)
				sch.SubmitGenerator(gen, interval, scheduler.MediumPriority)
			}

			if isOnDemand {
				// onDemand services used in routes.go
				onDemand.Add(service)
			}
		}

		return onDemand, nil
	}

	log.Info().Msg("sync config not provided or disabled, so not enabling sync")

	return nil, nil //nolint: nilnil
}

func getLocalIPs() ([]string, error) {
	var localIPs []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{}, err
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return localIPs, err
		}

		for _, addr := range addrs {
			if localIP, ok := addr.(*net.IPNet); ok {
				localIPs = append(localIPs, localIP.IP.String())
			}
		}
	}

	return localIPs, nil
}

func removeSelfURLs(httpAddress, httpPort string, registryConfig *syncconf.RegistryConfig, log log.Logger) error {
	// get IP from config
	selfAddress := net.JoinHostPort(httpAddress, httpPort)

	// get all local IPs from interfaces
	localIPs, err := getLocalIPs()
	if err != nil {
		return err
	}

	for idx := range slices.Backward(registryConfig.URLs) {
		registryURL := registryConfig.URLs[idx]

		url, err := url.Parse(registryURL)
		if err != nil {
			log.Error().Str("url", registryURL).Msg("failed to parse sync registry url, removing it")

			registryConfig.URLs = append(registryConfig.URLs[:idx], registryConfig.URLs[idx+1:]...)

			continue
		}

		// check self address
		if strings.Contains(registryURL, selfAddress) {
			log.Info().Str("url", registryURL).Msg("removing local registry url")

			registryConfig.URLs = append(registryConfig.URLs[:idx], registryConfig.URLs[idx+1:]...)

			continue
		}

		// check dns
		ips, err := net.LookupIP(url.Hostname()) //nolint: noctx
		if err != nil {
			// will not remove, maybe it will get resolved later after multiple retries
			log.Warn().Str("url", registryURL).Msg("failed to lookup sync registry url's hostname")

			continue
		}

		var removed bool

		for _, localIP := range localIPs {
			// if ip resolved from hostname/dns is equal with any local ip
			for _, ip := range ips {
				if (ip.IsLoopback() && (url.Port() == httpPort)) ||
					(net.JoinHostPort(ip.String(), url.Port()) == net.JoinHostPort(localIP, httpPort)) {
					registryConfig.URLs = append(registryConfig.URLs[:idx], registryConfig.URLs[idx+1:]...)

					removed = true

					break
				}
			}

			if removed {
				break
			}
		}
	}

	return nil
}
