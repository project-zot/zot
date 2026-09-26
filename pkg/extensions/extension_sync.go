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

// EnableSyncExtension builds the sync services for config. prev is the SyncOnDemand from before a
// reload (nil at startup); its stream manager is reused, so streams in flight stay reachable.
func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, prev SyncOnDemand, log log.Logger,
) (SyncOnDemand, error) {
	// Get extensions config safely
	extensionsConfig := config.CopyExtensionsConfig()
	httpAddress := config.GetHTTPAddress()
	httpPort := config.GetHTTPPort()

	if extensionsConfig.IsSyncEnabled() {
		log.Info().Msg("sync extension is enabled")

		onDemand := sync.NewOnDemand(log)
		syncConfig := extensionsConfig.GetSyncConfig()

		// One stream manager serves every streaming registry, so maxConcurrentStreams is one
		// instance-wide cap. Created only if some registry streams.
		var (
			streamManager        sync.StreamManager
			maxConcurrentStreams int
		)

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

			// Built from the first streaming registry; config validation ensures the others use
			// the same maxConcurrentStreams.
			if registryConfig.IsStreamEnabled() && streamManager == nil {
				if registryConfig.MaxConcurrentStreams != nil {
					maxConcurrentStreams = *registryConfig.MaxConcurrentStreams
				}

				streamManager = reuseOrNewStreamManager(prev, storeController, maxConcurrentStreams, log)
				onDemand.SetStreamManager(streamManager)
			}

			// Every service gets it, but only uses it for a staged repo:reference (see syncRef).
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

		// Resize a reused manager only now that every service is up: a reload that fails above
		// keeps the previous SyncOnDemand, which must keep its cap too.
		if chunking, ok := streamManager.(*sync.ChunkingStreamManager); ok {
			chunking.SetMaxConcurrentStreams(maxConcurrentStreams)
		}

		// No registry streams any more: keep the previous manager anyway, so the blob routes can
		// still serve the streams staged before the reload until they drain. Nothing new is
		// staged: the manifest route only streams repos a streaming registry matches.
		if streamManager == nil && prev != nil && prev.StreamManager() != nil {
			onDemand.SetStreamManager(prev.StreamManager())
		}

		return onDemand, nil
	}

	log.Info().Msg("sync config not provided or disabled, so not enabling sync")

	return nil, nil //nolint: nilnil
}

// reuseOrNewStreamManager returns prev's stream manager, not yet resized (EnableSyncExtension does
// that once the reload can't fail), or a new one. A reload never drops a manager (see
// EnableSyncExtension): streams in flight stay reachable until they drain.
func reuseOrNewStreamManager(prev SyncOnDemand, storeController storage.StoreController,
	maxConcurrentStreams int, log log.Logger,
) sync.StreamManager {
	if prev != nil {
		if streamManager, ok := prev.StreamManager().(*sync.ChunkingStreamManager); ok {
			return streamManager
		}
	}

	return sync.NewChunkingStreamManager(storeController, maxConcurrentStreams, log)
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
