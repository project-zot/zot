//go:build sync
// +build sync

package extensions

import (
	"net"
	"net/url"
	"strings"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/sync"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
)

func EnableSyncExtension(config *config.Config, metaDB mTypes.MetaDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, log log.Logger,
) (*sync.BaseOnDemand, error) {
	if config.Extensions.Sync != nil && *config.Extensions.Sync.Enable {
		onDemand := sync.NewOnDemand(log)

		for _, registryConfig := range config.Extensions.Sync.Registries {
			registryConfig := registryConfig
			if len(registryConfig.URLs) > 1 {
				if err := removeSelfURLs(config, &registryConfig, log); err != nil {
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

			tmpDir := config.Extensions.Sync.DownloadDir
			credsPath := config.Extensions.Sync.CredentialsFile

			service, err := sync.New(registryConfig, credsPath, tmpDir, storeController, metaDB, log)
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

func getIPFromHostName(host string) ([]string, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return []string{}, err
	}

	ips := make([]string, 0, len(addrs))

	for _, ip := range addrs {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func removeSelfURLs(config *config.Config, registryConfig *syncconf.RegistryConfig, log log.Logger) error {
	// get IP from config
	port := config.HTTP.Port
	selfAddress := net.JoinHostPort(config.HTTP.Address, port)

	// get all local IPs from interfaces
	localIPs, err := getLocalIPs()
	if err != nil {
		return err
	}

	for idx := len(registryConfig.URLs) - 1; idx >= 0; idx-- {
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
		ips, err := getIPFromHostName(url.Hostname())
		if err != nil {
			// will not remove, maybe it will get resolved later after multiple retries
			log.Warn().Str("url", registryURL).Msg("failed to lookup sync registry url's hostname")

			continue
		}

		var removed bool

		for _, localIP := range localIPs {
			// if ip resolved from hostname/dns is equal with any local ip
			for _, ip := range ips {
				if net.JoinHostPort(ip, url.Port()) == net.JoinHostPort(localIP, port) {
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
