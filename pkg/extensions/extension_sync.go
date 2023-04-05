//go:build sync
// +build sync

package extensions

import (
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/sync"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
)

func EnableSyncExtension(config *config.Config, repoDB repodb.RepoDB,
	storeController storage.StoreController, sch *scheduler.Scheduler, log log.Logger,
) (*sync.BaseOnDemand, error) {
	if config.Extensions.Sync != nil && *config.Extensions.Sync.Enable {
		onDemand := sync.NewOnDemand(log)

		for _, registryConfig := range config.Extensions.Sync.Registries {
			isPeriodical := len(registryConfig.Content) != 0 && registryConfig.PollInterval != 0
			isOnDemand := registryConfig.OnDemand

			if isPeriodical || isOnDemand {
				service, err := sync.New(registryConfig, config.Extensions.Sync.CredentialsFile,
					storeController, repoDB, log)
				if err != nil {
					return nil, err
				}

				if isPeriodical {
					// add to task scheduler periodic sync
					gen := sync.NewTaskGenerator(service, log)
					sch.SubmitGenerator(gen, registryConfig.PollInterval, scheduler.MediumPriority)
				}

				if isOnDemand {
					// onDemand services used in routes.go
					onDemand.Add(service)
				}
			}
		}

		return onDemand, nil
	}

	log.Info().Msg("Sync registries config not provided or disabled, skipping sync")

	return nil, nil //nolint: nilnil
}
