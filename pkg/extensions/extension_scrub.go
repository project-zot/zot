//go:build scrub
// +build scrub

package extensions

import (
	"time"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/scrub"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

// EnableScrubExtension enables scrub extension.
func EnableScrubExtension(config *config.Config, log log.Logger, storeController storage.StoreController,
	sch *scheduler.Scheduler,
) {
	if config.Extensions.Scrub != nil &&
		*config.Extensions.Scrub.Enable {
		minScrubInterval, _ := time.ParseDuration("2h")

		if config.Extensions.Scrub.Interval < minScrubInterval {
			config.Extensions.Scrub.Interval = minScrubInterval

			log.Warn().Msg("Scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
		}

		// is local imagestore (because of umoci dependency which works only locally)
		if config.Storage.StorageDriver == nil {
			generator := &taskGenerator{
				imgStore: storeController.DefaultStore,
				log:      log,
			}
			sch.SubmitGenerator(generator, config.Extensions.Scrub.Interval, scheduler.LowPriority)
		}

		if config.Storage.SubPaths != nil {
			for route := range config.Storage.SubPaths {
				// is local imagestore (because of umoci dependency which works only locally)
				if config.Storage.SubPaths[route].StorageDriver == nil {
					generator := &taskGenerator{
						imgStore: storeController.SubStore[route],
						log:      log,
					}
					sch.SubmitGenerator(generator, config.Extensions.Scrub.Interval, scheduler.LowPriority)
				}
			}
		}
	} else {
		log.Info().Msg("Scrub config not provided, skipping scrub")
	}
}

type taskGenerator struct {
	imgStore storageTypes.ImageStore
	log      log.Logger
	lastRepo string
	done     bool
}

func (gen *taskGenerator) Next() (scheduler.Task, error) {
	repo, err := gen.imgStore.GetNextRepository(gen.lastRepo)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return scrub.NewTask(gen.imgStore, repo, gen.log), nil
}

func (gen *taskGenerator) IsDone() bool {
	return gen.done
}

func (gen *taskGenerator) IsReady() bool {
	return true
}

func (gen *taskGenerator) Reset() {
	gen.lastRepo = ""
	gen.done = false
}
