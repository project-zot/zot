//go:build scrub
// +build scrub

package extensions

import (
	"time"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/scrub"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
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

			log.Warn().Msg("scrub interval set to too-short interval < 2h, changing scrub duration to 2 hours and continuing.") //nolint:lll // gofumpt conflicts with lll
		}

		processedRepos := make(map[string]struct{})

		generator := &taskGenerator{
			imgStore:       storeController.DefaultStore,
			log:            log,
			processedRepos: processedRepos,
		}

		sch.SubmitGenerator(generator, config.Extensions.Scrub.Interval, scheduler.LowPriority)

		if config.Storage.SubPaths != nil {
			for route := range config.Storage.SubPaths {
				processedRepos := make(map[string]struct{})

				generator := &taskGenerator{
					imgStore:       storeController.SubStore[route],
					log:            log,
					processedRepos: processedRepos,
				}

				sch.SubmitGenerator(generator, config.Extensions.Scrub.Interval, scheduler.LowPriority)
			}
		}
	} else {
		log.Info().Msg("scrub config not provided, skipping scrub")
	}
}

type taskGenerator struct {
	imgStore       storageTypes.ImageStore
	log            log.Logger
	processedRepos map[string]struct{}
	done           bool
}

func (gen *taskGenerator) Name() string {
	return "ScrubGenerator"
}

func (gen *taskGenerator) Next() (scheduler.Task, error) {
	repo, err := gen.imgStore.GetNextRepository(gen.processedRepos)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil //nolint:nilnil
	}

	gen.processedRepos[repo] = struct{}{}

	return scrub.NewTask(gen.imgStore, repo, gen.log), nil
}

func (gen *taskGenerator) IsDone() bool {
	return gen.done
}

func (gen *taskGenerator) IsReady() bool {
	return true
}

func (gen *taskGenerator) Reset() {
	gen.processedRepos = make(map[string]struct{})
	gen.done = false
}
