//go:build scrub
// +build scrub

package extensions

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/scrub"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// EnableScrubExtension enables scrub extension.
func EnableScrubExtension(config *config.Config, log log.Logger, storeController storage.StoreController,
	sch *scheduler.Scheduler,
) {
	// Get extensions config safely
	extensionsConfig := config.GetExtensionsConfig()
	if extensionsConfig.IsScrubEnabled() {
		scrubInterval := extensionsConfig.GetScrubInterval()

		processedRepos := make(map[string]struct{})

		generator := &taskGenerator{
			imgStore:       storeController.DefaultStore,
			log:            log,
			processedRepos: processedRepos,
		}

		sch.SubmitGenerator(generator, scrubInterval, scheduler.LowPriority)

		// Get storage config safely
		storageConfig := config.GetStorageConfig()
		if storageConfig.SubPaths != nil {
			for route := range storageConfig.SubPaths {
				processedRepos := make(map[string]struct{})

				generator := &taskGenerator{
					imgStore:       storeController.SubStore[route],
					log:            log,
					processedRepos: processedRepos,
				}

				sch.SubmitGenerator(generator, scrubInterval, scheduler.LowPriority)
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
