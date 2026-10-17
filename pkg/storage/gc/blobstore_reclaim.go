package gc

import (
	"context"
	"fmt"
	"time"

	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// globalBlobReclaimer is implemented by image stores that defer deleting unowned global blobstore
// payloads to a sweep. It is optional, so that other stores and mocks need not know about it.
type globalBlobReclaimer interface {
	ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error
}

// RunGlobalBlobReclaimPeriodically schedules the sweep that deletes the global blobstore payloads
// of a remote store that no repo has owned for at least gcDelay. It runs whether or not GC is
// enabled: blobs deleted through the API must have their payloads reclaimed too. Local stores
// reclaim a payload with its last repo copy and need no sweep.
func RunGlobalBlobReclaimPeriodically(imgStore storageTypes.ImageStore, gcDelay, interval time.Duration,
	sch *scheduler.Scheduler, log zlog.Logger,
) {
	reclaimer, ok := imgStore.(globalBlobReclaimer)
	if !ok || imgStore.Name() == storageConstants.LocalStorageDriverName {
		return
	}

	if gcDelay <= 0 {
		gcDelay = storageConstants.DefaultGCDelay
	}

	if interval <= 0 {
		interval = storageConstants.DefaultGCInterval
	}

	log.Info().Str("module", "gc").Str("rootDir", imgStore.RootDir()).Dur("delay", gcDelay).
		Dur("interval", interval).Msg("enabling deferred reclaim of unowned global blobs")

	sch.SubmitGenerator(&globalBlobReclaimGenerator{
		reclaimer: reclaimer,
		rootDir:   imgStore.RootDir(),
		delay:     gcDelay,
	}, interval, scheduler.LowPriority)
}

// globalBlobReclaimGenerator yields a single sweep task per interval.
type globalBlobReclaimGenerator struct {
	reclaimer globalBlobReclaimer
	rootDir   string
	delay     time.Duration
	submitted bool
	done      bool
}

func (gen *globalBlobReclaimGenerator) Name() string {
	return "GlobalBlobReclaimGenerator"
}

func (gen *globalBlobReclaimGenerator) Next() (scheduler.Task, error) {
	// The scheduler drops whatever Next returns once IsDone is true, so the sweep task goes out
	// on one call and done is only reported on the next.
	if gen.submitted {
		gen.done = true

		return nil, nil //nolint:nilnil // no task: this round's sweep is already queued
	}

	gen.submitted = true

	return &globalBlobReclaimTask{reclaimer: gen.reclaimer, rootDir: gen.rootDir, delay: gen.delay}, nil
}

func (gen *globalBlobReclaimGenerator) IsDone() bool {
	return gen.done
}

func (gen *globalBlobReclaimGenerator) IsReady() bool {
	return true
}

func (gen *globalBlobReclaimGenerator) Reset() {
	gen.submitted = false
	gen.done = false
}

type globalBlobReclaimTask struct {
	reclaimer globalBlobReclaimer
	rootDir   string
	delay     time.Duration
}

func (task *globalBlobReclaimTask) DoWork(ctx context.Context) error {
	return task.reclaimer.ReclaimGlobalBlobs(ctx, task.delay)
}

func (task *globalBlobReclaimTask) String() string {
	return fmt.Sprintf("{Name: %s, rootDir: %s}", task.Name(), task.rootDir)
}

func (task *globalBlobReclaimTask) Name() string {
	return "GlobalBlobReclaimTask"
}
