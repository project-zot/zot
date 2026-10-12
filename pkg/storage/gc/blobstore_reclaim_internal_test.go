package gc

import (
	"context"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// reclaimerStore is an image store that defers global blob reclaim, as remote stores do.
type reclaimerStore struct {
	mocks.MockedImageStore

	logicalRefs bool
	delays      chan time.Duration
}

func (store *reclaimerStore) UsesLogicalRepoRefs() bool {
	return store.logicalRefs
}

func (store *reclaimerStore) ReclaimGlobalBlobs(_ context.Context, delay time.Duration) error {
	store.delays <- delay

	return nil
}

func TestRunGlobalBlobReclaimPeriodically(t *testing.T) {
	log := zlog.NewTestLogger()

	newScheduler := func() *scheduler.Scheduler {
		sch := scheduler.NewScheduler(config.New(), monitoring.NewNopMetricServer(), log)
		sch.RateLimit = 10 * time.Millisecond

		return sch
	}

	awaitDelay := func(delays chan time.Duration) time.Duration {
		select {
		case delay := <-delays:
			return delay
		case <-time.After(10 * time.Second):
			return -1
		}
	}

	Convey("The sweep never runs with less than the safe minimum delay", t, func() {
		store := &reclaimerStore{logicalRefs: true, delays: make(chan time.Duration, 8)}

		sch := newScheduler()
		RunGlobalBlobReclaimPeriodically(store, time.Millisecond, time.Hour, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		So(awaitDelay(store.delays), ShouldEqual, imagestore.MinGlobalReclaimDelay)
	})

	Convey("A longer GC delay is used as the reclaim delay", t, func() {
		store := &reclaimerStore{logicalRefs: true, delays: make(chan time.Duration, 8)}

		sch := newScheduler()
		// zero delay and interval fall back to the GC defaults
		RunGlobalBlobReclaimPeriodically(store, 0, 0, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		So(awaitDelay(store.delays), ShouldEqual, time.Hour)
	})

	Convey("Stores that keep per-repo copies get no sweep", t, func() {
		store := &reclaimerStore{delays: make(chan time.Duration, 8)}

		sch := newScheduler()
		RunGlobalBlobReclaimPeriodically(store, time.Hour, time.Hour, sch, log)
		RunGlobalBlobReclaimPeriodically(mocks.MockedImageStore{}, time.Hour, time.Hour, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		select {
		case <-store.delays:
			So("sweep ran for a store without logical refs", ShouldBeEmpty)
		case <-time.After(200 * time.Millisecond):
		}
	})

	Convey("The task and generator identify themselves", t, func() {
		gen := &globalBlobReclaimGenerator{rootDir: "/root"}
		So(gen.Name(), ShouldEqual, "GlobalBlobReclaimGenerator")
		So(gen.IsReady(), ShouldBeTrue)

		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(gen.IsDone(), ShouldBeFalse)
		So(task.Name(), ShouldEqual, "GlobalBlobReclaimTask")
		So(task.String(), ShouldContainSubstring, "/root")

		// one sweep per round: the second call only reports the round as done
		task, err = gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)

		gen.Reset()
		So(gen.IsDone(), ShouldBeFalse)
	})
}
