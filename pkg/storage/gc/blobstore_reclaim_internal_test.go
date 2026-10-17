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
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// reclaimerStore is an image store that defers global blob reclaim to a sweep.
type reclaimerStore struct {
	mocks.MockedImageStore

	delays chan time.Duration
}

func (store *reclaimerStore) ReclaimGlobalBlobs(_ context.Context, delay time.Duration) error {
	store.delays <- delay

	return nil
}

func newReclaimerStore(driverName string) *reclaimerStore {
	return &reclaimerStore{
		MockedImageStore: mocks.MockedImageStore{NameFn: func() string { return driverName }},
		delays:           make(chan time.Duration, 8), //nolint:mnd
	}
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

	Convey("A remote store's sweep reclaims payloads unowned for the GC delay", t, func() {
		store := newReclaimerStore(storageConstants.S3StorageDriverName)

		sch := newScheduler()
		// with claims in the cache, a short delay is only a policy, not a risk
		RunGlobalBlobReclaimPeriodically(store, time.Minute, time.Hour, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		So(awaitDelay(store.delays), ShouldEqual, time.Minute)
	})

	Convey("A zero GC delay and interval fall back to the GC defaults", t, func() {
		store := newReclaimerStore(storageConstants.S3StorageDriverName)

		sch := newScheduler()
		RunGlobalBlobReclaimPeriodically(store, 0, 0, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		So(awaitDelay(store.delays), ShouldEqual, storageConstants.DefaultGCDelay)
	})

	Convey("Local stores, and stores without a sweep, get none", t, func() {
		store := newReclaimerStore(storageConstants.LocalStorageDriverName)

		sch := newScheduler()
		RunGlobalBlobReclaimPeriodically(store, time.Hour, time.Hour, sch, log)
		RunGlobalBlobReclaimPeriodically(mocks.MockedImageStore{}, time.Hour, time.Hour, sch, log)
		sch.RunScheduler()
		defer sch.Shutdown()

		select {
		case <-store.delays:
			So("sweep ran for a local store", ShouldBeEmpty)
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
