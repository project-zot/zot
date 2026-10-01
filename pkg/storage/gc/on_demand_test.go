package gc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

const onDemandRepo = "on-demand"

func TestGarbageCollectOnDemand(t *testing.T) {
	Convey("On-demand GC", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()

		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil,
			[]compat.MediaCompatibility{compat.DockerManifestV2SchemaV2}, nil)

		boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: rootDir})
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDriver, log)
		So(err, ShouldBeNil)

		storeController := storage.StoreController{DefaultStore: imgStore}

		err = WriteImageToFileSystem(CreateRandomImage(), onDemandRepo, "0.0.1", storeController)
		So(err, ShouldBeNil)

		opts := gc.Options{Delay: time.Millisecond, MaxSchedulerDelay: 10 * time.Millisecond}

		sch := scheduler.NewScheduler(config.New(), metrics, log)

		Convey("status is idle before the first sweep", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			status := onDemand.Status()
			So(status.Running, ShouldBeFalse)
			So(status.StartedAt.IsZero(), ShouldBeTrue)
			So(status.FinishedAt.IsZero(), ShouldBeTrue)
		})

		Convey("a requested sweep is reported as running before the scheduler starts it", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			// the scheduler is not running yet, so nothing can have started the sweep
			So(onDemand.SweepNow(), ShouldBeNil)

			status := onDemand.Status()
			So(status.Running, ShouldBeTrue)
			So(status.StartedAt.IsZero(), ShouldBeFalse)
			So(status.FinishedAt.IsZero(), ShouldBeTrue)

			So(onDemand.SweepNow(), ShouldEqual, zerr.ErrGCAlreadyRunning)

			sch.RunScheduler()
			defer sch.Shutdown()

			So(waitFor(func() bool { return !onDemand.Status().Running }), ShouldBeTrue)
			So(onDemand.Status().FinishedAt.IsZero(), ShouldBeFalse)
		})

		Convey("SweepNow runs a sweep before the interval passes", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			sch.RunScheduler()
			defer sch.Shutdown()

			// the first sweep starts right away
			So(waitFor(func() bool { return !onDemand.Status().FinishedAt.IsZero() }), ShouldBeTrue)
			firstFinish := onDemand.Status().FinishedAt

			orphan := uploadOrphanBlob(imgStore)
			time.Sleep(10 * time.Millisecond) // let the orphan get older than the GC delay

			So(onDemand.SweepNow(), ShouldBeNil)
			So(waitFor(func() bool {
				status := onDemand.Status()

				return !status.Running && status.FinishedAt.After(firstFinish)
			}), ShouldBeTrue)

			So(blobExists(imgStore, orphan), ShouldBeFalse)
		})

		Convey("SweepNow runs outside the configured time window", func() {
			windowOpts := opts
			windowOpts.TimeWindow = timeWindowExcludingNow()

			onDemand := gc.NewGarbageCollect(imgStore, metaDB, windowOpts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			orphan := uploadOrphanBlob(imgStore)
			time.Sleep(10 * time.Millisecond)

			sch.RunScheduler()
			defer sch.Shutdown()

			// outside the window, the periodic sweep does not start by itself
			time.Sleep(500 * time.Millisecond)
			So(onDemand.Status().StartedAt.IsZero(), ShouldBeTrue)

			So(onDemand.SweepNow(), ShouldBeNil)
			So(waitFor(func() bool { return !onDemand.Status().FinishedAt.IsZero() }), ShouldBeTrue)
			So(blobExists(imgStore, orphan), ShouldBeFalse)
		})

		Convey("CleanRepoNow collects a single repository", func() {
			windowOpts := opts
			windowOpts.TimeWindow = timeWindowExcludingNow() // keep the periodic sweep out of the way

			onDemand := gc.NewGarbageCollect(imgStore, metaDB, windowOpts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			orphan := uploadOrphanBlob(imgStore)
			time.Sleep(10 * time.Millisecond)

			sch.RunScheduler()
			defer sch.Shutdown()

			_, found := onDemand.RepoStatus(onDemandRepo)
			So(found, ShouldBeFalse)

			So(onDemand.CleanRepoNow(onDemandRepo), ShouldBeNil)
			So(waitFor(func() bool {
				status, found := onDemand.RepoStatus(onDemandRepo)

				return found && !status.Running && !status.FinishedAt.IsZero()
			}), ShouldBeTrue)

			status, _ := onDemand.RepoStatus(onDemandRepo)
			So(status.Error, ShouldBeEmpty)
			So(blobExists(imgStore, orphan), ShouldBeFalse)

			// the store-wide sweep did not run
			So(onDemand.Status().StartedAt.IsZero(), ShouldBeTrue)
		})

		Convey("CleanRepoNow rejects an unknown repository", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			So(onDemand.CleanRepoNow("does-not-exist"), ShouldEqual, zerr.ErrRepoNotFound)
		})

		Convey("CleanRepoNow rejects an invalid repository name", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			for _, repo := range []string{"..", "../" + onDemandRepo, ".", "/" + onDemandRepo, "UPPER"} {
				So(onDemand.CleanRepoNow(repo), ShouldEqual, zerr.ErrInvalidRepositoryName)
			}
		})

		Convey("CleanRepoNow reports a task the scheduler did not accept", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			sch.RunScheduler()
			sch.Shutdown()

			So(onDemand.CleanRepoNow(onDemandRepo), ShouldEqual, zerr.ErrGCNotScheduled)

			// not left running, so it can be requested again
			_, found := onDemand.RepoStatus(onDemandRepo)
			So(found, ShouldBeFalse)
		})

		Convey("SweepNow reports a sweep the scheduler will not run", func() {
			onDemand := gc.NewGarbageCollect(imgStore, metaDB, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			sch.RunScheduler()
			sch.Shutdown()

			So(onDemand.SweepNow(), ShouldEqual, zerr.ErrGCNotScheduled)

			// the rejected request does not leave the sweep reported as running
			So(onDemand.Status().Running, ShouldBeFalse)
		})
	})
}

var errIndexUnavailable = errors.New("index unavailable")

// blockingStore is an image store with a single repository, whose GC blocks until released and
// then fails, and which counts how many times the repository was collected.
type blockingStore struct {
	mocks.MockedImageStore

	release     chan struct{}
	releaseOnce sync.Once
	started     chan struct{}
	cleaned     *atomic.Int64
}

// unblock lets GC of the repository finish. It is safe to call more than once.
func (store *blockingStore) unblock() {
	store.releaseOnce.Do(func() { close(store.release) })
}

func newBlockingStore() *blockingStore {
	store := &blockingStore{
		release: make(chan struct{}),
		started: make(chan struct{}, 10),
		cleaned: &atomic.Int64{},
	}

	store.MockedImageStore = mocks.MockedImageStore{
		RootDirFn: func() string { return "/mock" },
		GetNextRepositoryFn: func(processedRepos map[string]struct{}) (string, error) {
			if _, ok := processedRepos[onDemandRepo]; ok {
				return "", nil
			}

			return onDemandRepo, nil
		},
		// CleanRepo reads the repository index first
		GetIndexContentFn: func(repo string) ([]byte, error) {
			store.cleaned.Add(1)
			store.started <- struct{}{}
			<-store.release

			return nil, errIndexUnavailable
		},
	}

	return store
}

func TestGarbageCollectOnDemandConcurrency(t *testing.T) {
	Convey("On-demand GC while GC is running", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		opts := gc.Options{Delay: time.Millisecond, MaxSchedulerDelay: 10 * time.Millisecond}

		store := newBlockingStore()
		sch := scheduler.NewScheduler(config.New(), metrics, log)

		Convey("a repository can't be collected twice at the same time, and errors are reported", func() {
			windowOpts := opts
			windowOpts.TimeWindow = timeWindowExcludingNow() // keep the periodic sweep out of the way

			onDemand := gc.NewGarbageCollect(store, nil, windowOpts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			sch.RunScheduler()
			defer sch.Shutdown()
			// runs before the scheduler shutdown, so a failed assertion can't leave GC blocked
			defer store.unblock()

			So(onDemand.CleanRepoNow(onDemandRepo), ShouldBeNil)
			<-store.started

			status, found := onDemand.RepoStatus(onDemandRepo)
			So(found, ShouldBeTrue)
			So(status.Running, ShouldBeTrue)

			So(onDemand.CleanRepoNow(onDemandRepo), ShouldEqual, zerr.ErrGCAlreadyRunning)

			store.unblock()

			So(waitFor(func() bool {
				status, _ := onDemand.RepoStatus(onDemandRepo)

				return !status.Running
			}), ShouldBeTrue)

			status, _ = onDemand.RepoStatus(onDemandRepo)
			So(status.Error, ShouldContainSubstring, errIndexUnavailable.Error())
			So(status.FinishedAt.IsZero(), ShouldBeFalse)
			So(store.cleaned.Load(), ShouldEqual, 1)

			// once finished, it can be requested again
			So(onDemand.CleanRepoNow(onDemandRepo), ShouldBeNil)
		})

		Convey("a sweep can't be requested while a sweep is running, and errors are reported", func() {
			onDemand := gc.NewGarbageCollect(store, nil, opts, nil, log, metrics).
				CleanImageStorePeriodically(time.Hour, sch)

			sch.RunScheduler()
			defer sch.Shutdown()
			// runs before the scheduler shutdown, so a failed assertion can't leave GC blocked
			defer store.unblock()

			// the first periodic sweep starts right away, and blocks on the only repository
			<-store.started
			So(onDemand.Status().Running, ShouldBeTrue)

			// give the generator time to hand out all repositories, while the last one is still being collected
			time.Sleep(200 * time.Millisecond)

			So(onDemand.SweepNow(), ShouldEqual, zerr.ErrGCAlreadyRunning)

			store.unblock()

			So(waitFor(func() bool { return !onDemand.Status().Running }), ShouldBeTrue)
			So(onDemand.Status().Error, ShouldContainSubstring, errIndexUnavailable.Error())

			// no second sweep ran
			time.Sleep(500 * time.Millisecond)
			So(store.cleaned.Load(), ShouldEqual, 1)
		})
	})
}

func uploadOrphanBlob(imgStore storageTypes.ImageStore) godigest.Digest {
	content := []byte(fmt.Sprintf("orphan blob %d", time.Now().UnixNano()))
	digest := godigest.FromBytes(content)

	_, _, err := imgStore.FullBlobUpload(context.Background(), onDemandRepo, bytes.NewReader(content), digest)
	So(err, ShouldBeNil)
	So(blobExists(imgStore, digest), ShouldBeTrue)

	return digest
}

func blobExists(imgStore storageTypes.ImageStore, digest godigest.Digest) bool {
	found, _, _ := imgStore.CheckBlob(context.Background(), onDemandRepo, digest)

	return found
}

// timeWindowExcludingNow returns a one-minute GC time window twelve hours away from now.
func timeWindowExcludingNow() config.GCTimeWindow {
	start := time.Now().UTC().Add(12 * time.Hour)
	end := start.Add(time.Minute)

	var window config.GCTimeWindow

	err := json.Unmarshal([]byte(fmt.Sprintf(`"%s-%s"`, start.Format("15:04"), end.Format("15:04"))), &window)
	So(err, ShouldBeNil)
	So(window.Contains(time.Now()), ShouldBeFalse)

	return window
}

func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		if cond() {
			return true
		}

		time.Sleep(10 * time.Millisecond)
	}

	return cond()
}

func TestGarbageCollectOnDemandListError(t *testing.T) {
	Convey("A sweep which can't list repositories reports the error, and finishes once it can", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		opts := gc.Options{Delay: time.Millisecond, MaxSchedulerDelay: 10 * time.Millisecond}

		var failing atomic.Bool

		failing.Store(true)

		store := mocks.MockedImageStore{
			RootDirFn: func() string { return "/mock" },
			GetNextRepositoryFn: func(processedRepos map[string]struct{}) (string, error) {
				if failing.Load() {
					return "", errIndexUnavailable
				}

				return "", nil
			},
		}

		sch := scheduler.NewScheduler(config.New(), metrics, log)

		onDemand := gc.NewGarbageCollect(store, nil, opts, nil, log, metrics).
			CleanImageStorePeriodically(time.Hour, sch)

		sch.RunScheduler()
		defer sch.Shutdown()

		So(waitFor(func() bool { return onDemand.Status().Error != "" }), ShouldBeTrue)

		status := onDemand.Status()
		So(status.Running, ShouldBeTrue)
		So(status.Error, ShouldContainSubstring, errIndexUnavailable.Error())

		failing.Store(false)

		So(waitFor(func() bool { return !onDemand.Status().Running }), ShouldBeTrue)
	})
}
