//go:build !metrics

package gc

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type cleanupLockStore struct {
	mocks.MockedImageStore
	lockDelay time.Duration
	lockErr   error
}

// indexReads makes GetIndexContent succeed for the unlocked scan and fail, after a delay, for
// the read the commit makes under the cleanup lock.
func indexReads(err error) func(string) ([]byte, error) {
	var calls atomic.Int32

	return func(string) ([]byte, error) {
		if calls.Add(1) == 1 {
			return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
		}

		time.Sleep(15 * time.Millisecond)

		return nil, err
	}
}

func (s cleanupLockStore) WithRepoCleanupLock(_ string, wrappedFunc func() error) error {
	time.Sleep(s.lockDelay)

	if s.lockErr != nil {
		return s.lockErr
	}

	return wrappedFunc()
}

func cleanRepoTime(metrics monitoring.MetricServer, part string) (int, float64) {
	metricsCopy, ok := metrics.ReceiveMetrics().(monitoring.MetricsCopy)
	if !ok {
		return 0, 0
	}

	for _, histogram := range metricsCopy.Histograms {
		if histogram.Name == "zot.storage.operation.time.seconds" &&
			slices.Equal(histogram.LabelValues, []string{storageConstants.StorageOpCleanRepo, part}) {
			return histogram.Count, histogram.Sum
		}
	}

	return 0, 0
}

func TestCleanRepoOperationTime(t *testing.T) {
	Convey("CleanRepo records how long it waited for and held the cleanup lock", t, func() {
		log := zlog.NewTestLogger()
		indexErr := errors.New("index read failed") //nolint:err113 // test

		store := cleanupLockStore{lockDelay: 20 * time.Millisecond}
		store.RootDirFn = func() string { return "/store" }
		store.GetIndexContentFn = indexReads(indexErr)

		Convey("the wait and the hold are recorded separately", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			gc := NewGarbageCollect(store, nil, Options{}, &log, log, metrics)

			err := gc.CleanRepo(context.Background(), "repo")
			So(errors.Is(err, indexErr), ShouldBeTrue)

			waitCount, waitSum := cleanRepoTime(metrics, storageConstants.StoragePartLockWait)
			So(waitCount, ShouldEqual, 1)
			So(waitSum, ShouldBeGreaterThanOrEqualTo, 0.02)

			holdCount, holdSum := cleanRepoTime(metrics, storageConstants.StoragePartLockHold)
			So(holdCount, ShouldEqual, 1)
			So(holdSum, ShouldBeGreaterThanOrEqualTo, 0.015)
		})

		Convey("a lock that was never acquired records neither part", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			lockErr := errors.New("lock unavailable") //nolint:err113 // test
			store.lockErr = lockErr

			gc := NewGarbageCollect(store, nil, Options{}, &log, log, metrics)

			err := gc.CleanRepo(context.Background(), "repo")
			So(errors.Is(err, lockErr), ShouldBeTrue)

			waitCount, _ := cleanRepoTime(metrics, storageConstants.StoragePartLockWait)
			So(waitCount, ShouldEqual, 0)

			holdCount, _ := cleanRepoTime(metrics, storageConstants.StoragePartLockHold)
			So(holdCount, ShouldEqual, 0)
		})
	})
}
