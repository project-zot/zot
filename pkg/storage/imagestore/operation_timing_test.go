//go:build !metrics

package imagestore_test

import (
	"bytes"
	"context"
	"slices"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

const storageOperationTimeMetric = "zot.storage.operation.time.seconds"

// operationTimeCount returns how many times part of operation was recorded.
func operationTimeCount(metrics monitoring.MetricServer, operation, part string) int {
	metricsCopy, ok := metrics.ReceiveMetrics().(monitoring.MetricsCopy)
	if !ok {
		return 0
	}

	for _, histogram := range metricsCopy.Histograms {
		if histogram.Name == storageOperationTimeMetric &&
			slices.Equal(histogram.LabelValues, []string{operation, part}) {
			return histogram.Count
		}
	}

	return 0
}

func blobCheckParts(metrics monitoring.MetricServer) map[string]int {
	parts := map[string]int{}

	metricsCopy, ok := metrics.ReceiveMetrics().(monitoring.MetricsCopy)
	if !ok {
		return parts
	}

	for _, histogram := range metricsCopy.Histograms {
		if histogram.Name == storageOperationTimeMetric &&
			histogram.LabelValues[0] == storageConstants.StorageOpCheckBlob {
			parts[histogram.LabelValues[1]] = histogram.Count
		}
	}

	return parts
}

func TestCheckBlobOperationTime(t *testing.T) {
	Convey("CheckBlob records the time of each part that ran", t, func() {
		ctx := context.Background()
		log := zlog.NewTestLogger()
		content := []byte("operation-time-blob")
		digest := godigest.FromBytes(content)

		Convey("a present blob without dedupe runs stat and the descriptor lookup", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			So(blobCheckParts(metrics), ShouldResemble, map[string]int{
				storageConstants.StoragePartLockWait:         1,
				storageConstants.StoragePartLockHold:         1,
				storageConstants.StoragePartStat:             1,
				storageConstants.StoragePartDescriptorLookup: 1,
			})
		})

		Convey("a known size skips the descriptor lookup", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlobWithSize(ctx, "repo", digest, int64(len(content)))
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			So(blobCheckParts(metrics), ShouldResemble, map[string]int{
				storageConstants.StoragePartLockWait: 1,
				storageConstants.StoragePartLockHold: 1,
				storageConstants.StoragePartStat:     1,
			})
		})

		Convey("a missing blob looks in the cache and stops", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			found, _, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldNotBeNil)
			So(found, ShouldBeFalse)

			So(blobCheckParts(metrics), ShouldResemble, map[string]int{
				storageConstants.StoragePartLockWait:    1,
				storageConstants.StoragePartLockHold:    1,
				storageConstants.StoragePartStat:        1,
				storageConstants.StoragePartCacheLookup: 1,
			})
		})

		Convey("a dedupe hit in another repository copies the blob and updates the cache", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			dir := t.TempDir()

			cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)
			So(err, ShouldBeNil)

			imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)
			So(imgStore.InitRepo(ctx, "repo1"), ShouldBeNil)

			_, _, err = imgStore.FullBlobUpload(ctx, "repo1", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, size, err := imgStore.CheckBlob(ctx, "repo2", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, len(content))

			So(blobCheckParts(metrics), ShouldResemble, map[string]int{
				storageConstants.StoragePartLockWait:    1,
				storageConstants.StoragePartLockHold:    1,
				storageConstants.StoragePartStat:        1,
				storageConstants.StoragePartCacheLookup: 1,
				storageConstants.StoragePartCopy:        1,
				storageConstants.StoragePartCacheUpdate: 1,
			})
		})

		Convey("an invalid digest is rejected before anything is measured", func() {
			metrics := monitoring.NewMetricsServer(true, log)
			defer metrics.Stop()

			imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)

			_, _, err := imgStore.CheckBlob(ctx, "repo", godigest.Digest("invalid"))
			So(err, ShouldNotBeNil)

			So(blobCheckParts(metrics), ShouldBeEmpty)
		})

		Convey("nothing is recorded when metrics are disabled", func() {
			metrics := monitoring.NewMetricsServer(false, log)
			defer metrics.Stop()

			imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)
			So(imgStore.InitRepo(ctx, "repo"), ShouldBeNil)

			_, _, err := imgStore.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
			So(err, ShouldBeNil)

			found, _, err := imgStore.CheckBlob(ctx, "repo", digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)

			So(blobCheckParts(metrics), ShouldBeEmpty)
		})
	})
}

func TestGetNextRepositoryOperationTime(t *testing.T) {
	// GetNextRepository takes no store lock (a listing of every repo cannot be atomic
	// across repos), so it must not wait behind the blobstore lock or report lock time.
	Convey("GetNextRepository neither waits for the blobstore lock nor records lock time", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(true, log)
		defer metrics.Stop()

		imgStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil, nil, nil)
		So(imgStore.InitRepo(context.Background(), "repo"), ShouldBeNil)

		held := make(chan struct{})
		release := make(chan struct{})
		released := make(chan struct{})

		go func() {
			defer close(released)

			_ = imgStore.WithBlobstoreLock(func() error {
				close(held)
				<-release

				return nil
			})
		}()

		<-held

		repo, err := imgStore.GetNextRepository(map[string]struct{}{"done": {}})

		close(release)
		<-released

		So(err, ShouldBeNil)
		So(repo, ShouldEqual, "repo")

		waitCount := operationTimeCount(metrics,
			storageConstants.StorageOpGetNextRepository, storageConstants.StoragePartLockWait)
		So(waitCount, ShouldEqual, 0)

		holdCount := operationTimeCount(metrics,
			storageConstants.StorageOpGetNextRepository, storageConstants.StoragePartLockHold)
		So(holdCount, ShouldEqual, 0)
	})
}
