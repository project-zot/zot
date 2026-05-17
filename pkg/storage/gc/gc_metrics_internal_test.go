//go:build !metrics

package gc

import (
	"context"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

func TestGCDeletedMetrics(t *testing.T) {
	trueVal := true

	Convey("Given a repo with a kept and a deletable tag", t, func() {
		dir := t.TempDir()

		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(true, log)
		defer metrics.Stop()

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		err := WriteImageToFileSystem(CreateDefaultImage(), repoName, "keep-me",
			storage.StoreController{DefaultStore: imgStore})
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(CreateDefaultImage(), repoName, "delete-me",
			storage.StoreController{DefaultStore: imgStore})
		So(err, ShouldBeNil)

		retentionPolicies := []config.RetentionPolicy{
			{
				Repositories:   []string{"**"},
				DeleteUntagged: &trueVal,
				KeepTags: []config.KeepTagsPolicy{
					{Patterns: []string{"keep-me"}},
				},
			},
		}

		Convey("DryRun should not emit deleted metrics", func() {
			gc := NewGarbageCollect(imgStore, nil, Options{
				Delay: 1 * time.Millisecond,
				ImageRetention: config.ImageRetention{
					Delay:    1 * time.Millisecond,
					DryRun:   true,
					Policies: retentionPolicies,
				},
			}, audit, log, metrics)

			err = gc.CleanRepo(context.Background(), repoName)
			So(err, ShouldBeNil)

			So(gcDeletedCount(metrics, "manifest"), ShouldEqual, 0)
		})

		Convey("Real GC should emit deleted metrics", func() {
			gc := NewGarbageCollect(imgStore, nil, Options{
				Delay: 1 * time.Millisecond,
				ImageRetention: config.ImageRetention{
					Delay:    1 * time.Millisecond,
					Policies: retentionPolicies,
				},
			}, audit, log, metrics)

			err = gc.CleanRepo(context.Background(), repoName)
			So(err, ShouldBeNil)

			So(gcDeletedCount(metrics, "manifest"), ShouldBeGreaterThan, 0)
		})
	})
}

func gcDeletedCount(metrics monitoring.MetricServer, artifactType string) int {
	data := metrics.ReceiveMetrics()

	metricsCopy, ok := data.(monitoring.MetricsCopy)
	if !ok {
		return -1
	}

	for _, counter := range metricsCopy.Counters {
		if counter.Name == "zot.gc.deleted" &&
			len(counter.LabelValues) > 0 && counter.LabelValues[0] == artifactType {
			return counter.Count
		}
	}

	return 0
}
