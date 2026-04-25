//go:build !metrics

package gc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func counterValue(metrics monitoring.MetricsCopy, name string, labelValues ...string) int {
	for _, counter := range metrics.Counters {
		if counter.Name == name && metricLabelsMatch(counter.LabelValues, labelValues) {
			return counter.Count
		}
	}

	return 0
}

func summaryValue(metrics monitoring.MetricsCopy, name string) monitoring.SummaryValue {
	for _, summary := range metrics.Summaries {
		if summary.Name == name {
			return summary
		}
	}

	return monitoring.SummaryValue{}
}

func metricLabelsMatch(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}

	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}

	return true
}

func TestGarbageCollectMetrics(t *testing.T) {
	Convey("Garbage collection records run, duration, and deletion metrics", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(true, log)
		defer metrics.Stop()

		repo := "repo"
		manifestDigest := godigest.FromString("manifest")
		orphanDigest := godigest.FromString("orphan")
		configDigest := godigest.FromString("config")
		deleteUntagged := true

		storedIndex := ispec.Index{
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    manifestDigest,
				},
			},
		}
		manifestContent, err := json.Marshal(ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				Digest: configDigest,
			},
		})
		So(err, ShouldBeNil)

		imgStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return json.Marshal(storedIndex)
			},
			PutIndexContentFn: func(repo string, index ispec.Index) error {
				storedIndex = index

				return nil
			},
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				So(digest, ShouldEqual, manifestDigest)

				return manifestContent, nil
			},
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				return true, 1, time.Now().Add(-2 * time.Hour), nil
			},
			GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
				return []godigest.Digest{manifestDigest, orphanDigest}, nil
			},
			CleanupRepoFn: func(repo string, blobs []godigest.Digest, removeRepo bool) (int, error) {
				So(blobs, ShouldHaveLength, 2)
				So(removeRepo, ShouldBeTrue)

				return len(blobs), nil
			},
			ListBlobUploadsFn: func(repo string) ([]string, error) {
				return []string{"upload-1", "upload-2"}, nil
			},
			StatBlobUploadFn: func(repo, uuid string) (bool, int64, time.Time, error) {
				return true, 1, time.Now().Add(-2 * time.Hour), nil
			},
		}

		garbageCollect := NewGarbageCollect(imgStore, nil, Options{
			Delay:   time.Hour,
			Metrics: metrics,
			ImageRetention: config.ImageRetention{
				Delay: storageConstants.DefaultGCDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &deleteUntagged,
					},
				},
			},
		}, nil, log)

		err = garbageCollect.CleanRepo(context.Background(), repo)
		So(err, ShouldBeNil)

		metricsCopy := metrics.ReceiveMetrics().(monitoring.MetricsCopy)
		So(counterValue(metricsCopy, "zot.gc.runs", "false"), ShouldEqual, 1)
		So(counterValue(metricsCopy, "zot.gc.deleted", "manifest"), ShouldEqual, 1)
		So(counterValue(metricsCopy, "zot.gc.deleted", "blob"), ShouldEqual, 2)
		So(counterValue(metricsCopy, "zot.gc.deleted", "upload"), ShouldEqual, 2)

		summary := summaryValue(metricsCopy, "zot.gc.duration.seconds")
		So(summary.Count, ShouldEqual, 1)
		So(summary.Sum, ShouldBeGreaterThanOrEqualTo, 0)
	})

	Convey("Failed garbage collection records an errored run", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(true, log)
		defer metrics.Stop()

		imgStore := mocks.MockedImageStore{
			DirExistsFn: func(d string) bool {
				return false
			},
		}
		garbageCollect := NewGarbageCollect(imgStore, nil, Options{
			Delay:   time.Hour,
			Metrics: metrics,
		}, nil, log)

		err := garbageCollect.CleanRepo(context.Background(), "repo")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)

		metricsCopy := metrics.ReceiveMetrics().(monitoring.MetricsCopy)
		So(counterValue(metricsCopy, "zot.gc.runs", "true"), ShouldEqual, 1)

		summary := summaryValue(metricsCopy, "zot.gc.duration.seconds")
		So(summary.Count, ShouldEqual, 1)
		So(summary.Sum, ShouldBeGreaterThanOrEqualTo, 0)
	})
}
