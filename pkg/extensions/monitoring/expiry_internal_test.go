//go:build metrics

package monitoring

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	uploadsMetricName   = "zot_repo_uploads_total"
	downloadsMetricName = "zot_repo_downloads_total"
	latencyMetricName   = "zot_http_repo_latency_seconds"
	storageMetricName   = "zot_repo_storage_bytes"
	connMetricName      = "zot_http_requests_total"
)

func TestExpireRepoMetricsMarkAndSweep(t *testing.T) {
	Convey("Repo touched again survives while an untouched repo is evicted, without zeroing survivors", t, func() {
		logger := log.NewTestLogger()
		ms := NewMetricsServer(true, logger)

		repoA := uniqueExpiryRepo("repoA")
		repoB := uniqueExpiryRepo("repoB")

		touchExpiryRepo(ms, repoA, 3*time.Millisecond)
		touchExpiryRepo(ms, repoB, 3*time.Millisecond)

		// end of interval N: both repos were touched during N, neither should be evicted yet
		ExpireRepoMetrics(ms)

		So(repoSeries(uploadsMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(downloadsMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(latencyMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(uploadsMetricName, repoB), ShouldNotBeNil)
		So(repoSeries(downloadsMetricName, repoB), ShouldNotBeNil)
		So(repoSeries(latencyMetricName, repoB), ShouldNotBeNil)

		// touch only repoA during interval N+1
		touchExpiryRepo(ms, repoA, 3*time.Millisecond)

		// end of interval N+1: repoB was untouched during N+1, so it is evicted now.
		ExpireRepoMetrics(ms)

		So(repoSeries(uploadsMetricName, repoB), ShouldBeNil)
		So(repoSeries(downloadsMetricName, repoB), ShouldBeNil)
		So(repoSeries(latencyMetricName, repoB), ShouldBeNil)

		uploadMetric := repoSeries(uploadsMetricName, repoA)
		So(uploadMetric, ShouldNotBeNil)
		So(uploadMetric.GetCounter().GetValue(), ShouldEqual, 2)

		downloadMetric := repoSeries(downloadsMetricName, repoA)
		So(downloadMetric, ShouldNotBeNil)
		So(downloadMetric.GetCounter().GetValue(), ShouldEqual, 2)

		latencyMetric := repoSeries(latencyMetricName, repoA)
		So(latencyMetric, ShouldNotBeNil)
		// A full Reset() of the summary would have wrongly zeroed the sample count for
		// a survivor; DeleteLabelValues on the stale repo only must leave this at 2.
		So(latencyMetric.GetSummary().GetSampleCount(), ShouldEqual, 2)
	})
}

func TestExpireRepoMetricsGraceWindow(t *testing.T) {
	Convey("A repo survives the sweep ending the interval it was touched in", t, func() {
		logger := log.NewTestLogger()
		ms := NewMetricsServer(true, logger)

		repo := uniqueExpiryRepo("grace")

		touchExpiryRepo(ms, repo, time.Millisecond)

		// end of interval N: touched during N, must survive this sweep
		ExpireRepoMetrics(ms)
		So(repoSeries(uploadsMetricName, repo), ShouldNotBeNil)

		Convey("and is only evicted at the sweep ending the following interval if untouched", func() {
			// interval N+1: repo not touched at all
			ExpireRepoMetrics(ms)
			So(repoSeries(uploadsMetricName, repo), ShouldBeNil)
			So(repoSeries(downloadsMetricName, repo), ShouldBeNil)
			So(repoSeries(latencyMetricName, repo), ShouldBeNil)
		})

		Convey("but survives another sweep if touched again during the following interval", func() {
			touchExpiryRepo(ms, repo, time.Millisecond)

			// end of interval N+1: touched during N+1, must survive this sweep too
			ExpireRepoMetrics(ms)
			So(repoSeries(uploadsMetricName, repo), ShouldNotBeNil)
		})
	})
}

func TestExpireRepoMetricsBlastRadius(t *testing.T) {
	Convey("Expiry only touches the three repo-labeled vecs, nothing else", t, func() {
		logger := log.NewTestLogger()
		ms := NewMetricsServer(true, logger)

		repo := uniqueExpiryRepo("blast")

		touchExpiryRepo(ms, repo, time.Millisecond)

		// end of interval N: survives
		ExpireRepoMetrics(ms)

		// values on unrelated metrics that happen to share the repo's label value,
		// set directly since they are not driven by ExpireRepoMetrics' mark-and-sweep.
		repoStorageBytes.WithLabelValues(repo).Set(1234)
		httpConnRequests.WithLabelValues(repo, "200").Inc()

		// interval N+1: repo untouched, so it is evicted from the three tracked vecs only.
		ExpireRepoMetrics(ms)

		So(repoSeries(uploadsMetricName, repo), ShouldBeNil)
		So(repoSeries(downloadsMetricName, repo), ShouldBeNil)
		So(repoSeries(latencyMetricName, repo), ShouldBeNil)

		storageMetric := findMetricByLabels(storageMetricName, map[string]string{"repo": repo})
		So(storageMetric, ShouldNotBeNil)
		So(storageMetric.GetGauge().GetValue(), ShouldEqual, 1234)

		connMetric := findMetricByLabels(connMetricName, map[string]string{"method": repo, "code": "200"})
		So(connMetric, ShouldNotBeNil)
		So(connMetric.GetCounter().GetValue(), ShouldEqual, 1)
	})
}

func touchExpiryRepo(ms MetricServer, repo string, latency time.Duration) {
	IncUploadCounter(ms, repo)
	IncDownloadCounter(ms, repo)
	ObserveHTTPRepoLatency(ms, fmt.Sprintf("/v2/%s/blobs/uploads/expiry-test-uuid", repo), latency)
}

func repoSeries(metricName, repo string) *dto.Metric {
	return findMetricByLabels(metricName, map[string]string{"repo": repo})
}

func findMetricByLabels(name string, want map[string]string) *dto.Metric {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric.GetLabel(), want) {
				return metric
			}
		}
	}

	return nil
}

func metricLabelsMatch(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(pairs) != len(want) {
		return false
	}

	for _, pair := range pairs {
		value, ok := want[pair.GetName()]
		if !ok || pair.GetValue() != value {
			return false
		}
	}

	return true
}

func uniqueExpiryRepo(prefix string) string {
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz"

	suffix := make([]byte, 8)
	for i := range suffix {
		suffix[i] = charset[seededRand.Intn(len(charset))]
	}

	return fmt.Sprintf("expirytest-%s-%s", prefix, string(suffix))
}
