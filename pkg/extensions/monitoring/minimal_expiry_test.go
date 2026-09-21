//go:build !metrics

package monitoring_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestExpireRepoMetricsMinimalMarkAndSweep(t *testing.T) {
	Convey("Mark-and-sweep drops the stale repo, keeps the active one and unrelated metrics", t, func() {
		// Tracking is off until a deployment actually configures repoLabelExpiry; this
		// test exercises the sweep, so turn it on (idempotent, safe to call repeatedly).
		monitoring.EnableRepoLabelExpiryTracking()

		logger := log.NewTestLogger()
		metricsServer := monitoring.NewMetricsServer(true, logger)
		Reset(metricsServer.Stop)

		repoA := uniqueMetricLabel("expirytest-repoA")
		repoB := uniqueMetricLabel("expirytest-repoB")

		rootDir := t.TempDir()
		makeRepoDir(t, rootDir, repoA)
		makeRepoDir(t, rootDir, repoB)

		monitoring.SetStorageUsage(metricsServer, rootDir, repoA)
		monitoring.SetStorageUsage(metricsServer, rootDir, repoB)

		method := uniqueMetricLabel("method")
		monitoring.IncHTTPConnRequests(metricsServer, method, "200")

		touchMinimalRepo(metricsServer, repoA)
		touchMinimalRepo(metricsServer, repoB)

		// end of interval N: both touched during N, neither evicted yet
		monitoring.ExpireRepoMetrics(metricsServer)

		So(minimalCounter(metricsServer, "zot.repo.uploads", []string{repoA}), ShouldEqual, 1)
		So(minimalCounter(metricsServer, "zot.repo.uploads", []string{repoB}), ShouldEqual, 1)

		// touch only repoA during interval N+1
		touchMinimalRepo(metricsServer, repoA)

		// end of interval N+1: repoB untouched during N+1, evicted now
		monitoring.ExpireRepoMetrics(metricsServer)

		copyAfter := receiveCopy(metricsServer)

		So(minimalCounterPresent(copyAfter, "zot.repo.uploads", []string{repoB}), ShouldBeFalse)
		So(minimalCounterPresent(copyAfter, "zot.repo.downloads", []string{repoB}), ShouldBeFalse)
		So(minimalSummaryPresent(copyAfter, "zot.http.repo.latency.seconds", []string{repoB}), ShouldBeFalse)

		So(minimalCounter(metricsServer, "zot.repo.uploads", []string{repoA}), ShouldEqual, 2)
		So(minimalCounter(metricsServer, "zot.repo.downloads", []string{repoA}), ShouldEqual, 2)

		summaryCount, found := minimalSummaryCount(copyAfter, "zot.http.repo.latency.seconds", []string{repoA})
		So(found, ShouldBeTrue)
		So(summaryCount, ShouldEqual, 2)

		// unrelated metric untouched by the sweep
		So(minimalCounter(metricsServer, "zot.http.requests", []string{method, "200"}), ShouldEqual, 1)

		// storage bytes gauge is deliberately excluded from expiry, for both the
		// surviving and the just-evicted repo
		storageA, foundA := minimalGauge(metricsServer, "zot.repo.storage.bytes", []string{repoA})
		So(foundA, ShouldBeTrue)
		So(storageA, ShouldBeGreaterThanOrEqualTo, 0)

		storageB, foundB := minimalGauge(metricsServer, "zot.repo.storage.bytes", []string{repoB})
		So(foundB, ShouldBeTrue)
		So(storageB, ShouldBeGreaterThanOrEqualTo, 0)
	})
}

func TestExpireRepoMetricsMinimalAutoDisabled(t *testing.T) {
	Convey("Expiry still runs via ForceSendMetric even when the metrics server is disabled", t, func() {
		logger := log.NewTestLogger()
		metricsServer := monitoring.NewMetricsServer(false, logger)
		Reset(metricsServer.Stop)

		So(metricsServer.IsEnabled(), ShouldBeFalse)

		done := make(chan struct{})

		go func() {
			monitoring.ExpireRepoMetrics(metricsServer)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ExpireRepoMetrics did not return; force-send path appears blocked while disabled")
		}

		// ExpireRepoMetrics must not itself flip the server back to enabled.
		So(metricsServer.IsEnabled(), ShouldBeFalse)
	})
}

func touchMinimalRepo(ms monitoring.MetricServer, repo string) {
	monitoring.IncUploadCounter(ms, repo)
	monitoring.IncDownloadCounter(ms, repo)
	monitoring.ObserveHTTPRepoLatency(ms, fmt.Sprintf("/v2/%s/blobs/uploads/expiry-test-uuid", repo), time.Millisecond)
}

func makeRepoDir(t *testing.T, rootDir, repo string) {
	t.Helper()

	err := os.MkdirAll(filepath.Join(rootDir, repo), 0o755)
	if err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}
}

func minimalCounterPresent(metricsCopy monitoring.MetricsCopy, name string, labelValues []string) bool {
	for _, counter := range metricsCopy.Counters {
		if counter.Name == name && slices.Equal(counter.LabelValues, labelValues) {
			return true
		}
	}

	return false
}

func minimalSummaryPresent(metricsCopy monitoring.MetricsCopy, name string, labelValues []string) bool {
	_, found := minimalSummaryCount(metricsCopy, name, labelValues)

	return found
}

func minimalSummaryCount(metricsCopy monitoring.MetricsCopy, name string, labelValues []string) (int, bool) {
	for _, summary := range metricsCopy.Summaries {
		if summary.Name == name && slices.Equal(summary.LabelValues, labelValues) {
			return summary.Count, true
		}
	}

	return 0, false
}
