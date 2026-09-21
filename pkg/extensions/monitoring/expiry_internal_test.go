//go:build metrics

package monitoring

import (
	"fmt"
	"math/rand"
	"sync"
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
		// Tracking is off until a deployment actually configures repoLabelExpiry; this
		// test exercises the sweep, so turn it on (idempotent, safe to call repeatedly).
		EnableRepoLabelExpiryTracking()

		logger := log.NewTestLogger()
		metricsServer := NewMetricsServer(true, logger)

		repoA := uniqueExpiryRepo("repoA")
		repoB := uniqueExpiryRepo("repoB")

		touchExpiryRepo(metricsServer, repoA, 3*time.Millisecond)
		touchExpiryRepo(metricsServer, repoB, 3*time.Millisecond)

		// end of interval N: both repos were touched during N, neither should be evicted yet
		ExpireRepoMetrics(metricsServer)

		So(repoSeries(uploadsMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(downloadsMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(latencyMetricName, repoA), ShouldNotBeNil)
		So(repoSeries(uploadsMetricName, repoB), ShouldNotBeNil)
		So(repoSeries(downloadsMetricName, repoB), ShouldNotBeNil)
		So(repoSeries(latencyMetricName, repoB), ShouldNotBeNil)

		// touch only repoA during interval N+1
		touchExpiryRepo(metricsServer, repoA, 3*time.Millisecond)

		// end of interval N+1: repoB was untouched during N+1, so it is evicted now.
		ExpireRepoMetrics(metricsServer)

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
		EnableRepoLabelExpiryTracking()

		logger := log.NewTestLogger()
		metricsServer := NewMetricsServer(true, logger)

		repo := uniqueExpiryRepo("grace")

		touchExpiryRepo(metricsServer, repo, time.Millisecond)

		// end of interval N: touched during N, must survive this sweep
		ExpireRepoMetrics(metricsServer)
		So(repoSeries(uploadsMetricName, repo), ShouldNotBeNil)

		Convey("and is only evicted at the sweep ending the following interval if untouched", func() {
			// interval N+1: repo not touched at all
			ExpireRepoMetrics(metricsServer)
			So(repoSeries(uploadsMetricName, repo), ShouldBeNil)
			So(repoSeries(downloadsMetricName, repo), ShouldBeNil)
			So(repoSeries(latencyMetricName, repo), ShouldBeNil)
		})

		Convey("but survives another sweep if touched again during the following interval", func() {
			touchExpiryRepo(metricsServer, repo, time.Millisecond)

			// end of interval N+1: touched during N+1, must survive this sweep too
			ExpireRepoMetrics(metricsServer)
			So(repoSeries(uploadsMetricName, repo), ShouldNotBeNil)
		})
	})
}

// Deterministic, isolated from any global/test-ordering state: touchAndObserve takes
// its tracking decision as an explicit argument, so this exercises the disabled path
// directly on a fresh tracker rather than depending on the package-level flag.
func TestTouchAndObserveDisabledSkipsTracking(t *testing.T) {
	Convey("With tracking disabled, touchAndObserve runs observe but never writes to current", t, func() {
		tracker := &repoLabelTracker{current: map[string]struct{}{}, previous: map[string]struct{}{}}

		observed := 0
		for i := 0; i < 100; i++ {
			tracker.touchAndObserve(false, fmt.Sprintf("repo-%d", i), func() {
				observed++
			})
		}

		So(observed, ShouldEqual, 100)
		So(len(tracker.current), ShouldEqual, 0)
	})

	Convey("With tracking enabled, the same repo is recorded in current", t, func() {
		tracker := &repoLabelTracker{current: map[string]struct{}{}, previous: map[string]struct{}{}}

		tracker.touchAndObserve(true, "repo-x", func() {})

		So(len(tracker.current), ShouldEqual, 1)
	})
}

func TestExpireRepoMetricsBlastRadius(t *testing.T) {
	Convey("Expiry only touches the three repo-labeled vecs, nothing else", t, func() {
		EnableRepoLabelExpiryTracking()

		logger := log.NewTestLogger()
		metricsServer := NewMetricsServer(true, logger)

		repo := uniqueExpiryRepo("blast")

		touchExpiryRepo(metricsServer, repo, time.Millisecond)

		// end of interval N: survives
		ExpireRepoMetrics(metricsServer)

		// values on unrelated metrics that happen to share the repo's label value,
		// set directly since they are not driven by ExpireRepoMetrics' mark-and-sweep.
		repoStorageBytes.WithLabelValues(repo).Set(1234)
		httpConnRequests.WithLabelValues(repo, "200").Inc()

		// interval N+1: repo untouched, so it is evicted from the three tracked vecs only.
		ExpireRepoMetrics(metricsServer)

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

// Regression test for a race where sweep() released its lock before DeleteLabelValues
// ran, letting a concurrent touch land in between and get wiped anyway. Lockstepped via
// channels so every touch happens-before the next sweep (deterministic, run with -race).
func TestExpireRepoMetricsConcurrentTouchNeverLosesUpdates(t *testing.T) {
	Convey("A repo touched immediately before every sweep is never evicted or zeroed", t, func() {
		EnableRepoLabelExpiryTracking()

		logger := log.NewTestLogger()
		metricsServer := NewMetricsServer(true, logger)

		repo := uniqueExpiryRepo("race")

		const rounds = 500

		touched := make(chan struct{})
		swept := make(chan struct{})

		var wg sync.WaitGroup

		wg.Add(2)

		go func() {
			defer wg.Done()
			defer close(touched)

			for i := 0; i < rounds; i++ {
				IncUploadCounter(metricsServer, repo)
				touched <- struct{}{}
				<-swept
			}
		}()

		go func() {
			defer wg.Done()
			defer close(swept)

			for range touched {
				ExpireRepoMetrics(metricsServer)
				swept <- struct{}{}
			}
		}()

		wg.Wait()

		metric := repoSeries(uploadsMetricName, repo)
		So(metric, ShouldNotBeNil)
		So(metric.GetCounter().GetValue(), ShouldEqual, rounds)
	})
}

func touchExpiryRepo(metricsServer MetricServer, repo string, latency time.Duration) {
	IncUploadCounter(metricsServer, repo)
	IncDownloadCounter(metricsServer, repo)
	ObserveHTTPRepoLatency(metricsServer, fmt.Sprintf("/v2/%s/blobs/uploads/expiry-test-uuid", repo), latency)
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

// BenchmarkIncUploadCounter measures the hot request path with tracking enabled (this
// reflects a deployment that has repoLabelExpiry configured). See
// BenchmarkTouchAndObserveDisabled/Enabled below for the isolated with/without-the-flag
// comparison, benchmarked directly against a local tracker instead of the global one.
func BenchmarkIncUploadCounter(b *testing.B) {
	EnableRepoLabelExpiryTracking()

	logger := log.NewTestLogger()
	metricsServer := NewMetricsServer(true, logger)
	repo := uniqueExpiryRepo("bench-inc")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		IncUploadCounter(metricsServer, repo)
	}
}

// BenchmarkIncUploadCounterParallel measures the same hot path under concurrent callers,
// since touchAndObserve serializes all writers on t.mu regardless of label value.
func BenchmarkIncUploadCounterParallel(b *testing.B) {
	EnableRepoLabelExpiryTracking()

	logger := log.NewTestLogger()
	metricsServer := NewMetricsServer(true, logger)
	repo := uniqueExpiryRepo("bench-inc-parallel")

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			IncUploadCounter(metricsServer, repo)
		}
	})
}

// BenchmarkTouchAndObserveDisabled/Enabled isolate exactly what the feature flag costs:
// same call, same repo, only the tracking bool differs. Uses a fresh local tracker so
// the result doesn't depend on the global flag's state.
func BenchmarkTouchAndObserveDisabled(b *testing.B) {
	tracker := &repoLabelTracker{current: map[string]struct{}{}, previous: map[string]struct{}{}}
	repo := "bench-repo"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.touchAndObserve(false, repo, func() {})
	}
}

func BenchmarkTouchAndObserveEnabled(b *testing.B) {
	tracker := &repoLabelTracker{current: map[string]struct{}{}, previous: map[string]struct{}{}}
	repo := "bench-repo"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.touchAndObserve(true, repo, func() {})
	}
}

// BenchmarkExpireRepoMetrics measures one sweep's cost at a realistic cardinality
// (1000 distinct repos, half stale) to quantify the eviction pass itself, separate from
// the per-request touch cost measured above.
func BenchmarkExpireRepoMetrics(b *testing.B) {
	EnableRepoLabelExpiryTracking()

	logger := log.NewTestLogger()
	metricsServer := NewMetricsServer(true, logger)

	const repoCount = 1000

	repos := make([]string, repoCount)

	for i := range repos {
		repos[i] = uniqueExpiryRepo(fmt.Sprintf("bench-expire-%d", i))
		IncUploadCounter(metricsServer, repos[i])
	}

	// age every repo out of the "current" generation once, then re-touch half of them
	// so each benchmark iteration has a realistic 50% stale ratio to evict.
	ExpireRepoMetrics(metricsServer)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < repoCount; j += 2 {
			IncUploadCounter(metricsServer, repos[j])
		}

		ExpireRepoMetrics(metricsServer)
	}
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
