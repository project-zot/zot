//go:build !metrics

package monitoring_test

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestMetricHelpersUpdateWhenEnabled(t *testing.T) {
	Convey("Metric helpers update the minimal metrics server when active", t, func() {
		logger := log.NewTestLogger()

		Convey("IncDownloadCounter", func() {
			repo := uniqueMetricLabel("download")
			assertMinimalCounterDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.IncDownloadCounter(metricsServer, repo)
			}, "zot.repo.downloads", []string{repo}, 1)
		})

		Convey("IncUploadCounter", func() {
			repo := uniqueMetricLabel("upload")
			assertMinimalCounterDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.IncUploadCounter(metricsServer, repo)
			}, "zot.repo.uploads", []string{repo}, 1)
		})

		Convey("IncHTTPConnRequests", func() {
			code := uniqueMetricLabel("code")
			assertMinimalCounterDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.IncHTTPConnRequests(metricsServer, "GET", code)
			}, "zot.http.requests", []string{"GET", code}, 1)
		})

		Convey("ObserveHTTPMethodLatency", func() {
			method := uniqueMetricLabel("method")
			assertMinimalHistogramCountDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.ObserveHTTPMethodLatency(metricsServer, method, time.Millisecond)
			}, "zot.http.method.latency.seconds", []string{method}, 1)
		})

		Convey("IncGCRuns", func() {
			assertMinimalCounterDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.IncGCRuns(metricsServer, false)
			}, "zot.gc.runs", []string{"false"}, 1)
		})

		Convey("IncGCDeleted", func() {
			artifactType := uniqueMetricLabel("artifact")
			assertMinimalCounterDelta(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.IncGCDeleted(metricsServer, artifactType, 3)
			}, "zot.gc.deleted", []string{artifactType}, 3)
		})

		Convey("SetSchedulerWorkers", func() {
			state := uniqueMetricLabel("state")
			assertMinimalGaugeSet(logger, func(metricsServer monitoring.MetricServer) {
				monitoring.SetSchedulerWorkers(metricsServer, map[string]int{state: 7})
			}, "zot.scheduler.workers", []string{state}, 7)
		})
	})
}

func assertMinimalCounterDelta(logger log.Logger, emit func(monitoring.MetricServer),
	metricName string, labelValues []string, delta int,
) {
	activeMetricsServer := monitoring.NewMetricsServer(true, logger)
	Reset(activeMetricsServer.Stop)

	inactiveMetricsServer := monitoring.NewMetricsServer(false, logger)
	Reset(inactiveMetricsServer.Stop)

	before := minimalCounter(activeMetricsServer, metricName, labelValues)

	emit(inactiveMetricsServer)
	So(minimalCounter(inactiveMetricsServer, metricName, labelValues), ShouldEqual, 0)

	emit(activeMetricsServer)
	So(minimalCounter(activeMetricsServer, metricName, labelValues), ShouldEqual, before+delta)
}

func assertMinimalHistogramCountDelta(logger log.Logger, emit func(monitoring.MetricServer),
	metricName string, labelValues []string, delta int,
) {
	activeMetricsServer := monitoring.NewMetricsServer(true, logger)
	Reset(activeMetricsServer.Stop)

	inactiveMetricsServer := monitoring.NewMetricsServer(false, logger)
	Reset(inactiveMetricsServer.Stop)

	before := minimalHistogramCount(activeMetricsServer, metricName, labelValues)

	emit(inactiveMetricsServer)
	So(minimalHistogramCount(inactiveMetricsServer, metricName, labelValues), ShouldEqual, 0)

	emit(activeMetricsServer)
	So(minimalHistogramCount(activeMetricsServer, metricName, labelValues), ShouldEqual, before+delta)
}

func assertMinimalGaugeSet(logger log.Logger, emit func(monitoring.MetricServer),
	metricName string, labelValues []string, want float64,
) {
	activeMetricsServer := monitoring.NewMetricsServer(true, logger)
	Reset(activeMetricsServer.Stop)

	inactiveMetricsServer := monitoring.NewMetricsServer(false, logger)
	Reset(inactiveMetricsServer.Stop)

	emit(inactiveMetricsServer)
	_, found := minimalGauge(inactiveMetricsServer, metricName, labelValues)
	So(found, ShouldBeFalse)

	emit(activeMetricsServer)

	got, found := minimalGauge(activeMetricsServer, metricName, labelValues)
	So(found, ShouldBeTrue)
	So(got, ShouldEqual, want)
}

func uniqueMetricLabel(prefix string) string {
	return fmt.Sprintf("%s_%s_%d", prefix, generateRandomString(), time.Now().UnixNano())
}

func generateRandomString() string {
	//nolint: gosec
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randomBytes := make([]byte, 10)
	for i := range randomBytes {
		randomBytes[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(randomBytes)
}

func receiveCopy(metricsServer monitoring.MetricServer) monitoring.MetricsCopy {
	data := metricsServer.ReceiveMetrics()

	metricsCopy, ok := data.(monitoring.MetricsCopy)
	if !ok {
		return monitoring.MetricsCopy{}
	}

	return metricsCopy
}

func minimalCounter(metricsServer monitoring.MetricServer, name string, labelValues []string) int {
	for _, counter := range receiveCopy(metricsServer).Counters {
		if counter.Name == name && slices.Equal(counter.LabelValues, labelValues) {
			return counter.Count
		}
	}

	return 0
}

func minimalHistogramCount(metricsServer monitoring.MetricServer, name string, labelValues []string) int {
	for _, histogram := range receiveCopy(metricsServer).Histograms {
		if histogram.Name == name && slices.Equal(histogram.LabelValues, labelValues) {
			return histogram.Count
		}
	}

	return 0
}

func minimalGauge(metricsServer monitoring.MetricServer, name string, labelValues []string) (float64, bool) {
	for _, gauge := range receiveCopy(metricsServer).Gauges {
		if gauge.Name == name && slices.Equal(gauge.LabelValues, labelValues) {
			return gauge.Value, true
		}
	}

	return 0, false
}
