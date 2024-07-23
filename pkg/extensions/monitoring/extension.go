//go:build metrics
// +build metrics

package monitoring

import (
	"path"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

const metricsNamespace = "zot"

var (
	httpConnRequests = promauto.NewCounterVec( //nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "Total number of http request in zot",
		},
		[]string{"method", "code"},
	)
	httpRepoLatency = promauto.NewSummaryVec( //nolint: gochecknoglobals
		prometheus.SummaryOpts{
			Namespace: metricsNamespace,
			Name:      "http_repo_latency_seconds",
			Help:      "Latency of serving HTTP requests",
		},
		[]string{"repo"},
	)
	httpMethodLatency = promauto.NewHistogramVec( //nolint: gochecknoglobals
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "http_method_latency_seconds",
			Help:      "Latency of serving HTTP requests",
			Buckets:   GetDefaultBuckets(),
		},
		[]string{"method"},
	)
	repoStorageBytes = promauto.NewGaugeVec( //nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "repo_storage_bytes",
			Help:      "Storage used per zot repo",
		},
		[]string{"repo"},
	)
	uploadCounter = promauto.NewCounterVec( //nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "repo_uploads_total",
			Help:      "Total number times an image was uploaded",
		},
		[]string{"repo"},
	)
	downloadCounter = promauto.NewCounterVec( //nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "repo_downloads_total",
			Help:      "Total number times an image was downloaded",
		},
		[]string{"repo"},
	)
	serverInfo = promauto.NewGaugeVec( //nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "info",
			Help:      "Server general information",
		},
		[]string{"commit", "binaryType", "goVersion", "version"},
	)
	storageLockLatency = promauto.NewHistogramVec( //nolint: gochecknoglobals
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "storage_lock_latency_seconds",
			Help:      "Latency of serving HTTP requests",
			Buckets:   GetStorageLatencyBuckets(),
		},
		[]string{"storageName", "lockType"},
	)
	schedulerGenerators = promauto.NewCounter( //nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "scheduler_generators_total",
			Help:      "Total number of generators registered in scheduler",
		},
	)
	schedulerGeneratorsStatus = promauto.NewGaugeVec( //nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "scheduler_generators_status",
			Help:      "Scheduler generators by priority & state",
		},
		[]string{"priority", "state"},
	)
	schedulerNumWorkers = promauto.NewGauge( //nolint: gochecknoglobals
		prometheus.GaugeOpts{ //nolint: promlinter
			Namespace: metricsNamespace,
			Name:      "scheduler_workers_total",
			Help:      "Total number of available workers to perform scheduler tasks",
		},
	)
	schedulerWorkers = promauto.NewGaugeVec( //nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "scheduler_workers",
			Help:      "Scheduler workers state",
		},
		[]string{"state"},
	)
	schedulerTasksQueue = promauto.NewGaugeVec( //nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "scheduler_tasksqueue_length",
			Help:      "Number of tasks waiting in the queue to pe processed by scheduler workers",
		},
		[]string{"priority"},
	)
	workersTasksDuration = promauto.NewHistogramVec( //nolint: gochecknoglobals
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "scheduler_workers_tasks_duration_seconds",
			Help:      "How long it takes for a worker to execute a task",
			Buckets:   GetDefaultBuckets(),
		},
		[]string{"name"},
	)
)

type metricServer struct {
	enabled bool
	log     log.Logger
}

func GetDefaultBuckets() []float64 {
	return []float64{.05, .5, 1, 5, 30, 60, 600}
}

func GetStorageLatencyBuckets() []float64 {
	return []float64{.001, .01, 0.1, 1, 5, 10, 15, 30, 60}
}

func NewMetricsServer(enabled bool, log log.Logger) MetricServer {
	return &metricServer{
		enabled: enabled,
		log:     log,
	}
}

// implementing the MetricServer interface.
func (ms *metricServer) SendMetric(mfunc interface{}) {
	if ms.enabled {
		mfn, ok := mfunc.(func())
		if !ok {
			ms.log.Error().Err(errors.ErrInvalidMetric).
				Msgf("failed to cast type, expected '%T' but got '%T'", func() {}, mfunc)

			return
		}

		mfn()
	}
}

func (ms *metricServer) ForceSendMetric(mfunc interface{}) {
	mfn, ok := mfunc.(func())
	if !ok {
		ms.log.Error().Err(errors.ErrInvalidMetric).
			Msgf("failed to cast type, expected '%T' but got '%T'", func() {}, mfunc)

		return
	}

	mfn()
}

func (ms *metricServer) ReceiveMetrics() interface{} {
	return nil
}

func (ms *metricServer) IsEnabled() bool {
	return ms.enabled
}

func IncHTTPConnRequests(ms MetricServer, lvalues ...string) {
	ms.SendMetric(func() {
		httpConnRequests.WithLabelValues(lvalues...).Inc()
	})
}

func ObserveHTTPRepoLatency(ms MetricServer, path string, latency time.Duration) {
	ms.SendMetric(func() {
		match := re.FindStringSubmatch(path)

		if len(match) > 1 {
			httpRepoLatency.WithLabelValues(match[1]).Observe(latency.Seconds())
		} else {
			httpRepoLatency.WithLabelValues("N/A").Observe(latency.Seconds())
		}
	})
}

func ObserveHTTPMethodLatency(ms MetricServer, method string, latency time.Duration) {
	ms.SendMetric(func() {
		httpMethodLatency.WithLabelValues(method).Observe(latency.Seconds())
	})
}

func IncDownloadCounter(ms MetricServer, repo string) {
	ms.SendMetric(func() {
		downloadCounter.WithLabelValues(repo).Inc()
	})
}

func SetStorageUsage(ms MetricServer, rootDir, repo string) {
	ms.ForceSendMetric(func() {
		dir := path.Join(rootDir, repo)
		repoSize, err := GetDirSize(dir)

		if err == nil {
			repoStorageBytes.WithLabelValues(repo).Set(float64(repoSize))
		}
	})
}

func IncUploadCounter(ms MetricServer, repo string) {
	ms.SendMetric(func() {
		uploadCounter.WithLabelValues(repo).Inc()
	})
}

func SetServerInfo(ms MetricServer, lvalues ...string) {
	ms.ForceSendMetric(func() {
		serverInfo.WithLabelValues(lvalues...).Set(0)
	})
}

func ObserveStorageLockLatency(ms MetricServer, latency time.Duration, storageName, lockType string) {
	ms.SendMetric(func() {
		storageLockLatency.WithLabelValues(storageName, lockType).Observe(latency.Seconds())
	})
}

func IncSchedulerGenerators(ms MetricServer) {
	ms.ForceSendMetric(func() {
		schedulerGenerators.Inc()
	})
}

func SetSchedulerGenerators(ms MetricServer, gen map[string]map[string]uint64) {
	ms.SendMetric(func() {
		for priority, states := range gen {
			for state, value := range states {
				schedulerGeneratorsStatus.WithLabelValues(priority, state).Set(float64(value))
			}
		}
	})
}

func SetSchedulerNumWorkers(ms MetricServer, total int) {
	ms.SendMetric(func() {
		schedulerNumWorkers.Set(float64(total))
	})
}

func SetSchedulerWorkers(ms MetricServer, w map[string]int) {
	ms.SendMetric(func() {
		for state, value := range w {
			schedulerWorkers.WithLabelValues(state).Set(float64(value))
		}
	})
}

func SetSchedulerTasksQueue(ms MetricServer, tq map[string]int) {
	ms.SendMetric(func() {
		for priority, value := range tq {
			schedulerTasksQueue.WithLabelValues(priority).Set(float64(value))
		}
	})
}

func ObserveWorkersTasksDuration(ms MetricServer, taskName string, duration time.Duration) {
	ms.SendMetric(func() {
		workersTasksDuration.WithLabelValues(taskName).Observe(duration.Seconds())
	})
}
