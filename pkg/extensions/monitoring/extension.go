// +build extended

package monitoring

import (
	"path"
	"regexp"
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsNamespace = "zot"

var (
	httpConnRequests = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "Total number of http request in zot",
		},
		[]string{"method", "code"},
	)
	httpRepoLatency = promauto.NewSummaryVec( // nolint: gochecknoglobals
		prometheus.SummaryOpts{
			Namespace: metricsNamespace,
			Name:      "http_repo_latency_seconds",
			Help:      "Latency of serving HTTP requests",
		},
		[]string{"repo"},
	)
	httpMethodLatency = promauto.NewHistogramVec( // nolint: gochecknoglobals
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "http_method_latency_seconds",
			Help:      "Latency of serving HTTP requests",
			Buckets:   GetDefaultBuckets(),
		},
		[]string{"method"},
	)
	repoStorageBytes = promauto.NewGaugeVec( // nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "repo_storage_bytes",
			Help:      "Storage used per zot repo",
		},
		[]string{"repo"},
	)
	uploadCounter = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "repo_uploads_total",
			Help:      "Total number times an image was uploaded",
		},
		[]string{"repo"},
	)
	downloadCounter = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "repo_downloads_total",
			Help:      "Total number times an image was downloaded",
		},
		[]string{"repo"},
	)
	zotInfo = promauto.NewGaugeVec( // nolint: gochecknoglobals
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "info",
			Help:      "Zot general information",
		},
		[]string{"commit", "binaryType", "goVersion", "version"},
	)
)

type metricServer struct {
	enabled bool
	log     log.Logger
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
		fn := mfunc.(func())
		fn()
	}
}

func (ms *metricServer) ForceSendMetric(mfunc interface{}) {
	fn := mfunc.(func())
	fn()
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
		re := regexp.MustCompile(`\/v2\/(.*?)\/(blobs|tags|manifests)\/(.*)$`)
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

func SetStorageUsage(ms MetricServer, rootDir string, repo string) {
	ms.SendMetric(func() {
		dir := path.Join(rootDir, repo)
		repoSize, err := getDirSize(dir)

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

func SetZotInfo(ms MetricServer, lvalues ...string) {
	ms.ForceSendMetric(func() {
		zotInfo.WithLabelValues(lvalues...).Set(0)
	})
}
