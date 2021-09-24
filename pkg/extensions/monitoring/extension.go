// +build extended

package monitoring

import (
	"path"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsNamespace = "zot"

var metricsEnabled bool // nolint: gochecknoglobals

var (
	httpConnRequests = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "zot_http_requests_total",
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
			Name:      "zot_repo_storage_bytes",
			Help:      "Storage used per zot repo",
		},
		[]string{"repo"},
	)
	uploadCounter = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "zot_repo_uploads_total",
			Help:      "Total number times an image was uploaded",
		},
		[]string{"repo"},
	)
	downloadCounter = promauto.NewCounterVec( // nolint: gochecknoglobals
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "zot_repo_downloads_total",
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

func IncHTTPConnRequests(lvalues ...string) {
	if metricsEnabled {
		httpConnRequests.WithLabelValues(lvalues...).Inc()
	}
}

func ObserveHTTPRepoLatency(path string, latency time.Duration) {
	if metricsEnabled {
		re := regexp.MustCompile(`\/v2\/(.*?)\/(blobs|tags|manifests)\/(.*)$`)
		match := re.FindStringSubmatch(path)

		if len(match) > 1 {
			httpRepoLatency.WithLabelValues(match[1]).Observe(latency.Seconds())
		} else {
			httpRepoLatency.WithLabelValues("N/A").Observe(latency.Seconds())
		}
	}
}

func ObserveHTTPMethodLatency(method string, latency time.Duration) {
	if metricsEnabled {
		httpMethodLatency.WithLabelValues(method).Observe(latency.Seconds())
	}
}

func IncDownloadCounter(repo string) {
	if metricsEnabled {
		downloadCounter.WithLabelValues(repo).Inc()
	}
}

func SetStorageUsage(repo string, rootDir string) {
	if metricsEnabled {
		dir := path.Join(rootDir, repo)
		repoSize, err := getDirSize(dir)

		if err == nil {
			repoStorageBytes.WithLabelValues(repo).Set(float64(repoSize))
		}
	}
}

func IncUploadCounter(repo string) {
	if metricsEnabled {
		uploadCounter.WithLabelValues(repo).Inc()
	}
}

func GetMetrics() interface{} {
	return new(struct{})
}

func EnableMetrics() {
	metricsEnabled = true
}

func SetZotInfo(lvalues ...string) {
	//  This metric is set once at zot startup (do not condition upon metricsEnabled!)
	zotInfo.WithLabelValues(lvalues...).Set(0)
}
