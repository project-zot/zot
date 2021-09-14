// +build extended

package monitoring

import (
	"path"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var metricsEnabled bool
var metricsNamespace = "zot"

var (
	HttpConnRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "Total number of http request in zot",
		},
		[]string{"method", "code"},
	)
	HttpServeLatency = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace: metricsNamespace,
			Name:      "http_latency_seconds",
			Help:      "Latency of serving HTTP requests",
		},
		[]string{"repo"},
	)
	StorageUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "storage_usage_bytes",
			Help:      "Storage used",
		},
		[]string{"repo"},
	)
	UploadCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "upload_image_total",
			Help:      "Total number times an image was uploaded",
		},
		[]string{"repo"},
	)
	DownloadCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "download_image_total",
			Help:      "Total number times an image was downloaded",
		},
		[]string{"repo"},
	)
	ZotInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "info",
			Help:      "Zot general information",
		},
		[]string{"commit", "binaryType", "goVersion", "version"},
	)
)

func IncHttpConnRequests(lvalues ...string) {
	if metricsEnabled {
		HttpConnRequests.WithLabelValues(lvalues...).Inc()
	}
}

func ObserveHttpServeLatency(path string, latency time.Duration) {
	if metricsEnabled {
		re := regexp.MustCompile("\\/v2\\/(.*?)\\/(blobs|tags|manifests)\\/(.*)$")
		match := re.FindStringSubmatch(path)
		if len(match) > 1 {
			HttpServeLatency.WithLabelValues(match[1]).Observe(latency.Seconds())
		} else {
			HttpServeLatency.WithLabelValues("N/A").Observe(latency.Seconds())
		}
	}
}

func IncDownloadCounter(repo string) {
	if metricsEnabled {
		DownloadCounter.WithLabelValues(repo).Inc()
	}
}

func SetStorageUsage(repo string, rootDir string) {
	if metricsEnabled {
		dir := path.Join(rootDir, repo)
		repoSize, err := getDirSize(dir)

		if err == nil {
			StorageUsage.WithLabelValues(repo).Set(float64(repoSize))
		}
	}
}

func IncUploadCounter(repo string) {
	if metricsEnabled {
		UploadCounter.WithLabelValues(repo).Inc()
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
	ZotInfo.WithLabelValues(lvalues...).Set(0)
}
