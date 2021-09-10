// +build extended

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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
)
