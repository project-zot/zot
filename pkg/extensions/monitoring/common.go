package monitoring

import (
	"os"
	"path/filepath"
	"regexp"
)

var re = regexp.MustCompile(`\/v2\/(.*?)\/(blobs|tags|manifests)\/(.*)$`)

type MetricServer interface {
	SendMetric(any)
	// works like SendMetric, but adds the metric regardless of the value of 'enabled' field for MetricServer
	ForceSendMetric(any)
	ReceiveMetrics() any
	IsEnabled() bool
	// Stop gracefully shuts down the metrics server
	Stop()
}

func GetDirSize(path string) (int64, error) {
	var size int64

	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			size += info.Size()
		}

		return err
	})

	return size, err
}
