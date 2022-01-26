package monitoring

import (
	"os"
	"path/filepath"
)

type MetricServer interface {
	SendMetric(interface{})
	// works like SendMetric, but adds the metric regardless of the value of 'enabled' field for MetricServer
	ForceSendMetric(interface{})
	ReceiveMetrics() interface{}
	IsEnabled() bool
}

func getDirSize(path string) (int64, error) {
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
