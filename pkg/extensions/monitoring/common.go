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

type MetricsInfo struct {
	Counters   []*CounterValue
	Gauges     []*GaugeValue
	Summaries  []*SummaryValue
	Histograms []*HistogramValue
}

type MetricsCopy struct {
	Counters   []CounterValue
	Gauges     []GaugeValue
	Summaries  []SummaryValue
	Histograms []HistogramValue
}

// CounterValue stores info about a metric that is incremented over time,
// such as the number of requests to an HTTP endpoint.
type CounterValue struct {
	Name        string
	Count       int
	LabelNames  []string
	LabelValues []string
}

// GaugeValue stores one value that is updated as time goes on, such as
// the amount of memory allocated.
type GaugeValue struct {
	Name        string
	Value       float64
	LabelNames  []string
	LabelValues []string
}

// SummaryValue stores info about a metric that is incremented over time,
// such as the number of requests to an HTTP endpoint.
type SummaryValue struct {
	Name        string
	Count       int
	Sum         float64
	LabelNames  []string
	LabelValues []string
}

type HistogramValue struct {
	Name        string
	Count       int
	Sum         float64
	Buckets     map[string]int
	LabelNames  []string
	LabelValues []string
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
