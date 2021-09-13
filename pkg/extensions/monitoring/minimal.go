// +build minimal

package monitoring

import (
	"fmt"
	"sync"
	"time"
)

const (
	HttpConnRequests = "zot.http.requests"
)

type MetricsInfo struct {
	mutex    *sync.RWMutex
	Gauges   []GaugeValue
	Counters []SampledValue
	Samples  []SampledValue
}

var inMemoryMetrics MetricsInfo
var zotCounterList map[string][]string
var metricsEnabled bool
var lastMetricsCheck time.Time

// GaugeValue stores one value that is updated as time goes on, such as
// the amount of memory allocated.
type GaugeValue struct {
	Name   string
	Value  float32
	Labels map[string]string
}

// SampledValue stores info about a metric that is incremented over time,
// such as the number of requests to an HTTP endpoint.
type SampledValue struct {
	Name        string
	Count       int
	Sum         float64
	LabelNames  []string
	LabelValues []string
}

func init() {
	// contains a map with key=CounterName and value=CounterLabels
	zotCounterList = map[string][]string{
		HttpConnRequests: []string{"method", "code"},
	}

	inMemoryMetrics = MetricsInfo{
		mutex:    &sync.RWMutex{},
		Gauges:   make([]GaugeValue, 0),
		Counters: make([]SampledValue, 0),
		Samples:  make([]SampledValue, 0),
	}
}

func GetMetrics() MetricsInfo {
	if !metricsEnabled {
		metricsEnabled = true
	}
	lastMetricsCheck = time.Now()

	inMemoryMetrics.mutex.RLock()
	defer inMemoryMetrics.mutex.RUnlock()

	return inMemoryMetrics
}

// For Counters with no value we can send nil as LabelNames & LabelValues (equivalent of )
// Increments a counter atomically
func CounterInc(name string, labelNames []string, labelValues []string) {
	var sv SampledValue
	// Sanity Checks
	kLabels, ok := zotCounterList[name] // known label names for the 'name' counter
	if !ok {
		goto error
	}
	if len(labelNames) != len(labelValues) ||
		len(labelNames) != len(zotCounterList[name]) {
		goto error
	}
	// The list of label names defined in init() for the counter must match what was provided in labelNames
	for i, label := range labelNames {
		if label != kLabels[i] {
			goto error
		}
	}
	for i, sv := range inMemoryMetrics.Counters {
		if sv.Name == name {
			if labelNames == nil && labelValues == nil {
				//found the sampled values
				inMemoryMetrics.mutex.Lock()
				inMemoryMetrics.Counters[i].Count++
				inMemoryMetrics.mutex.Unlock()
				return
			}
			if len(labelValues) == len(sv.LabelValues) {
				found := true
				for j, v := range sv.LabelValues {
					if v != labelValues[j] {
						found = false
						break
					}
				}
				if found {
					inMemoryMetrics.mutex.Lock()
					inMemoryMetrics.Counters[i].Count++
					inMemoryMetrics.mutex.Unlock()
					return
				}
			}
		}
	}
	// The Counter/SampledValue still not found: create one and return
	sv = SampledValue{
		Count:       1, // First value, no need to increment
		Name:        name,
		LabelNames:  labelNames,
		LabelValues: labelValues,
	}
	inMemoryMetrics.mutex.Lock()
	inMemoryMetrics.Counters = append(inMemoryMetrics.Counters, sv)
	inMemoryMetrics.mutex.Unlock()
error:
	// The last thing we want is to panic/stop the server due to instrumentation
	// thus log a message (should be detected during development of new metrics)
	fmt.Println("Counter sanity check failed")
}

func IncHttpConnRequests(lvs ...string) {
	if metricsEnabled {
		CounterInc(HttpConnRequests, []string{"method", "code"}, lvs)
	}
}

func ObserveHttpServeLatency(path string, latency time.Duration) {

}

func IncDownloadCounter(repo string) {

}

func SetStorageUsage(repo string, rootDir string) {

}

func IncUploadCounter(repo string) {

}
