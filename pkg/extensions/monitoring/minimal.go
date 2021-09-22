// +build minimal

package monitoring

import (
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	metricsScrapeTimeout = 5 * time.Minute
	// Counters
	HttpConnRequests = "zot.http.requests"
	RepoDownloads    = "zot.repo.downloads"
	RepoUploads      = "zot.repo.uploads"
	//Gauge
	RepoStorageBytes = "zot.repo.storage.bytes"
	ZotInfo          = "zot.info"
	//Summary
	HttpRepoLatencySeconds = "zot.repo.latency.seconds"
	//Histogram
	HttpMethodLatencySeconds = "zot.method.latency.seconds"
)

type MetricsInfo struct {
	mutex    *sync.RWMutex
	Gauges   []GaugeValue
	Counters []SampledValue
	Samples  []SampledValue
}

var inMemoryMetrics MetricsInfo
var zotCounterList map[string][]string
var zotGaugeList map[string][]string
var zotSummaryList map[string][]string
var zotHistogramList map[string][]string
var metricsEnabled bool
var lastMetricsCheck time.Time
var bucketsFloat2String map[float64]string

// GaugeValue stores one value that is updated as time goes on, such as
// the amount of memory allocated.
type GaugeValue struct {
	Name        string
	Value       float64
	LabelNames  []string
	LabelValues []string
}

// SampledValue stores info about a metric that is incremented over time,
// such as the number of requests to an HTTP endpoint.
type SampledValue struct {
	Name        string
	Count       int
	Sum         float64
	LabelNames  []string
	LabelValues []string
	Buckets     map[string]int
}

func init() {
	// contains a map with key=CounterName and value=CounterLabels
	zotCounterList = map[string][]string{
		HttpConnRequests: []string{"method", "code"},
		RepoDownloads:    []string{"repo"},
		RepoUploads:      []string{"repo"},
	}
	// contains a map with key=CounterName and value=CounterLabels
	zotGaugeList = map[string][]string{
		RepoStorageBytes: []string{"repo"},
		ZotInfo:          []string{"commit", "binaryType", "goVersion", "version"},
	}

	// contains a map with key=CounterName and value=CounterLabels
	zotSummaryList = map[string][]string{
		HttpRepoLatencySeconds: []string{"repo"},
	}

	zotHistogramList = map[string][]string{
		HttpMethodLatencySeconds: []string{"method"},
	}

	inMemoryMetrics = MetricsInfo{
		mutex:    &sync.RWMutex{},
		Gauges:   make([]GaugeValue, 0),
		Counters: make([]SampledValue, 0),
		Samples:  make([]SampledValue, 0),
	}

	// convert to a map for returning easily the string corresponding to a bucket
	bucketsFloat2String = map[float64]string{}
	for _, fvalue := range GetDefaultBuckets() {
		if fvalue == math.MaxFloat64 {
			bucketsFloat2String[fvalue] = "+Inf"
		} else {
			s := strconv.FormatFloat(fvalue, 'f', -1, 64)
			bucketsFloat2String[fvalue] = s
		}
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

// return true if a metric does not have any labels or
// if the label values for searched metric corresponds to the one in the cached slice
func isMetricMatch(lNames []string, lValues []string, metricValues []string) bool {
	if lNames == nil && lValues == nil {
		// metric does not contain any labels
		return true
	}
	if len(lValues) == len(metricValues) {
		for i, v := range metricValues {
			if v != lValues[i] {
				return false
			}
		}
	}
	return true
}

// returns {-1, false} in case metric was not found in the slice
func findSampledValueIndex(metricSlice []SampledValue, name string, labelNames []string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelNames, labelValues, m.LabelValues) {
				return i, true
			}
		}
	}
	return -1, false
}

// returns {-1, false} in case metric was not found in the slice
func findGaugeValueIndex(metricSlice []GaugeValue, name string, labelNames []string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelNames, labelValues, m.LabelValues) {
				return i, true
			}
		}
	}
	return -1, false
}

// Increments a counter atomically
func CounterInc(name string, labelNames []string, labelValues []string) {
	var sv SampledValue

	kLabels, ok := zotCounterList[name] // known label names for the 'name' counter
	err := sanityChecks(name, kLabels, ok, labelNames, labelValues)
	if err != nil {
		fmt.Println(err) // The last thing we want is to panic/stop the server due to instrumentation
		return           // thus log a message (should be detected during development of new metrics)
	}

	index, ok := findSampledValueIndex(inMemoryMetrics.Counters, name, labelNames, labelValues)
	inMemoryMetrics.mutex.Lock()
	defer inMemoryMetrics.mutex.Unlock()
	if !ok {
		// The SampledValue not found: create one
		sv = SampledValue{
			Name:        name,
			Count:       1, // First value, no need to increment
			LabelNames:  labelNames,
			LabelValues: labelValues,
		}
		inMemoryMetrics.Counters = append(inMemoryMetrics.Counters, sv)
	} else {
		inMemoryMetrics.Counters[index].Count++
	}
}

// Sets a gauge atomically
func GaugeSet(name string, value float64, labelNames []string, labelValues []string) {
	var gv GaugeValue

	kLabels, ok := zotGaugeList[name] // known label names for the 'name' counter
	err := sanityChecks(name, kLabels, ok, labelNames, labelValues)
	if err != nil {
		fmt.Println(err) // The last thing we want is to panic/stop the server due to instrumentation
		return           // thus log a message (should be detected during development of new metrics)
	}

	index, ok := findGaugeValueIndex(inMemoryMetrics.Gauges, name, labelNames, labelValues)
	inMemoryMetrics.mutex.Lock()
	defer inMemoryMetrics.mutex.Unlock()
	if !ok {
		// The GaugeValue not found: create one
		gv = GaugeValue{
			Name:        name,
			Value:       value,
			LabelNames:  labelNames,
			LabelValues: labelValues,
		}
		inMemoryMetrics.Gauges = append(inMemoryMetrics.Gauges, gv)
	} else {
		inMemoryMetrics.Gauges[index].Value = value
	}
}

// Increments a summary counter & add to the summary sum atomically
func SummaryObserve(name string, value float64, labelNames []string, labelValues []string) {
	var sv SampledValue

	kLabels, ok := zotSummaryList[name] // known label names for the 'name' counter
	err := sanityChecks(name, kLabels, ok, labelNames, labelValues)
	if err != nil {
		fmt.Println(err) // The last thing we want is to panic/stop the server due to instrumentation
		return           // thus log a message (should be detected during development of new metrics)
	}

	index, ok := findSampledValueIndex(inMemoryMetrics.Samples, name, labelNames, labelValues)
	inMemoryMetrics.mutex.Lock()
	defer inMemoryMetrics.mutex.Unlock()
	if !ok {
		// The SampledValue not found: create one
		sv = SampledValue{
			Name:        name,
			Count:       1, // First value, no need to increment
			LabelNames:  labelNames,
			LabelValues: labelValues,
		}
		inMemoryMetrics.Samples = append(inMemoryMetrics.Samples, sv)
	} else {
		inMemoryMetrics.Samples[index].Count++
		inMemoryMetrics.Samples[index].Sum += value
	}
}

// Increments a summary counter & add to the summary sum atomically
func HistogramObserve(name string, value float64, labelNames []string, labelValues []string) {
	var sv SampledValue

	kLabels, ok := zotHistogramList[name] // known label names for the 'name' counter
	err := sanityChecks(name, kLabels, ok, labelNames, labelValues)
	if err != nil {
		fmt.Println(err) // The last thing we want is to panic/stop the server due to instrumentation
		return           // thus log a message (should be detected during development of new metrics)
	}

	index, ok := findSampledValueIndex(inMemoryMetrics.Samples, name, labelNames, labelValues)
	inMemoryMetrics.mutex.Lock()
	defer inMemoryMetrics.mutex.Unlock()
	if !ok {
		// The SampledValue not found: create one
		buckets := make(map[string]int, 0)
		for _, fvalue := range GetDefaultBuckets() {
			if value <= fvalue {
				buckets[bucketsFloat2String[fvalue]] = 1
			} else {
				buckets[bucketsFloat2String[fvalue]] = 0
			}
		}
		sv = SampledValue{
			Name:        name,
			Count:       1, // First value, no need to increment
			Sum:         value,
			LabelNames:  labelNames,
			LabelValues: labelValues,
			Buckets:     buckets,
		}
		inMemoryMetrics.Samples = append(inMemoryMetrics.Samples, sv)
	} else {
		inMemoryMetrics.Samples[index].Count++
		inMemoryMetrics.Samples[index].Sum += value
		for _, fvalue := range GetDefaultBuckets() {
			if value <= fvalue {
				inMemoryMetrics.Samples[index].Buckets[bucketsFloat2String[fvalue]]++
			}
		}
	}
}

func sanityChecks(name string, knownLabels []string, found bool, labelNames []string, labelValues []string) error {
	if !found {
		return errors.New(fmt.Sprintf("Metric %s not found", name))
	}

	if len(labelNames) != len(labelValues) ||
		len(labelNames) != len(knownLabels) {
		return errors.New(fmt.Sprintf("Metric %s : label size mismatch", name))
	}
	// The list of label names defined in init() for the counter must match what was provided in labelNames
	for i, label := range labelNames {
		if label != knownLabels[i] {
			return errors.New(fmt.Sprintf("Metric %s : label order mismatch", name))
		}
	}
	return nil
}

func IncHttpConnRequests(lvs ...string) {
	if metricsEnabled {
		go CounterInc(HttpConnRequests, []string{"method", "code"}, lvs)
		// Check if we didn't receive a metrics scrape in a while and if so, disable metrics (possible node exporter down/crashed)
		latency := time.Now().Sub(lastMetricsCheck)
		if latency > metricsScrapeTimeout {
			metricsEnabled = false
		}
	}
}

func ObserveHttpRepoLatency(path string, latency time.Duration) {
	if metricsEnabled {
		re := regexp.MustCompile("\\/v2\\/(.*?)\\/(blobs|tags|manifests)\\/(.*)$")
		match := re.FindStringSubmatch(path)
		if len(match) > 1 {
			go SummaryObserve(HttpRepoLatencySeconds, latency.Seconds(), []string{"repo"}, []string{match[1]})
		} else {
			go SummaryObserve(HttpRepoLatencySeconds, latency.Seconds(), []string{"repo"}, []string{"N/A"})
		}
	}
}

func ObserveHttpMethodLatency(method string, latency time.Duration) {
	if metricsEnabled {
		go HistogramObserve(HttpMethodLatencySeconds, latency.Seconds(), []string{"method"}, []string{method})
	}
}

func IncDownloadCounter(repo string) {
	if metricsEnabled {
		go CounterInc(RepoDownloads, []string{"repo"}, []string{repo})
	}
}

func IncUploadCounter(repo string) {
	if metricsEnabled {
		go CounterInc(RepoUploads, []string{"repo"}, []string{repo})
	}
}

func SetStorageUsage(repo string, rootDir string) {
	if metricsEnabled {
		dir := path.Join(rootDir, repo)
		repoSize, err := getDirSize(dir)

		if err == nil {
			go GaugeSet(RepoStorageBytes, float64(repoSize), []string{"repo"}, []string{repo})
		}
	}
}

func SetZotInfo(lvs ...string) {
	//  This metric is set once at zot startup (do not condition upon metricsEnabled!)
	go GaugeSet(ZotInfo, 0, []string{"commit", "binaryType", "goVersion", "version"}, lvs)
}

// Used by the zot exporter
func BucketConvFloat2String(b float64) string {
	return bucketsFloat2String[b]
}
