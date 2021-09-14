// +build minimal

package monitoring

import (
	"errors"
	"fmt"
	"path"
	"regexp"
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
	HttpLatencySeconds = "zot.repo.latency.seconds"
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
var metricsEnabled bool
var lastMetricsCheck time.Time

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
		HttpLatencySeconds: []string{"repo"},
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

// Increments a counter atomically
func CounterInc(name string, labelNames []string, labelValues []string) {
	var sv SampledValue

	kLabels, ok := zotCounterList[name] // known label names for the 'name' counter
	err := sanityChecks(name, kLabels, ok, labelNames, labelValues)
	if err != nil {
		fmt.Println(err) // The last thing we want is to panic/stop the server due to instrumentation
		return           // thus log a message (should be detected during development of new metrics)
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
		Name:        name,
		Count:       1, // First value, no need to increment
		LabelNames:  labelNames,
		LabelValues: labelValues,
	}
	inMemoryMetrics.mutex.Lock()
	inMemoryMetrics.Counters = append(inMemoryMetrics.Counters, sv)
	inMemoryMetrics.mutex.Unlock()
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

	for i, gv := range inMemoryMetrics.Gauges {
		if gv.Name == name {
			if labelNames == nil && labelValues == nil {
				//found the sampled values
				inMemoryMetrics.mutex.Lock()
				inMemoryMetrics.Gauges[i].Value = value
				inMemoryMetrics.mutex.Unlock()
				return
			}
			if len(labelValues) == len(gv.LabelValues) {
				found := true
				for j, v := range gv.LabelValues {
					if v != labelValues[j] {
						found = false
						break
					}
				}
				if found {
					inMemoryMetrics.mutex.Lock()
					inMemoryMetrics.Gauges[i].Value = value
					inMemoryMetrics.mutex.Unlock()
					return
				}
			}
		}
	}
	// The Counter/SampledValue still not found: create one and return
	gv = GaugeValue{
		Name:        name,
		Value:       value,
		LabelNames:  labelNames,
		LabelValues: labelValues,
	}
	inMemoryMetrics.mutex.Lock()
	inMemoryMetrics.Gauges = append(inMemoryMetrics.Gauges, gv)
	inMemoryMetrics.mutex.Unlock()
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

	for i, sv := range inMemoryMetrics.Samples {
		if sv.Name == name {
			if labelNames == nil && labelValues == nil {
				//found the sampled values
				inMemoryMetrics.mutex.Lock()
				inMemoryMetrics.Samples[i].Count++
				inMemoryMetrics.Samples[i].Sum += value
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
					inMemoryMetrics.Samples[i].Count++
					inMemoryMetrics.Samples[i].Sum += value
					inMemoryMetrics.mutex.Unlock()
					return
				}
			}
		}
	}
	// The Counter/SampledValue still not found: create one and return
	sv = SampledValue{
		Name:        name,
		Count:       1, // First value, no need to increment
		Sum:         value,
		LabelNames:  labelNames,
		LabelValues: labelValues,
	}
	inMemoryMetrics.mutex.Lock()
	inMemoryMetrics.Samples = append(inMemoryMetrics.Samples, sv)
	inMemoryMetrics.mutex.Unlock()
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

func ObserveHttpServeLatency(path string, latency time.Duration) {
	if metricsEnabled {
		re := regexp.MustCompile("\\/v2\\/(.*?)\\/(blobs|tags|manifests)\\/(.*)$")
		match := re.FindStringSubmatch(path)
		if len(match) > 1 {
			go SummaryObserve(HttpLatencySeconds, latency.Seconds(), []string{"repo"}, []string{match[1]})
		} else {
			go SummaryObserve(HttpLatencySeconds, latency.Seconds(), []string{"repo"}, []string{"N/A"})
		}
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
