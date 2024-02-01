//go:build !metrics
// +build !metrics

//nolint:varnamelen,forcetypeassert
package monitoring

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"sync"
	"time"

	"zotregistry.dev/zot/pkg/log"
)

const (
	metricsNamespace = "zot"
	// Counters.
	httpConnRequests    = metricsNamespace + ".http.requests"
	repoDownloads       = metricsNamespace + ".repo.downloads"
	repoUploads         = metricsNamespace + ".repo.uploads"
	schedulerGenerators = metricsNamespace + ".scheduler.generators"
	// Gauge.
	repoStorageBytes          = metricsNamespace + ".repo.storage.bytes"
	serverInfo                = metricsNamespace + ".info"
	schedulerNumWorkers       = metricsNamespace + ".scheduler.workers.total"
	schedulerWorkers          = metricsNamespace + ".scheduler.workers"
	schedulerGeneratorsStatus = metricsNamespace + ".scheduler.generators.status"
	schedulerTasksQueue       = metricsNamespace + ".scheduler.tasksqueue.length"
	// Summary.
	httpRepoLatencySeconds = metricsNamespace + ".http.repo.latency.seconds"
	// Histogram.
	httpMethodLatencySeconds  = metricsNamespace + ".http.method.latency.seconds"
	storageLockLatencySeconds = metricsNamespace + ".storage.lock.latency.seconds"
	workersTasksDuration      = metricsNamespace + ".scheduler.workers.tasks.duration.seconds"

	metricsScrapeTimeout       = 2 * time.Minute
	metricsScrapeCheckInterval = 30 * time.Second
)

type metricServer struct {
	enabled    bool
	lastCheck  time.Time
	reqChan    chan interface{}
	cache      *MetricsInfo
	cacheChan  chan MetricsCopy
	bucketsF2S map[float64]string // float64 to string conversion of buckets label
	log        log.Logger
	lock       *sync.RWMutex
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

func GetDefaultBuckets() []float64 {
	return []float64{.05, .5, 1, 5, 30, 60, 600, math.MaxFloat64}
}

func GetStorageLatencyBuckets() []float64 {
	return []float64{.001, .01, 0.1, 1, 5, 10, 15, 30, 60, math.MaxFloat64}
}

// implements the MetricServer interface.
func (ms *metricServer) SendMetric(metric interface{}) {
	ms.lock.RLock()
	if ms.enabled {
		ms.lock.RUnlock()
		ms.reqChan <- metric
	} else {
		ms.lock.RUnlock()
	}
}

func (ms *metricServer) ForceSendMetric(metric interface{}) {
	ms.reqChan <- metric
}

func (ms *metricServer) ReceiveMetrics() interface{} {
	ms.lock.Lock()
	if !ms.enabled {
		ms.enabled = true
	}
	ms.lock.Unlock()
	ms.cacheChan <- MetricsCopy{}

	return <-ms.cacheChan
}

func (ms *metricServer) IsEnabled() bool {
	ms.lock.RLock()
	defer ms.lock.RUnlock()

	return ms.enabled
}

func (ms *metricServer) Run() {
	sendAfter := make(chan time.Duration, 1)
	// periodically send a notification to the metric server to check if we can disable metrics
	go func() {
		for {
			t := metricsScrapeCheckInterval
			time.Sleep(t)
			sendAfter <- t
		}
	}()

	for {
		select {
		case <-ms.cacheChan:
			ms.lastCheck = time.Now()
			// make a copy of cache values to prevent data race
			metrics := MetricsCopy{
				Counters:   make([]CounterValue, len(ms.cache.Counters)),
				Gauges:     make([]GaugeValue, len(ms.cache.Gauges)),
				Summaries:  make([]SummaryValue, len(ms.cache.Summaries)),
				Histograms: make([]HistogramValue, len(ms.cache.Histograms)),
			}
			for i, cv := range ms.cache.Counters {
				metrics.Counters[i] = *cv
			}

			for i, gv := range ms.cache.Gauges {
				metrics.Gauges[i] = *gv
			}

			for i, sv := range ms.cache.Summaries {
				metrics.Summaries[i] = *sv
			}

			for i, hv := range ms.cache.Histograms {
				metrics.Histograms[i] = *hv
			}
			ms.cacheChan <- metrics
		case m := <-ms.reqChan:
			switch v := m.(type) {
			case CounterValue:
				cv := m.(CounterValue)
				ms.CounterInc(&cv)
			case GaugeValue:
				gv := m.(GaugeValue)
				ms.GaugeSet(&gv)
			case SummaryValue:
				sv := m.(SummaryValue)
				ms.SummaryObserve(&sv)
			case HistogramValue:
				hv := m.(HistogramValue)
				ms.HistogramObserve(&hv)
			default:
				ms.log.Error().Str("type", fmt.Sprintf("%T", v)).Msg("unexpected type")
			}
		case <-sendAfter:
			// Check if we didn't receive a metrics scrape in a while and if so,
			// disable metrics (possible node exporter down/crashed)
			ms.lock.Lock()
			if ms.enabled {
				lastCheckInterval := time.Since(ms.lastCheck)
				if lastCheckInterval > metricsScrapeTimeout {
					ms.enabled = false
				}
			}
			ms.lock.Unlock()
		}
	}
}

func NewMetricsServer(enabled bool, log log.Logger) MetricServer {
	mi := &MetricsInfo{
		Counters:   make([]*CounterValue, 0),
		Gauges:     make([]*GaugeValue, 0),
		Summaries:  make([]*SummaryValue, 0),
		Histograms: make([]*HistogramValue, 0),
	}
	// convert to a map for returning easily the string corresponding to a bucket
	bucketsFloat2String := map[float64]string{}

	for _, fvalue := range append(GetDefaultBuckets(), GetStorageLatencyBuckets()...) {
		if fvalue == math.MaxFloat64 {
			bucketsFloat2String[fvalue] = "+Inf"
		} else {
			s := strconv.FormatFloat(fvalue, 'f', -1, 64)
			bucketsFloat2String[fvalue] = s
		}
	}

	ms := &metricServer{
		enabled:    enabled,
		reqChan:    make(chan interface{}),
		cacheChan:  make(chan MetricsCopy),
		cache:      mi,
		bucketsF2S: bucketsFloat2String,
		log:        log,
		lock:       &sync.RWMutex{},
	}

	go ms.Run()

	return ms
}

// contains a map with key=CounterName and value=CounterLabels.
func GetCounters() map[string][]string {
	return map[string][]string{
		httpConnRequests:    {"method", "code"},
		repoDownloads:       {"repo"},
		repoUploads:         {"repo"},
		schedulerGenerators: {},
	}
}

func GetGauges() map[string][]string {
	return map[string][]string{
		repoStorageBytes:          {"repo"},
		serverInfo:                {"commit", "binaryType", "goVersion", "version"},
		schedulerNumWorkers:       {},
		schedulerGeneratorsStatus: {"priority", "state"},
		schedulerTasksQueue:       {"priority"},
		schedulerWorkers:          {"state"},
	}
}

func GetSummaries() map[string][]string {
	return map[string][]string{
		httpRepoLatencySeconds: {"repo"},
	}
}

func GetHistograms() map[string][]string {
	return map[string][]string{
		httpMethodLatencySeconds:  {"method"},
		storageLockLatencySeconds: {"storageName", "lockType"},
		workersTasksDuration:      {"name"},
	}
}

// return true if a metric does not have any labels or if the label
// values for searched metric corresponds to the one in the cached slice.
func isMetricMatch(lValues, metricValues []string) bool {
	if len(lValues) == len(metricValues) {
		for i, v := range metricValues {
			if v != lValues[i] {
				return false
			}
		}
	}

	return true
}

// returns {-1, false} in case metric was not found in the slice.
func findCounterValueIndex(metricSlice []*CounterValue, name string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelValues, m.LabelValues) {
				return i, true
			}
		}
	}

	return -1, false
}

// returns {-1, false} in case metric was not found in the slice.
func findGaugeValueIndex(metricSlice []*GaugeValue, name string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelValues, m.LabelValues) {
				return i, true
			}
		}
	}

	return -1, false
}

// returns {-1, false} in case metric was not found in the slice.
func findSummaryValueIndex(metricSlice []*SummaryValue, name string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelValues, m.LabelValues) {
				return i, true
			}
		}
	}

	return -1, false
}

// returns {-1, false} in case metric was not found in the slice.
func findHistogramValueIndex(metricSlice []*HistogramValue, name string, labelValues []string) (int, bool) {
	for i, m := range metricSlice {
		if m.Name == name {
			if isMetricMatch(labelValues, m.LabelValues) {
				return i, true
			}
		}
	}

	return -1, false
}

func (ms *metricServer) CounterInc(cv *CounterValue) {
	labels, ok := GetCounters()[cv.Name] // known label names for the 'name' counter

	err := sanityChecks(cv.Name, labels, ok, cv.LabelNames, cv.LabelValues)
	if err != nil {
		// The last thing we want is to panic/stop the server due to instrumentation
		// thus log a message (should be detected during development of new metrics)
		ms.log.Error().Err(err).Msg("failed due to instrumentation error")

		return
	}

	index, ok := findCounterValueIndex(ms.cache.Counters, cv.Name, cv.LabelValues)
	if !ok {
		// cv not found in cache: add it
		cv.Count = 1
		ms.cache.Counters = append(ms.cache.Counters, cv)
	} else {
		ms.cache.Counters[index].Count++
	}
}

func (ms *metricServer) GaugeSet(gv *GaugeValue) {
	labels, ok := GetGauges()[gv.Name] // known label names for the 'name' counter

	err := sanityChecks(gv.Name, labels, ok, gv.LabelNames, gv.LabelValues)
	if err != nil {
		ms.log.Error().Err(err).Msg("failed due to instrumentation error")

		return
	}

	index, ok := findGaugeValueIndex(ms.cache.Gauges, gv.Name, gv.LabelValues)
	if !ok {
		// gv not found in cache: add it
		ms.cache.Gauges = append(ms.cache.Gauges, gv)
	} else {
		ms.cache.Gauges[index].Value = gv.Value
	}
}

func (ms *metricServer) SummaryObserve(sv *SummaryValue) {
	labels, ok := GetSummaries()[sv.Name] // known label names for the 'name' summary

	err := sanityChecks(sv.Name, labels, ok, sv.LabelNames, sv.LabelValues)
	if err != nil {
		ms.log.Error().Err(err).Msg("failed due to instrumentation error")

		return
	}

	index, ok := findSummaryValueIndex(ms.cache.Summaries, sv.Name, sv.LabelValues)
	if !ok {
		// The SampledValue not found: add it
		sv.Count = 1 // First value, no need to increment
		ms.cache.Summaries = append(ms.cache.Summaries, sv)
	} else {
		ms.cache.Summaries[index].Count++
		ms.cache.Summaries[index].Sum += sv.Sum
	}
}

func (ms *metricServer) HistogramObserve(hv *HistogramValue) {
	labels, ok := GetHistograms()[hv.Name] // known label names for the 'name' counter

	err := sanityChecks(hv.Name, labels, ok, hv.LabelNames, hv.LabelValues)
	if err != nil {
		ms.log.Error().Err(err).Msg("failed due to instrumentation error")

		return
	}

	index, ok := findHistogramValueIndex(ms.cache.Histograms, hv.Name, hv.LabelValues)
	if !ok {
		// The HistogramValue not found: add it
		buckets := make(map[string]int)

		for _, fvalue := range GetBuckets(hv.Name) {
			if hv.Sum <= fvalue {
				buckets[ms.bucketsF2S[fvalue]] = 1
			} else {
				buckets[ms.bucketsF2S[fvalue]] = 0
			}
		}

		hv.Count = 1 // First value, no need to increment
		hv.Buckets = buckets
		ms.cache.Histograms = append(ms.cache.Histograms, hv)
	} else {
		cachedH := ms.cache.Histograms[index]
		cachedH.Count++
		cachedH.Sum += hv.Sum
		for _, fvalue := range GetBuckets(hv.Name) {
			if hv.Sum <= fvalue {
				cachedH.Buckets[ms.bucketsF2S[fvalue]]++
			}
		}
	}
}

//nolint:goerr113
func sanityChecks(name string, knownLabels []string, found bool, labelNames, labelValues []string) error {
	if !found {
		return fmt.Errorf("metric %s: not found", name)
	}

	if len(labelNames) != len(labelValues) ||
		len(labelNames) != len(knownLabels) {
		return fmt.Errorf("metric %s: label size mismatch", name)
	}
	// The list of label names defined in init() for the counter must match what was provided in labelNames
	for i, label := range labelNames {
		if label != knownLabels[i] {
			return fmt.Errorf("metric %s: label size mismatch", name)
		}
	}

	return nil
}

func IncHTTPConnRequests(ms MetricServer, lvs ...string) {
	req := CounterValue{
		Name:        httpConnRequests,
		LabelNames:  []string{"method", "code"},
		LabelValues: lvs,
	}
	ms.SendMetric(req)
}

func ObserveHTTPRepoLatency(ms MetricServer, path string, latency time.Duration) {
	var lvs []string
	match := re.FindStringSubmatch(path)

	if len(match) > 1 {
		lvs = []string{match[1]}
	} else {
		lvs = []string{"N/A"}
	}

	sv := SummaryValue{
		Name:        httpRepoLatencySeconds,
		Sum:         latency.Seconds(),
		LabelNames:  []string{"repo"},
		LabelValues: lvs,
	}
	ms.SendMetric(sv)
}

func ObserveHTTPMethodLatency(ms MetricServer, method string, latency time.Duration) {
	h := HistogramValue{
		Name:        httpMethodLatencySeconds,
		Sum:         latency.Seconds(), // convenient temporary store for Histogram latency value
		LabelNames:  []string{"method"},
		LabelValues: []string{method},
	}
	ms.SendMetric(h)
}

func IncDownloadCounter(ms MetricServer, repo string) {
	dCounter := CounterValue{
		Name:        repoDownloads,
		LabelNames:  []string{"repo"},
		LabelValues: []string{repo},
	}
	ms.SendMetric(dCounter)
}

func IncUploadCounter(ms MetricServer, repo string) {
	uCounter := CounterValue{
		Name:        repoUploads,
		LabelNames:  []string{"repo"},
		LabelValues: []string{repo},
	}
	ms.SendMetric(uCounter)
}

func SetStorageUsage(ms MetricServer, rootDir, repo string) {
	dir := path.Join(rootDir, repo)

	repoSize, err := GetDirSize(dir)
	if err != nil {
		ms.(*metricServer).log.Error().Err(err).Msg("failed to set storage usage")
	}

	storage := GaugeValue{
		Name:        repoStorageBytes,
		Value:       float64(repoSize),
		LabelNames:  []string{"repo"},
		LabelValues: []string{repo},
	}
	ms.ForceSendMetric(storage)
}

func SetServerInfo(ms MetricServer, lvs ...string) {
	info := GaugeValue{
		Name:        serverInfo,
		Value:       0,
		LabelNames:  []string{"commit", "binaryType", "goVersion", "version"},
		LabelValues: lvs,
	}
	// This metric is set once at zot startup (set it regardless of metrics enabled)
	ms.ForceSendMetric(info)
}

func ObserveStorageLockLatency(ms MetricServer, latency time.Duration, storageName, lockType string) {
	h := HistogramValue{
		Name:        storageLockLatencySeconds,
		Sum:         latency.Seconds(), // convenient temporary store for Histogram latency value
		LabelNames:  []string{"storageName", "lockType"},
		LabelValues: []string{storageName, lockType},
	}
	ms.SendMetric(h)
}

func GetMaxIdleScrapeInterval() time.Duration {
	return metricsScrapeTimeout + metricsScrapeCheckInterval
}

func GetBuckets(metricName string) []float64 {
	switch metricName {
	case storageLockLatencySeconds:
		return GetStorageLatencyBuckets()
	default:
		return GetDefaultBuckets()
	}
}

func SetSchedulerNumWorkers(ms MetricServer, workers int) {
	numWorkers := GaugeValue{
		Name:  schedulerNumWorkers,
		Value: float64(workers),
	}
	ms.ForceSendMetric(numWorkers)
}

func IncSchedulerGenerators(ms MetricServer) {
	genCounter := CounterValue{
		Name: schedulerGenerators,
	}
	ms.ForceSendMetric(genCounter)
}

func ObserveWorkersTasksDuration(ms MetricServer, taskName string, duration time.Duration) {
	h := HistogramValue{
		Name:        workersTasksDuration,
		Sum:         duration.Seconds(), // convenient temporary store for Histogram latency value
		LabelNames:  []string{"name"},
		LabelValues: []string{taskName},
	}
	ms.SendMetric(h)
}

func SetSchedulerGenerators(ms MetricServer, gen map[string]map[string]uint64) {
	for priority, states := range gen {
		for state, value := range states {
			generator := GaugeValue{
				Name:        schedulerGeneratorsStatus,
				Value:       float64(value),
				LabelNames:  []string{"priority", "state"},
				LabelValues: []string{priority, state},
			}
			ms.SendMetric(generator)
		}
	}
}

func SetSchedulerTasksQueue(ms MetricServer, tq map[string]int) {
	for priority, value := range tq {
		tasks := GaugeValue{
			Name:        schedulerTasksQueue,
			Value:       float64(value),
			LabelNames:  []string{"priority"},
			LabelValues: []string{priority},
		}
		ms.SendMetric(tasks)
	}
}

func SetSchedulerWorkers(ms MetricServer, w map[string]int) {
	for state, value := range w {
		workers := GaugeValue{
			Name:        schedulerWorkers,
			Value:       float64(value),
			LabelNames:  []string{"state"},
			LabelValues: []string{state},
		}
		ms.SendMetric(workers)
	}
}
