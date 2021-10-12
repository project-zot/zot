// +build minimal

package monitoring

import (
	"fmt"
	"math"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/anuvu/zot/pkg/log"
)

const (
	// Counters
	httpConnRequests = "zot.http.requests"
	repoDownloads    = "zot.repo.downloads"
	repoUploads      = "zot.repo.uploads"
	//Gauge
	repoStorageBytes = "zot.repo.storage.bytes"
	zotInfo          = "zot.info"
	//Summary
	httpRepoLatencySeconds = "zot.repo.latency.seconds"
	//Histogram
	httpMethodLatencySeconds = "zot.method.latency.seconds"

	metricsScrapeTimeout       = 2 * time.Minute
	metricsScrapeCheckInterval = 30 * time.Second
)

type metricServer struct {
	enabled    bool
	lastCheck  time.Time
	reqChan    chan interface{}
	cache      *MetricsInfo
	cacheChan  chan *MetricsInfo
	bucketsF2S map[float64]string // float64 to string conversion of buckets label
	log        log.Logger
}

type MetricsInfo struct {
	Counters   []*CounterValue
	Gauges     []*GaugeValue
	Summaries  []*SummaryValue
	Histograms []*HistogramValue
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

// implements the MetricServer interface.
func (ms *metricServer) SendMetric(metric interface{}) {
	if ms.enabled {
		ms.reqChan <- metric
	}
}

func (ms *metricServer) ForceSendMetric(metric interface{}) {
	ms.reqChan <- metric
}

func (ms *metricServer) ReceiveMetrics() interface{} {
	if !ms.enabled {
		ms.enabled = true
	}
	ms.cacheChan <- &MetricsInfo{}

	return <-ms.cacheChan
}

func (ms *metricServer) IsEnabled() (b bool) {
	// send a bool value on the request channel to avoid data race
	ms.reqChan <- b
	return (<-ms.reqChan).(bool)
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
			ms.cacheChan <- ms.cache
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
			case bool:
				ms.reqChan <- ms.enabled
			default:
				ms.log.Error().Msgf("unexpected type %T", v)
			}
		case <-sendAfter:
			// Check if we didn't receive a metrics scrape in a while and if so,
			// disable metrics (possible node exporter down/crashed)
			if ms.enabled {
				lastCheckInterval := time.Since(ms.lastCheck)
				if lastCheckInterval > metricsScrapeTimeout {
					ms.enabled = false
				}
			}
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

	for _, fvalue := range GetDefaultBuckets() {
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
		cacheChan:  make(chan *MetricsInfo),
		cache:      mi,
		bucketsF2S: bucketsFloat2String,
		log:        log,
	}

	go ms.Run()

	return ms
}

// contains a map with key=CounterName and value=CounterLabels.
func GetCounters() map[string][]string {
	return map[string][]string{
		httpConnRequests: {"method", "code"},
		repoDownloads:    {"repo"},
		repoUploads:      {"repo"},
	}
}

func GetGauges() map[string][]string {
	return map[string][]string{
		repoStorageBytes: {"repo"},
		zotInfo:          {"commit", "binaryType", "goVersion", "version"},
	}
}

func GetSummaries() map[string][]string {
	return map[string][]string{
		httpRepoLatencySeconds: {"repo"},
	}
}

func GetHistograms() map[string][]string {
	return map[string][]string{
		httpMethodLatencySeconds: {"method"},
	}
}

// return true if a metric does not have any labels or if the label
// values for searched metric corresponds to the one in the cached slice.
func isMetricMatch(lValues []string, metricValues []string) bool {
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
	kLabels, ok := GetCounters()[cv.Name] // known label names for the 'name' counter
	err := sanityChecks(cv.Name, kLabels, ok, cv.LabelNames, cv.LabelValues)

	if err != nil {
		// The last thing we want is to panic/stop the server due to instrumentation
		// thus log a message (should be detected during development of new metrics)
		ms.log.Error().Err(err).Msg("Instrumentation error")
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
	kLabels, ok := GetGauges()[gv.Name] // known label names for the 'name' counter
	err := sanityChecks(gv.Name, kLabels, ok, gv.LabelNames, gv.LabelValues)

	if err != nil {
		ms.log.Error().Err(err).Msg("Instrumentation error")
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
	kLabels, ok := GetSummaries()[sv.Name] // known label names for the 'name' summary
	err := sanityChecks(sv.Name, kLabels, ok, sv.LabelNames, sv.LabelValues)

	if err != nil {
		ms.log.Error().Err(err).Msg("Instrumentation error")
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
	kLabels, ok := GetHistograms()[hv.Name] // known label names for the 'name' counter
	err := sanityChecks(hv.Name, kLabels, ok, hv.LabelNames, hv.LabelValues)

	if err != nil {
		ms.log.Error().Err(err).Msg("Instrumentation error")
		return
	}

	index, ok := findHistogramValueIndex(ms.cache.Histograms, hv.Name, hv.LabelValues)
	if !ok {
		// The HistogramValue not found: add it
		buckets := make(map[string]int)

		for _, fvalue := range GetDefaultBuckets() {
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
		for _, fvalue := range GetDefaultBuckets() {
			if hv.Sum <= fvalue {
				cachedH.Buckets[ms.bucketsF2S[fvalue]]++
			}
		}
	}
}

// nolint: goerr113
func sanityChecks(name string, knownLabels []string, found bool, labelNames []string, labelValues []string) error {
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
	if ms.(*metricServer).enabled {
		var lvs []string

		re := regexp.MustCompile(`\/v2\/(.*?)\/(blobs|tags|manifests)\/(.*)$`)
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

func SetStorageUsage(ms MetricServer, rootDir string, repo string) {
	dir := path.Join(rootDir, repo)
	repoSize, err := getDirSize(dir)

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

func SetZotInfo(ms MetricServer, lvs ...string) {
	info := GaugeValue{
		Name:        zotInfo,
		Value:       0,
		LabelNames:  []string{"commit", "binaryType", "goVersion", "version"},
		LabelValues: lvs,
	}
	// This metric is set once at zot startup (set it regardless of metrics enabled)
	ms.ForceSendMetric(info)
}

func GetMaxIdleScrapeInterval() time.Duration {
	return metricsScrapeTimeout + metricsScrapeCheckInterval
}
