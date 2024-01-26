//go:build !metrics
// +build !metrics

//nolint:varnamelen
package api

import (
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
)

const (
	idleTimeout       = 120 * time.Second
	readHeaderTimeout = 5 * time.Second
)

type Collector struct {
	Client       *monitoring.MetricsClient
	MetricsDesc  map[string]*prometheus.Desc // all known metrics descriptions
	invalidChars *regexp.Regexp
}

// Implements prometheus.Collector interface.
func (zc Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, metricDescription := range zc.MetricsDesc {
		ch <- metricDescription
	}
}

// Implements prometheus.Collector interface.
func (zc Collector) Collect(ch chan<- prometheus.Metric) {
	metrics, err := zc.Client.GetMetrics()
	if err != nil {
		fmt.Printf("error getting metrics: %v\n", err)
		ch <- prometheus.MustNewConstMetric(zc.MetricsDesc["zot_up"], prometheus.GaugeValue, 0)

		return
	}
	ch <- prometheus.MustNewConstMetric(zc.MetricsDesc["zot_up"], prometheus.GaugeValue, 1)

	for _, g := range metrics.Gauges {
		name := zc.invalidChars.ReplaceAllLiteralString(g.Name, "_")
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.GaugeValue, g.Value, g.LabelValues...)
	}

	for _, c := range metrics.Counters {
		name := zc.invalidChars.ReplaceAllLiteralString(c.Name, "_")
		name += "_total"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, float64(c.Count), c.LabelValues...)
	}

	for _, summary := range metrics.Summaries {
		mname := zc.invalidChars.ReplaceAllLiteralString(summary.Name, "_")
		name := mname + "_count"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, float64(summary.Count), summary.LabelValues...)

		name = mname + "_sum"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, summary.Sum, summary.LabelValues...)
	}

	for _, h := range metrics.Histograms {
		mname := zc.invalidChars.ReplaceAllLiteralString(h.Name, "_")
		name := mname + "_count"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, float64(h.Count), h.LabelValues...)

		name = mname + "_sum"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, h.Sum, h.LabelValues...)

		if h.Buckets != nil {
			for _, fvalue := range monitoring.GetBuckets(h.Name) {
				var svalue string
				if fvalue == math.MaxFloat64 {
					svalue = "+Inf"
				} else {
					svalue = strconv.FormatFloat(fvalue, 'f', -1, 64)
				}

				name = mname + "_bucket"
				ch <- prometheus.MustNewConstMetric(
					zc.MetricsDesc[name], prometheus.CounterValue, float64(h.Buckets[svalue]), append(h.LabelValues, svalue)...)
			}
		}
	}
}

func panicOnDuplicateMetricName(m map[string]*prometheus.Desc, name string, log log.Logger) {
	if _, present := m[name]; present {
		log.Fatal().Str("metric", name).Msg("duplicate key found")
	}
}

func GetCollector(c *Controller) *Collector {
	// compute all metrics description map
	MetricsDesc := map[string]*prometheus.Desc{
		"zot_up": prometheus.NewDesc(
			"zot_up",
			"Connection to zot server was successfully established.",
			nil, nil,
		),
	}
	invalidChars := regexp.MustCompile("[^a-zA-Z0-9:_]")

	for metricName, metricLabelNames := range monitoring.GetCounters() {
		name := invalidChars.ReplaceAllLiteralString(metricName, "_")
		name += "_total"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetGauges() {
		name := invalidChars.ReplaceAllLiteralString(metricName, "_")
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetSummaries() {
		mname := invalidChars.ReplaceAllLiteralString(metricName, "_")

		name := mname + "_count"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)

		name = mname + "_sum"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetHistograms() {
		mname := invalidChars.ReplaceAllLiteralString(metricName, "_")

		name := mname + "_count"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)

		name = mname + "_sum"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, metricLabelNames, nil)

		name = mname + "_bucket"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		// Append a new label to hitogram bucket - le - 'lower or equal'
		MetricsDesc[name] = prometheus.NewDesc(name, "Metric "+name, append(metricLabelNames, "le"), nil)
	}

	// parameters to connect to the zot server
	serverAddr := fmt.Sprintf("%s://%s:%s", c.Config.Server.Protocol,
		c.Config.Server.Host, c.Config.Server.Port)
	cfg := &monitoring.MetricsConfig{Address: serverAddr}

	return &Collector{
		Client:       monitoring.NewMetricsClient(cfg, c.Log),
		MetricsDesc:  MetricsDesc,
		invalidChars: invalidChars,
	}
}

func runExporter(c *Controller) {
	exporterAddr := fmt.Sprintf(":%s", c.Config.Exporter.Port)
	server := &http.Server{
		Addr:              exporterAddr,
		IdleTimeout:       idleTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	err := prometheus.Register(GetCollector(c))
	if err != nil {
		c.Log.Debug().Err(err).Msg("ignoring error")
	}

	http.Handle(c.Config.Exporter.Metrics.Path, promhttp.Handler())
	c.Log.Info().Str("addr", exporterAddr).
		Str("path", c.Config.Exporter.Metrics.Path).
		Msg("exporter listening")

	serverAddr := fmt.Sprintf("%s://%s:%s", c.Config.Server.Protocol,
		c.Config.Server.Host, c.Config.Server.Port)
	c.Log.Info().Str("serverAddr", serverAddr).Msg("scraping metrics")
	c.Log.Fatal().Err(server.ListenAndServe()).Msg("exporter stopped")
}
