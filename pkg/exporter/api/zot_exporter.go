// +build minimal

package api

import (
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"

	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/anuvu/zot/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ZotCollector struct {
	Client       *monitoring.MetricsClient
	MetricsDesc  map[string]*prometheus.Desc // all known metrics descriptions
	invalidChars *regexp.Regexp
}

// Implements prometheus.Collector interface.
func (zc ZotCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metricDescription := range zc.MetricsDesc {
		ch <- metricDescription
	}
}

// Implements prometheus.Collector interface.
func (zc ZotCollector) Collect(ch chan<- prometheus.Metric) {
	metrics, err := zc.Client.GetMetrics()

	if err != nil {
		fmt.Println(err)
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

	for _, s := range metrics.Summaries {
		mname := zc.invalidChars.ReplaceAllLiteralString(s.Name, "_")
		name := mname + "_count"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, float64(s.Count), s.LabelValues...)

		name = mname + "_sum"
		ch <- prometheus.MustNewConstMetric(
			zc.MetricsDesc[name], prometheus.CounterValue, s.Sum, s.LabelValues...)
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
			for _, fvalue := range monitoring.GetDefaultBuckets() {
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
		log.Fatal().Msg("Duplicate keys: metric " + name + " already present")
	}
}

func GetZotCollector(c *Controller) *ZotCollector {
	//compute all metrics description map
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
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetGauges() {
		name := invalidChars.ReplaceAllLiteralString(metricName, "_")
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetSummaries() {
		mname := invalidChars.ReplaceAllLiteralString(metricName, "_")

		name := mname + "_count"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)

		name = mname + "_sum"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)
	}

	for metricName, metricLabelNames := range monitoring.GetHistograms() {
		mname := invalidChars.ReplaceAllLiteralString(metricName, "_")

		name := mname + "_count"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)

		name = mname + "_sum"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, metricLabelNames, nil)

		name = mname + "_bucket"
		panicOnDuplicateMetricName(MetricsDesc, name, c.Log)
		// Append a new label to hitogram bucket - le - 'lower or equal'
		MetricsDesc[name] = prometheus.NewDesc(name, "Zot metric "+name, append(metricLabelNames, "le"), nil)
	}

	// parameters to connect to the zot server
	zotServerAddr := fmt.Sprintf("%s://%s:%s", c.Config.ZotServer.Protocol,
		c.Config.ZotServer.Host, c.Config.ZotServer.Port)
	cfg := &monitoring.ZotMetricsConfig{Address: zotServerAddr}

	return &ZotCollector{
		Client:       monitoring.NewMetricsClient(cfg, c.Log),
		MetricsDesc:  MetricsDesc,
		invalidChars: invalidChars,
	}
}

func runZotExporter(c *Controller) {
	err := prometheus.Register(GetZotCollector(c))
	if err != nil {
		c.Log.Error().Err(err).Msg("Expected error in testing")
	}

	http.Handle(c.Config.ZotExporter.Metrics.Path, promhttp.Handler())
	zotExporterAddr := fmt.Sprintf(":%s", c.Config.ZotExporter.Port)
	c.Log.Info().Msgf("Zot app exporter is listening on %s & exposes metrics on %s path",
		zotExporterAddr, c.Config.ZotExporter.Metrics.Path)

	zotServerAddr := fmt.Sprintf("%s://%s:%s", c.Config.ZotServer.Protocol,
		c.Config.ZotServer.Host, c.Config.ZotServer.Port)
	c.Log.Info().Msgf("Scraping metrics from %s", zotServerAddr)
	c.Log.Fatal().Err(http.ListenAndServe(zotExporterAddr, nil)).Msg("Zot app exporter stopped")
}
