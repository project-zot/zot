// +build minimal

package api

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	up = prometheus.NewDesc(
		"zot_up",
		"Connection to zot server was successfully established.",
		nil, nil,
	)
	invalidChars = regexp.MustCompile("[^a-zA-Z0-9:_]")
)

type ZotCollector struct {
	mc *monitoring.MetricsClient
}

// Implements prometheus.Collector
func (zc ZotCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
}

// Implements prometheus.Collector
func (zc ZotCollector) Collect(ch chan<- prometheus.Metric) {
	metrics, err := zc.mc.GetMetrics()

	if err != nil {
		fmt.Println(err)
		ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(up, prometheus.GaugeValue, 1)

	for _, g := range metrics.Gauges {
		name := invalidChars.ReplaceAllLiteralString(g.Name, "_")
		desc := prometheus.NewDesc(name, "Zot metric "+g.Name, g.LabelNames, nil)
		ch <- prometheus.MustNewConstMetric(
			desc, prometheus.GaugeValue, float64(g.Value), g.LabelValues...)
	}

	for _, c := range metrics.Counters {
		name := invalidChars.ReplaceAllLiteralString(c.Name, "_")
		desc := prometheus.NewDesc(name+"_total", "Zot metric "+c.Name, c.LabelNames, nil)
		ch <- prometheus.MustNewConstMetric(
			desc, prometheus.CounterValue, float64(c.Count), c.LabelValues...)
	}

	for _, s := range metrics.Samples {
		name := invalidChars.ReplaceAllLiteralString(s.Name, "_")
		countDesc := prometheus.NewDesc(
			name+"_count", "Zot metric "+s.Name, s.LabelNames, nil)
		ch <- prometheus.MustNewConstMetric(
			countDesc, prometheus.CounterValue, float64(s.Count), s.LabelValues...)
		sumDesc := prometheus.NewDesc(
			name+"_sum", "Zot metric "+s.Name, s.LabelNames, nil)
		ch <- prometheus.MustNewConstMetric(
			sumDesc, prometheus.CounterValue, s.Sum, s.LabelValues...)
		if s.Buckets != nil {
			for _, fvalue := range monitoring.GetDefaultBuckets() {
				svalue := monitoring.BucketConvFloat2String(fvalue)

				countDesc = prometheus.NewDesc(
					name+"_bucket", "Zot metric "+s.Name, append(s.LabelNames, "le"), nil)
				ch <- prometheus.MustNewConstMetric(
					countDesc, prometheus.CounterValue, float64(s.Buckets[svalue]), append(s.LabelValues, svalue)...)
			}
		}
	}
}

func runZotExporter(c *Controller) {
	// parameters to connect to the zot server
	zotServerAddr := fmt.Sprintf("%s://%s:%s", c.config.ZotServer.Protocol, c.config.ZotServer.Host, c.config.ZotServer.Port)
	cfg := &monitoring.ZotMetricsConfig{Address: zotServerAddr}
	zc := ZotCollector{mc: monitoring.NewMetricsClient(cfg, c.log)}
	prometheus.MustRegister(zc)

	http.Handle(c.config.ZotExporter.Metrics.Path, promhttp.Handler())
	zotExporterAddr := fmt.Sprintf(":%s", c.config.ZotExporter.Port)
	c.log.Info().Msgf("Zot app exporter is listening on %s & exposes metrics on %s path", zotExporterAddr, c.config.ZotExporter.Metrics.Path)
	c.log.Info().Msgf("Scraping metrics from %s", zotServerAddr)
	c.log.Fatal().Err(http.ListenAndServe(zotExporterAddr, nil)).Msg("Zot app exporter stopped")
}
