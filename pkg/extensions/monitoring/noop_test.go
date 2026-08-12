package monitoring_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
)

func TestNopMetricServer(t *testing.T) {
	Convey("nop MetricServer discards metrics without panicking", t, func() {
		metricsServer := monitoring.NewNopMetricServer()

		So(metricsServer.IsEnabled(), ShouldBeFalse)
		So(func() { metricsServer.SendMetric(monitoring.CounterValue{Name: "x"}) }, ShouldNotPanic)
		So(func() { metricsServer.ForceSendMetric(monitoring.GaugeValue{Name: "y"}) }, ShouldNotPanic)
		So(metricsServer.ReceiveMetrics(), ShouldResemble, monitoring.MetricsCopy{})
		So(func() { metricsServer.Stop() }, ShouldNotPanic)

		// SetStorageUsage used to type-assert *metricServer; must tolerate nop.
		So(func() {
			monitoring.SetStorageUsage(metricsServer, t.TempDir(), "missing-repo")
		}, ShouldNotPanic)
	})
}
