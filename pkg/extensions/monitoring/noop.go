package monitoring

// nopMetricServer is a MetricServer that discards all metrics and does not
// start background goroutines. Use it for short-lived ImageStores (e.g. sync
// temp OCI layouts) that must satisfy the MetricServer dependency without
// leaking the Run() loops from NewMetricsServer under the !metrics build.
type nopMetricServer struct{}

// NewNopMetricServer returns a no-op MetricServer.
func NewNopMetricServer() MetricServer {
	return nopMetricServer{}
}

func (nopMetricServer) SendMetric(any) {}

func (nopMetricServer) ForceSendMetric(any) {}

func (nopMetricServer) ReceiveMetrics() any {
	return MetricsCopy{}
}

func (nopMetricServer) IsEnabled() bool {
	return false
}

func (nopMetricServer) Stop() {}
