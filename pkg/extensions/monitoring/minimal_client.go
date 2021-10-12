// +build minimal

package monitoring

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"

	"github.com/anuvu/zot/pkg/log"
)

const (
	httpTimeout = 1 * time.Minute
)

// ZotMetricsConfig is used to configure the creation of a Node Exporter http client
// that will connect to a particular zot instance.
type ZotMetricsConfig struct {
	// Address of the zot http server
	Address string

	// Transport to use for the http client.
	Transport *http.Transport

	// HTTPClient is the client to use.
	HTTPClient *http.Client
}

type MetricsClient struct {
	headers http.Header
	config  ZotMetricsConfig
	log     log.Logger
}

func newHTTPMetricsClient() *http.Client {
	defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
	defaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: defaultTransport,
	}
}

// Creates a MetricsClient that can be used to retrieve in memory metrics
// The new MetricsClient retrieved must be cached  and reused by the Node Exporter
// in order to prevent concurrent memory leaks.
func NewMetricsClient(config *ZotMetricsConfig, logger log.Logger) *MetricsClient {
	if config.HTTPClient == nil {
		config.HTTPClient = newHTTPMetricsClient()
	}

	return &MetricsClient{config: *config, headers: make(http.Header), log: logger}
}

func (mc *MetricsClient) GetMetrics() (*MetricsInfo, error) {
	metrics := &MetricsInfo{}
	if _, err := mc.makeGETRequest(mc.config.Address+"/v2/metrics", metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}

func (mc *MetricsClient) makeGETRequest(url string, resultsPtr interface{}) (http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	resp, err := mc.config.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(resultsPtr); err != nil {
		return nil, err
	}

	return resp.Header, nil
}
