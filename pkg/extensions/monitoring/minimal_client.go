//go:build !metrics
// +build !metrics

package monitoring

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"zotregistry.dev/zot/pkg/log"
)

const (
	httpTimeout = 1 * time.Minute
)

// MetricsConfig is used to configure the creation of a Node Exporter http client
// that will connect to a particular zot instance.
type MetricsConfig struct {
	// Address of the zot http server
	Address string

	// Transport to use for the http client.
	Transport *http.Transport

	// HTTPClient is the client to use.
	HTTPClient *http.Client
}

type MetricsClient struct {
	headers http.Header
	config  MetricsConfig
	log     log.Logger
}

func newHTTPMetricsClient() *http.Client {
	defaultTransport := http.DefaultTransport.(*http.Transport).Clone()      //nolint: forcetypeassert
	defaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: defaultTransport,
	}
}

// Creates a MetricsClient that can be used to retrieve in memory metrics
// The new MetricsClient retrieved must be cached  and reused by the Node Exporter
// in order to prevent concurrent memory leaks.
func NewMetricsClient(config *MetricsConfig, logger log.Logger) *MetricsClient {
	if config.HTTPClient == nil {
		config.HTTPClient = newHTTPMetricsClient()
	}

	return &MetricsClient{config: *config, headers: make(http.Header), log: logger}
}

func (mc *MetricsClient) GetMetrics() (*MetricsInfo, error) {
	metrics := &MetricsInfo{}
	if _, err := mc.makeGETRequest(mc.config.Address+"/metrics", metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}

func (mc *MetricsClient) makeGETRequest(url string, resultsPtr interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("metric scraping failed: %w", err)
	}

	resp, err := mc.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metric scraping failed: %w", err)
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(resultsPtr); err != nil {
		return nil, fmt.Errorf("metric scraping failed: %w", err)
	}

	return resp.Header, nil
}
