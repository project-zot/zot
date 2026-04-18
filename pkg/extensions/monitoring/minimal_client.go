//go:build !metrics

package monitoring

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	httpTimeout = 1 * time.Minute
)

// MetricsConfig is used to configure the creation of a Node Exporter http client
// that will connect to a particular zot instance.
type MetricsConfig struct {
	// Address of the zot http server
	Address string

	// CACert is an optional path to a PEM-encoded CA certificate file used to
	// verify the zot server's TLS certificate.  When empty the system cert pool
	// is used.  Set this when the zot server uses a self-signed or private CA.
	CACert string

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

func newHTTPMetricsClient(caCertFile string) (*http.Client, error) {
	var rootCAs *x509.CertPool

	if caCertFile != "" {
		caCertPool, err := x509.SystemCertPool()
		if err != nil || caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("metrics client: failed to read CA cert %s: %w", caCertFile, err)
		}

		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("metrics client: no valid PEM certificate found in %s", caCertFile)
		}

		rootCAs = caCertPool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}

	return &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
	}, nil
}

// NewMetricsClient creates a MetricsClient that can be used to retrieve in memory metrics.
// The new MetricsClient retrieved must be cached and reused by the Node Exporter
// in order to prevent concurrent memory leaks.
func NewMetricsClient(config *MetricsConfig, logger log.Logger) *MetricsClient {
	if config.HTTPClient == nil {
		client, err := newHTTPMetricsClient(config.CACert)
		if err != nil {
			logger.Error().Err(err).Msg("failed to create metrics HTTP client; falling back to TLS12/system-root transport")

			fallbackClient, fallbackErr := newHTTPMetricsClient("")
			if fallbackErr != nil {
				logger.Error().Err(fallbackErr).Msg("failed to create fallback metrics HTTP client; using default transport")
				config.HTTPClient = &http.Client{Timeout: httpTimeout}
			} else {
				config.HTTPClient = fallbackClient
			}
		} else {
			config.HTTPClient = client
		}
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

func (mc *MetricsClient) makeGETRequest(url string, resultsPtr any) (http.Header, error) {
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
