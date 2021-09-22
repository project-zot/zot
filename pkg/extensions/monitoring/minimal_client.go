// +build minimal

package monitoring

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
)

const (
	httpTimeout = 1 * time.Minute
)

// ZotMetricsConfig is used to configure the creation of a Node Exporter http client that will connect to a particular zot instance
type ZotMetricsConfig struct {
	// Address of the zot http server
	Address string

	// Transport to use for the http client.
	Transport *http.Transport

	// HttpClient is the client to use.
	HttpClient *http.Client
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

// Creates a MetricsClient that can be used to retrive in memory metrics
// The new MetricsClient retrieved must be cached  and reused by the Node Exporter
// in order to prevent concurrent memory leaks
func NewMetricsClient(config *ZotMetricsConfig, logger log.Logger) *MetricsClient {
	if config.HttpClient == nil {
		config.HttpClient = newHTTPMetricsClient()
	}

	return &MetricsClient{config: *config, headers: make(http.Header), log: logger}
}

func (mc *MetricsClient) GetMetrics() (*MetricsInfo, error) {
	metrics := &MetricsInfo{}
	_, err := mc.makeGETRequest(mc.config.Address+"/v2/metrics", metrics)
	if err != nil {
		return nil, err
	}
	return metrics, nil
}

func (mc *MetricsClient) makeGETRequest(url string, resultsPtr interface{}) (http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	resp, err := mc.config.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, zotErrors.ErrUnauthorizedAccess
		}

		bodyBytes, _ := ioutil.ReadAll(resp.Body)

		return nil, errors.New(string(bodyBytes)) //nolint: goerr113
	}

	if err := json.NewDecoder(resp.Body).Decode(resultsPtr); err != nil {
		return nil, err
	}

	return resp.Header, nil
}
