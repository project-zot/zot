package client

import (
	"net/http"
	"net/url"
	"sync"

	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
)

type Config struct {
	URL       string
	Username  string
	Password  string
	CertDir   string
	TLSVerify bool
}

type Client struct {
	config *Config
	client *http.Client
	url    *url.URL
	lock   *sync.RWMutex
	log    log.Logger
}

func New(config Config, log log.Logger) (*Client, error) {
	client := &Client{log: log, lock: new(sync.RWMutex)}
	if err := client.SetConfig(config); err != nil {
		return nil, err
	}

	return client, nil
}

func (httpClient *Client) GetConfig() *Config {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	return httpClient.config
}

func (httpClient *Client) GetHostname() string {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	return httpClient.url.Host
}

func (httpClient *Client) SetConfig(config Config) error {
	httpClient.lock.Lock()
	defer httpClient.lock.Unlock()

	clientURL, err := url.Parse(config.URL)
	if err != nil {
		return err
	}

	httpClient.url = clientURL

	client, err := common.CreateHTTPClient(config.TLSVerify, clientURL.Host, config.CertDir)
	if err != nil {
		return err
	}

	httpClient.client = client
	httpClient.config = &config

	return nil
}

func (httpClient *Client) IsAvailable() bool {
	_, _, statusCode, err := httpClient.MakeGetRequest(nil, "", "/v2/")
	if err != nil || statusCode != http.StatusOK {
		return false
	}

	return true
}

func (httpClient *Client) MakeGetRequest(resultPtr interface{}, mediaType string,
	route ...string,
) ([]byte, string, int, error) {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	url := *httpClient.url

	for _, r := range route {
		url = *url.JoinPath(r)
	}

	url.RawQuery = url.Query().Encode()

	body, mediaType, statusCode, err := common.MakeHTTPGetRequest(httpClient.client, httpClient.config.Username,
		httpClient.config.Password, resultPtr,
		url.String(), mediaType, httpClient.log)

	return body, mediaType, statusCode, err
}
