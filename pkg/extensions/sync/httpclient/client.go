package client

import (
	"context"
	"io"
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

func (httpClient *Client) Ping() bool {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	pingURL := *httpClient.url

	pingURL = *pingURL.JoinPath("/v2/")

	req, err := http.NewRequest(http.MethodGet, pingURL.String(), nil) //nolint
	if err != nil {
		return false
	}

	resp, err := httpClient.client.Do(req)
	if err != nil {
		httpClient.log.Error().Err(err).Str("url", pingURL.String()).
			Msg("sync: failed to ping registry")

		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		return true
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpClient.log.Error().Err(err).Str("url", pingURL.String()).
			Msg("failed to read body while pinging registry")

		return false
	}

	httpClient.log.Error().Str("url", pingURL.String()).Str("body", string(body)).Int("statusCode", resp.StatusCode).
		Msg("sync: failed to ping registry")

	return false
}

func (httpClient *Client) MakeGetRequest(ctx context.Context, resultPtr interface{}, mediaType string,
	route ...string,
) ([]byte, string, int, error) {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	url := *httpClient.url

	for _, r := range route {
		url = *url.JoinPath(r)
	}

	url.RawQuery = url.Query().Encode()

	body, mediaType, statusCode, err := common.MakeHTTPGetRequest(ctx, httpClient.client, httpClient.config.Username,
		httpClient.config.Password, resultPtr,
		url.String(), mediaType, httpClient.log)

	return body, mediaType, statusCode, err
}
