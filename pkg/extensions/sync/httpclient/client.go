package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
)

const (
	minimumTokenLifetimeSeconds = 60 // in seconds
	pingTimeout                 = 5 * time.Second
	// tokenBuffer is used to renew a token before it actually expires
	// to account for the time to process requests on the server.
	tokenBuffer = 5 * time.Second
)

type authType int

const (
	noneAuth authType = iota
	basicAuth
	tokenAuth
)

type challengeParams struct {
	realm   string
	service string
	scope   string
	err     string
}

type bearerToken struct {
	Token          string    `json:"token"`        //nolint: tagliatelle
	AccessToken    string    `json:"access_token"` //nolint: tagliatelle
	ExpiresIn      int       `json:"expires_in"`   //nolint: tagliatelle
	IssuedAt       time.Time `json:"issued_at"`    //nolint: tagliatelle
	expirationTime time.Time
}

func (token *bearerToken) isExpired() bool {
	// use tokenBuffer to expire it a bit earlier
	return time.Now().After(token.expirationTime.Add(-1 * tokenBuffer))
}

type Config struct {
	URL       string
	Username  string
	Password  string
	CertDir   string
	TLSVerify bool
}

type Client struct {
	config   *Config
	client   *http.Client
	url      *url.URL
	authType authType
	cache    *TokenCache
	lock     *sync.RWMutex
	log      log.Logger
}

func New(config Config, log log.Logger) (*Client, error) {
	client := &Client{log: log, lock: new(sync.RWMutex)}

	client.cache = NewTokenCache()

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

func (httpClient *Client) GetBaseURL() string {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	return httpClient.url.String()
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
	httpClient.lock.Lock()
	defer httpClient.lock.Unlock()

	pingURL := *httpClient.url

	pingURL = *pingURL.JoinPath("/v2/")

	// for the ping function we want to timeout fast
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	//nolint: bodyclose
	resp, _, err := httpClient.get(ctx, pingURL.String(), false)
	if err != nil {
		return false
	}

	httpClient.getAuthType(resp)

	if resp.StatusCode >= http.StatusOK && resp.StatusCode <= http.StatusForbidden {
		return true
	}

	httpClient.log.Error().Str("url", pingURL.String()).Int("statusCode", resp.StatusCode).
		Str("component", "sync").Msg("failed to ping registry")

	return false
}

func (httpClient *Client) MakeGetRequest(ctx context.Context, resultPtr interface{}, mediaType string,
	route ...string,
) ([]byte, string, int, error) {
	httpClient.lock.RLock()
	defer httpClient.lock.RUnlock()

	var namespace string

	url := *httpClient.url
	for idx, path := range route {
		url = *url.JoinPath(path)

		// we know that the second route argument is always the repo name.
		// need it for caching tokens, it's not used in requests made to authz server.
		if idx == 1 {
			namespace = path
		}
	}

	url.RawQuery = url.Query().Encode()
	//nolint: bodyclose,contextcheck
	resp, body, err := httpClient.makeAndDoRequest(http.MethodGet, mediaType, namespace, url.String())
	if err != nil {
		httpClient.log.Error().Err(err).Str("url", url.String()).Str("component", "sync").
			Str("errorType", common.TypeOf(err)).
			Msg("failed to make request")

		return nil, "", -1, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", resp.StatusCode, errors.New(string(body)) //nolint:goerr113
	}

	// read blob
	if len(body) > 0 {
		err = json.Unmarshal(body, &resultPtr)
	}

	return body, resp.Header.Get("Content-Type"), resp.StatusCode, err
}

func (httpClient *Client) getAuthType(resp *http.Response) {
	authHeader := resp.Header.Get("www-authenticate")

	authHeaderLower := strings.ToLower(authHeader)

	//nolint: gocritic
	if strings.Contains(authHeaderLower, "bearer") {
		httpClient.authType = tokenAuth
	} else if strings.Contains(authHeaderLower, "basic") {
		httpClient.authType = basicAuth
	} else {
		httpClient.authType = noneAuth
	}
}

func (httpClient *Client) setupAuth(req *http.Request, namespace string) error {
	if httpClient.authType == tokenAuth {
		token, err := httpClient.getToken(req.URL.String(), namespace)
		if err != nil {
			httpClient.log.Error().Err(err).Str("url", req.URL.String()).Str("component", "sync").
				Str("errorType", common.TypeOf(err)).
				Msg("failed to get token from authorization realm")

			return err
		}

		req.Header.Set("Authorization", "Bearer "+token.Token)
	} else if httpClient.authType == basicAuth {
		req.SetBasicAuth(httpClient.config.Username, httpClient.config.Password)
	}

	return nil
}

func (httpClient *Client) get(ctx context.Context, url string, setAuth bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint
	if err != nil {
		return nil, nil, err
	}

	if setAuth && httpClient.config.Username != "" && httpClient.config.Password != "" {
		req.SetBasicAuth(httpClient.config.Username, httpClient.config.Password)
	}

	return httpClient.doRequest(req)
}

func (httpClient *Client) doRequest(req *http.Request) (*http.Response, []byte, error) {
	resp, err := httpClient.client.Do(req)
	if err != nil {
		httpClient.log.Error().Err(err).Str("url", req.URL.String()).Str("component", "sync").
			Str("errorType", common.TypeOf(err)).
			Msg("failed to make request")

		return nil, nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		httpClient.log.Error().Err(err).Str("url", req.URL.String()).
			Str("errorType", common.TypeOf(err)).
			Msg("failed to read body")

		return nil, nil, err
	}

	return resp, body, nil
}

func (httpClient *Client) makeAndDoRequest(method, mediaType, namespace, urlStr string,
) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, urlStr, nil) //nolint
	if err != nil {
		return nil, nil, err
	}

	if err := httpClient.setupAuth(req, namespace); err != nil {
		return nil, nil, err
	}

	if mediaType != "" {
		req.Header.Set("Accept", mediaType)
	}

	resp, body, err := httpClient.doRequest(req)
	if err != nil {
		return nil, nil, err
	}

	// let's retry one time if we get an insufficient_scope error
	if ok, challengeParams := needsRetryWithUpdatedScope(err, resp); ok {
		var tokenURL *url.URL

		var token *bearerToken

		tokenURL, err = getTokenURLFromChallengeParams(challengeParams, httpClient.config.Username)
		if err != nil {
			return nil, nil, err
		}

		token, err = httpClient.getTokenFromURL(tokenURL.String(), namespace)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Set("Authorization", "Bearer "+token.Token)

		resp, body, err = httpClient.doRequest(req)
	}

	return resp, body, err
}

func (httpClient *Client) getTokenFromURL(urlStr, namespace string) (*bearerToken, error) {
	//nolint: bodyclose
	resp, body, err := httpClient.get(context.Background(), urlStr, true)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, zerr.ErrUnauthorizedAccess
	}

	token, err := newBearerToken(body)
	if err != nil {
		return nil, err
	}

	// cache it
	httpClient.cache.Set(namespace, token)

	return token, nil
}

// Gets bearer token from Authorization realm.
func (httpClient *Client) getToken(urlStr, namespace string) (*bearerToken, error) {
	// first check cache
	token := httpClient.cache.Get(namespace)
	if token != nil && !token.isExpired() {
		return token, nil
	}

	//nolint: bodyclose
	resp, _, err := httpClient.get(context.Background(), urlStr, false)
	if err != nil {
		return nil, err
	}

	challengeParams, err := parseAuthHeader(resp)
	if err != nil {
		return nil, err
	}

	tokenURL, err := getTokenURLFromChallengeParams(challengeParams, httpClient.config.Username)
	if err != nil {
		return nil, err
	}

	return httpClient.getTokenFromURL(tokenURL.String(), namespace)
}

func newBearerToken(blob []byte) (*bearerToken, error) {
	token := new(bearerToken)
	if err := json.Unmarshal(blob, &token); err != nil {
		return nil, err
	}

	if token.Token == "" {
		token.Token = token.AccessToken
	}

	if token.ExpiresIn < minimumTokenLifetimeSeconds {
		token.ExpiresIn = minimumTokenLifetimeSeconds
	}

	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}

	token.expirationTime = token.IssuedAt.Add(time.Duration(token.ExpiresIn) * time.Second)

	return token, nil
}

func getTokenURLFromChallengeParams(params challengeParams, account string) (*url.URL, error) {
	parsedRealm, err := url.Parse(params.realm)
	if err != nil {
		return nil, err
	}

	query := parsedRealm.Query()
	query.Set("service", params.service)
	query.Set("scope", params.scope)

	if account != "" {
		query.Set("account", account)
	}

	parsedRealm.RawQuery = query.Encode()

	return parsedRealm, nil
}

func parseAuthHeader(resp *http.Response) (challengeParams, error) {
	authHeader := resp.Header.Get("www-authenticate")

	authHeaderSlice := strings.Split(authHeader, ",")

	params := challengeParams{}

	for _, elem := range authHeaderSlice {
		if strings.Contains(strings.ToLower(elem), "bearer") {
			elem = strings.Split(elem, " ")[1]
		}

		elem := strings.ReplaceAll(elem, "\"", "")

		elemSplit := strings.Split(elem, "=")
		if len(elemSplit) != 2 { //nolint: gomnd
			return params, zerr.ErrParsingAuthHeader
		}

		authKey := elemSplit[0]

		authValue := elemSplit[1]

		switch authKey {
		case "realm":
			params.realm = authValue
		case "service":
			params.service = authValue
		case "scope":
			params.scope = authValue
		case "error":
			params.err = authValue
		}
	}

	return params, nil
}

// Checks if the auth headers in the response contain an indication of a failed
// authorization because of an "insufficient_scope" error.
func needsRetryWithUpdatedScope(err error, resp *http.Response) (bool, challengeParams) {
	params := challengeParams{}
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		params, err = parseAuthHeader(resp)
		if err != nil {
			return false, params
		}

		if params.err == "insufficient_scope" {
			if params.scope != "" {
				return true, params
			}
		}
	}

	return false, params
}
