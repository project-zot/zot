//go:build sync

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// Tokens are refreshed once their remaining validity drops below oauth2ExpiryWindow,
// and assumed to live defaultAccessTokenLifetime when the endpoint omits expires_in.
const (
	oauth2ExpiryWindow         = 1 * time.Minute
	defaultAccessTokenLifetime = 5 * time.Minute
	oauth2RequestTimeout       = 30 * time.Second
	maxErrorBodyBytes          = 1024

	clientCredentialsGrantType = "client_credentials"
	jwtBearerGrantType         = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // not a credential
	clientAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	oauth2TokenUser = "<token>"
)

var (
	errOAuth2ConfigMissing    = errors.New("oauth2 credential helper requires oauth2HelperConfig")
	errOAuth2TokenURLMissing  = errors.New("oauth2 credential helper requires a tokenURL")
	errOAuth2AssertionMissing = errors.New("oauth2 credential helper requires an assertionFile")
	errOAuth2ReadAssertion    = errors.New("unable to read the oauth2 assertion file")
	errOAuth2ReadSecret       = errors.New("unable to read the oauth2 client secret file")
	errOAuth2ExchangeFailed   = errors.New("failed to exchange the oauth2 assertion for an access token")
	errOAuth2UnexpectedStatus = errors.New("unexpected status code from the oauth2 token endpoint")
	errOAuth2DecodeResponse   = errors.New("unable to decode the oauth2 token response")
	errOAuth2EmptyAccessToken = errors.New("the oauth2 token endpoint returned an empty access token")
	errFailedToGetOAuth2Creds = errors.New("failed to get oauth2 credentials")
)

type oauth2Token struct {
	accessToken string
	expiry      time.Time
}

type oauth2CredentialsHelper struct {
	config     *syncconf.OAuth2HelperConfig
	httpClient *http.Client
	mu         sync.RWMutex
	tokens     map[string]oauth2Token
	log        log.Logger
}

type oauth2TokenResponse struct {
	AccessToken string `json:"access_token"` //nolint:tagliatelle // OAuth2 token response field
	TokenType   string `json:"token_type"`   //nolint:tagliatelle // OAuth2 token response field
	ExpiresIn   int    `json:"expires_in"`   //nolint:tagliatelle // OAuth2 token response field
}

// NewOAuth2CredentialHelper exchanges a JWT assertion for a short-lived registry
// access token using an OAuth2 token endpoint.
func NewOAuth2CredentialHelper(
	log log.Logger,
	config *syncconf.OAuth2HelperConfig,
) (CredentialHelper, error) {
	if config == nil {
		return nil, errOAuth2ConfigMissing
	}

	if config.TokenURL == "" {
		return nil, errOAuth2TokenURLMissing
	}

	if config.AssertionFile == "" {
		return nil, errOAuth2AssertionMissing
	}

	return &oauth2CredentialsHelper{
		config:     config,
		httpClient: &http.Client{Timeout: oauth2RequestTimeout},
		tokens:     make(map[string]oauth2Token),
		log:        log,
	}, nil
}

func (credHelper *oauth2CredentialsHelper) grantType() string {
	if credHelper.config.GrantType != "" {
		return credHelper.config.GrantType
	}

	return clientCredentialsGrantType
}

func (credHelper *oauth2CredentialsHelper) username() string {
	if credHelper.config.Username != "" {
		return credHelper.config.Username
	}

	return oauth2TokenUser
}

func (credHelper *oauth2CredentialsHelper) clientSecret() (string, error) {
	if credHelper.config.ClientSecretFile == "" {
		return "", nil
	}

	secret, err := os.ReadFile(credHelper.config.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("%w %s: %w", errOAuth2ReadSecret, credHelper.config.ClientSecretFile, err)
	}

	return strings.TrimSpace(string(secret)), nil
}

func (credHelper *oauth2CredentialsHelper) requestValues(assertion, clientSecret string) url.Values {
	values := url.Values{}

	grantType := credHelper.grantType()
	values.Set("grant_type", grantType)

	if grantType == jwtBearerGrantType {
		values.Set("assertion", assertion)
	} else {
		values.Set("client_assertion_type", clientAssertionType)
		values.Set("client_assertion", assertion)
	}

	if credHelper.config.ClientID != "" {
		values.Set("client_id", credHelper.config.ClientID)
	}

	if clientSecret != "" {
		values.Set("client_secret", clientSecret)
	}

	if len(credHelper.config.Scopes) > 0 {
		values.Set("scope", strings.Join(credHelper.config.Scopes, " "))
	}

	return values
}

func (credHelper *oauth2CredentialsHelper) fetchToken() (oauth2Token, error) {
	assertion, err := os.ReadFile(credHelper.config.AssertionFile)
	if err != nil {
		return oauth2Token{}, fmt.Errorf("%w %s: %w", errOAuth2ReadAssertion, credHelper.config.AssertionFile, err)
	}

	clientSecret, err := credHelper.clientSecret()
	if err != nil {
		return oauth2Token{}, err
	}

	values := credHelper.requestValues(strings.TrimSpace(string(assertion)), clientSecret)

	ctx, cancel := context.WithTimeout(context.Background(), oauth2RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, credHelper.config.TokenURL, strings.NewReader(values.Encode()),
	)
	if err != nil {
		return oauth2Token{}, fmt.Errorf("%w: %w", errOAuth2ExchangeFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := credHelper.httpClient.Do(req)
	if err != nil {
		return oauth2Token{}, fmt.Errorf("%w: %w", errOAuth2ExchangeFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		bodyText := strings.TrimSpace(string(body))

		return oauth2Token{}, fmt.Errorf("%w: %d %s", errOAuth2UnexpectedStatus, resp.StatusCode, bodyText)
	}

	var tokenResp oauth2TokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return oauth2Token{}, fmt.Errorf("%w: %w", errOAuth2DecodeResponse, err)
	}

	if tokenResp.AccessToken == "" {
		return oauth2Token{}, errOAuth2EmptyAccessToken
	}

	lifetime := defaultAccessTokenLifetime
	if tokenResp.ExpiresIn > 0 {
		lifetime = time.Duration(tokenResp.ExpiresIn) * time.Second
	}

	return oauth2Token{
		accessToken: tokenResp.AccessToken,
		expiry:      time.Now().Add(lifetime),
	}, nil
}

func (credHelper *oauth2CredentialsHelper) storeToken(remoteAddress string, token oauth2Token) {
	credHelper.mu.Lock()
	defer credHelper.mu.Unlock()

	credHelper.tokens[remoteAddress] = token
}

func (credHelper *oauth2CredentialsHelper) tokenExpiry(remoteAddress string) time.Time {
	credHelper.mu.RLock()
	defer credHelper.mu.RUnlock()

	return credHelper.tokens[remoteAddress].expiry
}

// GetCredentials retrieves access tokens for the provided list of registry URLs.
func (credHelper *oauth2CredentialsHelper) GetCredentials(urls []string) (syncconf.CredentialsFile, error) {
	credentials := make(syncconf.CredentialsFile)

	for _, registryURL := range urls {
		remoteAddress := StripRegistryTransport(registryURL)

		token, err := credHelper.fetchToken()
		if err != nil {
			return syncconf.CredentialsFile{}, fmt.Errorf("%w %s: %w", errFailedToGetOAuth2Creds, registryURL, err)
		}

		credHelper.storeToken(remoteAddress, token)
		credentials[remoteAddress] = syncconf.Credentials{
			Username: credHelper.username(),
			Password: token.accessToken,
		}
	}

	return credentials, nil
}

func (credHelper *oauth2CredentialsHelper) AreCredentialsValid(remoteAddress string) bool {
	expiry := credHelper.tokenExpiry(remoteAddress)

	if time.Until(expiry) <= oauth2ExpiryWindow {
		credHelper.log.Debug().
			Str("url", remoteAddress).
			Msg("the oauth2 credentials are close to expiring")

		return false
	}

	credHelper.log.Debug().
		Str("url", remoteAddress).
		Msg("the oauth2 credentials are valid")

	return true
}

func (credHelper *oauth2CredentialsHelper) RefreshCredentials(remoteAddress string) (syncconf.Credentials, error) {
	credHelper.log.Info().Str("url", remoteAddress).Msg("refreshing the oauth2 credentials")

	token, err := credHelper.fetchToken()
	if err != nil {
		return syncconf.Credentials{}, fmt.Errorf("%w %s: %w", errFailedToGetOAuth2Creds, remoteAddress, err)
	}

	credHelper.storeToken(remoteAddress, token)

	return syncconf.Credentials{Username: credHelper.username(), Password: token.accessToken}, nil
}
