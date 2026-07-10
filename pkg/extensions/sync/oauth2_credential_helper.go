//go:build sync

package sync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/golang-jwt/jwt/v5"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// Tokens are refreshed once their remaining validity drops below oauth2ExpiryWindow,
// and assumed to live defaultAccessTokenLifetime when the endpoint omits expires_in.
// A minted assertion is single-use, so its lifetime only needs to cover the exchange
// round-trip plus clock skew; it does not affect the access token's lifetime.
const (
	oauth2ExpiryWindow         = 1 * time.Minute
	defaultAccessTokenLifetime = 5 * time.Minute
	assertionLifetime          = 5 * time.Minute
	oauth2RequestTimeout       = 30 * time.Second
	maxErrorBodyBytes          = 1024

	clientCredentialsGrantType = "client_credentials"
	jwtBearerGrantType         = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // not a credential
	clientAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	oauth2TokenUser = "<token>"
)

var (
	errOAuth2ReadAssertion     = errors.New("unable to read the oauth2 assertion file")
	errOAuth2ReadSecret        = errors.New("unable to read the oauth2 client secret file")
	errOAuth2ReadSigningFile   = errors.New("unable to read the oauth2 signing file")
	errOAuth2DecodeSigningFile = errors.New("unable to decode the oauth2 signing file")
	errOAuth2SigningKeyMissing = errors.New("the oauth2 signing requires a privateKeyFile")
	errOAuth2ReadSigningKey    = errors.New("unable to read the oauth2 signing key file")
	errOAuth2ParseSigningKey   = errors.New("unable to parse the oauth2 signing key")
	errOAuth2UnsupportedAlg    = errors.New("unsupported oauth2 signing algorithm")
	errOAuth2GenerateJTI       = errors.New("unable to generate the oauth2 assertion id")
	errOAuth2SignAssertion     = errors.New("unable to sign the oauth2 assertion")
	errOAuth2ExchangeFailed    = errors.New("failed to exchange the oauth2 assertion for an access token")
	errOAuth2UnexpectedStatus  = errors.New("unexpected status code from the oauth2 token endpoint")
	errOAuth2DecodeResponse    = errors.New("unable to decode the oauth2 token response")
	errOAuth2EmptyAccessToken  = errors.New("the oauth2 token endpoint returned an empty access token")
	errFailedToGetOAuth2Creds  = errors.New("failed to get oauth2 credentials")
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

// oauth2SigningConfig is read from the file pointed to by SigningFile and holds the
// private key and claims used to mint a fresh JWT assertion on every token exchange. Keeping
// it in a dedicated file lets the signing key be mounted as a secret, separate from the main
// zot configuration.
type oauth2SigningConfig struct {
	PrivateKeyFile string `json:"privateKeyFile"` // path to a PEM-encoded private key
	Algorithm      string `json:"algorithm"`      // JWT signing algorithm, e.g. RS256 or ES256
	KeyID          string `json:"keyId"`          // optional "kid" header value
	Issuer         string `json:"issuer"`         // "iss" claim, defaults to clientID
	Subject        string `json:"subject"`        // "sub" claim, defaults to clientID
	Audience       string `json:"audience"`       // "aud" claim, defaults to tokenURL
}

// NewOAuth2CredentialHelper exchanges a JWT assertion for a short-lived registry
// access token using an OAuth2 token endpoint.
func NewOAuth2CredentialHelper(
	log log.Logger,
	config *syncconf.OAuth2HelperConfig,
) (CredentialHelper, error) {
	if err := config.Validate(); err != nil {
		return nil, err
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

// assertion returns the JWT assertion to exchange for an access token. When a signing file
// is set it mints a fresh, single-use assertion (unique "jti") in-code; otherwise it reads a
// pre-signed one from AssertionFile. Both sources are re-evaluated on every refresh.
func (credHelper *oauth2CredentialsHelper) assertion() (string, error) {
	if credHelper.config.SigningFile != "" {
		return credHelper.mintAssertion()
	}

	assertion, err := os.ReadFile(credHelper.config.AssertionFile)
	if err != nil {
		return "", fmt.Errorf("%w %s: %w", errOAuth2ReadAssertion, credHelper.config.AssertionFile, err)
	}

	return strings.TrimSpace(string(assertion)), nil
}

// mintAssertion reads the signing file and signs a fresh, single-use JWT assertion from it.
func (credHelper *oauth2CredentialsHelper) mintAssertion() (string, error) {
	raw, err := os.ReadFile(credHelper.config.SigningFile)
	if err != nil {
		return "", fmt.Errorf("%w %s: %w", errOAuth2ReadSigningFile, credHelper.config.SigningFile, err)
	}

	var signingConfig oauth2SigningConfig

	if err := json.Unmarshal(raw, &signingConfig); err != nil {
		return "", fmt.Errorf("%w %s: %w", errOAuth2DecodeSigningFile, credHelper.config.SigningFile, err)
	}

	method := jwt.GetSigningMethod(signingConfig.Algorithm)
	if method == nil {
		return "", fmt.Errorf("%w: %q", errOAuth2UnsupportedAlg, signingConfig.Algorithm)
	}

	key, err := credHelper.parseSigningKey(method, signingConfig)
	if err != nil {
		return "", err
	}

	jti, err := newAssertionID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": firstNonEmpty(signingConfig.Issuer, credHelper.config.ClientID),
		"sub": firstNonEmpty(signingConfig.Subject, credHelper.config.ClientID),
		"aud": firstNonEmpty(signingConfig.Audience, credHelper.config.TokenURL),
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
		"jti": jti, // unique per assertion, lets the endpoint reject replays (single-use)
	}

	token := jwt.NewWithClaims(method, claims)
	if signingConfig.KeyID != "" {
		token.Header["kid"] = signingConfig.KeyID
	}

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errOAuth2SignAssertion, err)
	}

	return signed, nil
}

// parseSigningKey loads the PEM-encoded private key and parses it according to the
// signing method family (RSA, ECDSA or EdDSA).
func (credHelper *oauth2CredentialsHelper) parseSigningKey(
	method jwt.SigningMethod, signingConfig oauth2SigningConfig,
) (any, error) {
	pemKey, err := signingKeyPEM(signingConfig)
	if err != nil {
		return nil, err
	}

	var key any

	switch method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		key, err = jwt.ParseRSAPrivateKeyFromPEM(pemKey)
	case *jwt.SigningMethodECDSA:
		key, err = jwt.ParseECPrivateKeyFromPEM(pemKey)
	case *jwt.SigningMethodEd25519:
		key, err = jwt.ParseEdPrivateKeyFromPEM(pemKey)
	default:
		return nil, fmt.Errorf("%w: %q", errOAuth2UnsupportedAlg, method.Alg())
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", errOAuth2ParseSigningKey, err)
	}

	return key, nil
}

// signingKeyPEM returns the PEM-encoded private key, from the file reference.
func signingKeyPEM(signingConfig oauth2SigningConfig) ([]byte, error) {
	if signingConfig.PrivateKeyFile != "" {
		pemKey, err := os.ReadFile(signingConfig.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", errOAuth2ReadSigningKey, signingConfig.PrivateKeyFile, err)
		}

		return pemKey, nil
	}

	return nil, errOAuth2SigningKeyMissing
}

// newAssertionID returns a cryptographically random identifier used as the assertion's
// "jti" claim so that every minted assertion is unique and can only be used once.
func newAssertionID() (string, error) {
	buf := make([]byte, 16) //nolint:mnd // 128 bits of randomness
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("%w: %w", errOAuth2GenerateJTI, err)
	}

	return hex.EncodeToString(buf), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func (credHelper *oauth2CredentialsHelper) fetchToken() (oauth2Token, error) {
	assertion, err := credHelper.assertion()
	if err != nil {
		return oauth2Token{}, err
	}

	clientSecret, err := credHelper.clientSecret()
	if err != nil {
		return oauth2Token{}, err
	}

	values := credHelper.requestValues(assertion, clientSecret)

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
// The token is not URL-specific, so a single exchange covers all URLs; this also
// keeps a single-use assertion from being replayed once per mirror.
func (credHelper *oauth2CredentialsHelper) GetCredentials(urls []string) (syncconf.CredentialsFile, error) {
	credentials := make(syncconf.CredentialsFile)

	if len(urls) == 0 {
		return credentials, nil
	}

	token, err := credHelper.fetchToken()
	if err != nil {
		return syncconf.CredentialsFile{}, fmt.Errorf("%w: %w", errFailedToGetOAuth2Creds, err)
	}

	for _, registryURL := range urls {
		remoteAddress := StripRegistryTransport(registryURL)

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
