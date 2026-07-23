package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
)

var (
	errTokenRequestBodyTooLarge       = errors.New("token request body too large")
	errInvalidWrappedBearerCredential = errors.New("invalid wrapped bearer credential")
)

const (
	wrappedCredentialBearerPrefix = "zot_cred_v1." //nolint:gosec // Public token marker, not a credential.
	wrappedCredentialVersion      = 1
	wrappedCredentialTypeAPIKey   = "api-key"
)

type tokenExchangeCredential struct {
	Username string
	Secret   string
}

type tokenExchangeRequest struct {
	credentials []tokenExchangeCredential
}

type localOIDCTokenOwner int

const (
	localOIDCTokenOwnerNone localOIDCTokenOwner = iota
	localOIDCTokenOwnerBearer
	localOIDCTokenOwnerOpenID
)

type unverifiedJWTClaims struct {
	issuer    string
	audiences []string
}

type wrappedCredentialBearer struct {
	Version  int    `json:"v"`
	Type     string `json:"typ"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

func normalizeTokenExchangeRequest(request *http.Request) (*tokenExchangeRequest, error) {
	tokenRequest := &tokenExchangeRequest{}

	username, password, ok := request.BasicAuth()
	if ok && password != "" {
		tokenRequest.addCredential(username, password)
	}

	if request.Body == nil || request.Body == http.NoBody || !isFormURLEncoded(request.Header.Get("Content-Type")) {
		return tokenRequest, nil
	}

	bodyBytes, err := readTokenRequestFormBody(request.Body)
	if err != nil {
		return nil, err
	}

	request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	form, parseErr := url.ParseQuery(string(bodyBytes))
	if parseErr != nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidTokenProxyForm, parseErr)
	}

	formUsername := form.Get("username")
	if formUsername == "" {
		formUsername = form.Get("account")
	}

	for _, value := range form["password"] {
		tokenRequest.addCredential(formUsername, value)
	}

	for _, field := range []string{"id_token", "access_token", "refresh_token", "token"} {
		for _, value := range form[field] {
			tokenRequest.addCredential("", value)
		}
	}

	return tokenRequest, nil
}

func (request *tokenExchangeRequest) addCredential(username, secret string) {
	credential := tokenExchangeCredential{
		Username: strings.TrimSpace(username),
		Secret:   strings.TrimSpace(secret),
	}
	if credential.Secret == "" || request.hasCredential(credential) {
		return
	}

	request.credentials = append(request.credentials, credential)
}

func (request *tokenExchangeRequest) hasCredential(credential tokenExchangeCredential) bool {
	if credential.isAPIKey() {
		return slices.Contains(request.credentials, credential)
	}

	return slices.ContainsFunc(request.credentials, func(existing tokenExchangeCredential) bool {
		return existing.Secret == credential.Secret
	})
}

func (credential tokenExchangeCredential) isAPIKey() bool {
	return credential.Username != "" && strings.HasPrefix(credential.Secret, constants.APIKeysPrefix)
}

func readTokenRequestFormBody(body io.Reader) ([]byte, error) {
	reader := io.LimitReader(body, int64(constants.MaxTokenRequestBodySize)+1)

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	if len(bodyBytes) > constants.MaxTokenRequestBodySize {
		return nil, errTokenRequestBodyTooLarge
	}

	return bodyBytes, nil
}

func newWrappedCredentialBearerToken(username, secret string) string {
	payload, _ := json.Marshal(wrappedCredentialBearer{ //nolint:errchkjson,gosec // Fixed scalar struct.
		Version:  wrappedCredentialVersion,
		Type:     wrappedCredentialTypeAPIKey,
		Username: username,
		Secret:   secret,
	})

	return wrappedCredentialBearerPrefix + base64.RawURLEncoding.EncodeToString(payload)
}

func newWrappedCredentialTokenResponse(token string) oidcBearerTokenResponse {
	return oidcBearerTokenResponse{
		Token:       token,
		AccessToken: token,
		IssuedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func wrappedCredentialFromBearerAuthHeader(header string) (wrappedCredentialBearer, bool, error) {
	token, ok := bearerTokenFromAuthHeader(header)
	if !ok || !strings.HasPrefix(token, wrappedCredentialBearerPrefix) {
		return wrappedCredentialBearer{}, false, nil
	}

	wrapped, err := parseWrappedCredentialBearerToken(token)

	return wrapped, true, err
}

func bearerTokenFromAuthHeader(header string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false
	}

	return strings.TrimSpace(parts[1]), true
}

func parseWrappedCredentialBearerToken(token string) (wrappedCredentialBearer, error) {
	encoded := strings.TrimPrefix(token, wrappedCredentialBearerPrefix)
	if encoded == "" || len(encoded) > constants.MaxTokenRequestBodySize {
		return wrappedCredentialBearer{}, errInvalidWrappedBearerCredential
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return wrappedCredentialBearer{}, fmt.Errorf("%w: %w", errInvalidWrappedBearerCredential, err)
	}

	var wrapped wrappedCredentialBearer
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return wrappedCredentialBearer{}, fmt.Errorf("%w: %w", errInvalidWrappedBearerCredential, err)
	}

	if wrapped.Version != wrappedCredentialVersion || wrapped.Type == "" ||
		wrapped.Username == "" || wrapped.Secret == "" {
		return wrappedCredentialBearer{}, errInvalidWrappedBearerCredential
	}

	return wrapped, nil
}

func localOIDCTokenOwnerForCredential(credential string, authConfig *config.AuthConfig) localOIDCTokenOwner {
	claims, ok := parseUnverifiedJWTClaims(credential)
	if !ok {
		return localOIDCTokenOwnerNone
	}

	if bearerOIDCOwnsClaims(claims, authConfig) {
		return localOIDCTokenOwnerBearer
	}

	if openIDOwnsClaims(claims, authConfig) {
		return localOIDCTokenOwnerOpenID
	}

	return localOIDCTokenOwnerNone
}

func parseUnverifiedJWTClaims(token string) (unverifiedJWTClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return unverifiedJWTClaims{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return unverifiedJWTClaims{}, false
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()

	rawClaims := map[string]any{}
	if err := decoder.Decode(&rawClaims); err != nil {
		return unverifiedJWTClaims{}, false
	}

	issuer, _ := rawClaims["iss"].(string)
	audiences := audiencesFromClaim(rawClaims["aud"])
	if issuer == "" || len(audiences) == 0 {
		return unverifiedJWTClaims{}, false
	}

	return unverifiedJWTClaims{issuer: issuer, audiences: audiences}, true
}

func audiencesFromClaim(rawAudience any) []string {
	switch audience := rawAudience.(type) {
	case string:
		if audience != "" {
			return []string{audience}
		}
	case []string:
		return slices.DeleteFunc(slices.Clone(audience), func(value string) bool { return value == "" })
	case []any:
		audiences := make([]string, 0, len(audience))
		for _, value := range audience {
			if str, ok := value.(string); ok && str != "" {
				audiences = append(audiences, str)
			}
		}

		return audiences
	}

	return nil
}

func bearerOIDCOwnsClaims(claims unverifiedJWTClaims, authConfig *config.AuthConfig) bool {
	if authConfig == nil || authConfig.Bearer == nil {
		return false
	}

	for _, provider := range authConfig.Bearer.OIDC {
		if provider.Issuer == claims.issuer && intersects(claims.audiences, provider.Audiences) {
			return true
		}
	}

	return false
}

func openIDOwnsClaims(claims unverifiedJWTClaims, authConfig *config.AuthConfig) bool {
	if authConfig == nil || authConfig.OpenID == nil {
		return false
	}

	for providerName, provider := range authConfig.OpenID.Providers {
		if !config.IsOpenIDSupported(providerName) {
			continue
		}

		if provider.Issuer == claims.issuer &&
			provider.ClientID != "" &&
			slices.Contains(claims.audiences, provider.ClientID) {
			return true
		}
	}

	return false
}

func intersects(left, right []string) bool {
	for _, lval := range left {
		if slices.Contains(right, lval) {
			return true
		}
	}

	return false
}

func newOIDCBearerTokenResponse(token string, claims map[string]any, now time.Time) oidcBearerTokenResponse {
	expiresIn := int64(0)
	if now.IsZero() {
		now = time.Now()
	}

	if expiresAt, ok := unixTimeClaim(claims["exp"]); ok {
		expiresIn = max(int64(time.Unix(expiresAt, 0).Sub(now).Seconds()), 0)
	}

	issuedAt := ""
	if issuedAtUnix, ok := unixTimeClaim(claims["iat"]); ok {
		issuedAt = time.Unix(issuedAtUnix, 0).UTC().Format(time.RFC3339)
	}

	return oidcBearerTokenResponse{
		Token:       token,
		AccessToken: token,
		ExpiresIn:   expiresIn,
		IssuedAt:    issuedAt,
	}
}

func unixTimeClaim(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed, true
		}

		if parsed, err := strconv.ParseFloat(typed.String(), 64); err == nil {
			return int64(parsed), true
		}
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case string:
		if parsed, err := strconv.ParseInt(typed, 10, 64); err == nil {
			return parsed, true
		}
	}

	return 0, false
}
