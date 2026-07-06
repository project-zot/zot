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

var errTokenRequestBodyTooLarge = errors.New("token request body too large")

type tokenExchangeRequest struct {
	credentials []string
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

func normalizeTokenExchangeRequest(request *http.Request) (*tokenExchangeRequest, error) {
	tokenRequest := &tokenExchangeRequest{}

	_, password, ok := request.BasicAuth()
	if ok && password != "" {
		tokenRequest.addCredential(password)
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

	for _, field := range []string{"password", "id_token", "access_token", "refresh_token", "token"} {
		for _, value := range form[field] {
			tokenRequest.addCredential(value)
		}
	}

	return tokenRequest, nil
}

func (request *tokenExchangeRequest) addCredential(credential string) {
	credential = strings.TrimSpace(credential)
	if credential == "" || slices.Contains(request.credentials, credential) {
		return
	}

	request.credentials = append(request.credentials, credential)
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
