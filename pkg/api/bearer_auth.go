package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

type BearerAuth struct {
	authConfig   *config.AuthConfig
	bearerConfig *config.BearerConfig
	log          log.Logger

	oidc        *OIDCBearerAuthorizer
	traditional *BearerAuthorizer
}

type oidcBearerTokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"` //nolint:tagliatelle
	ExpiresIn   int64  `json:"expires_in"`   //nolint:tagliatelle
	IssuedAt    string `json:"issued_at"`    //nolint:tagliatelle
}

func NewBearerAuth(authConfig *config.AuthConfig, logger log.Logger) *BearerAuth {
	bearerAuth := &BearerAuth{
		authConfig: authConfig,
		log:        logger,
	}
	if !authConfig.HasBearerConfig() {
		return bearerAuth
	}

	bearerAuth.bearerConfig = authConfig.Bearer

	var traditionalAuthorizerKeyFunc BearerAuthorizerKeyFunc

	// Traditional bearer auth with public key/certificate.
	if authConfig.Bearer.Cert != "" {
		// although the configuration option is called 'cert', this function will also parse a public key directly
		// see https://github.com/project-zot/zot/issues/3173 for info
		publicKey, err := loadPublicKeyFromFile(authConfig.Bearer.Cert)
		if err != nil {
			logger.Panic().Err(err).Msg("failed to load public key for bearer authentication")
		}

		traditionalAuthorizerKeyFunc = func(_ context.Context, _ *jwt.Token) (any, error) {
			return publicKey, nil
		}
	}

	// Traditional bearer auth with AWS Secrets Manager.
	if authConfig.Bearer.AWSSecretsManager != nil {
		asmAuthz, err := NewAWSSecretsManager(
			authConfig.Bearer.AWSSecretsManager, AWSSecretsManagerProviderImplementation{}, logger)
		if err != nil {
			logger.Panic().Err(err).Msg("failed to create AWS Secrets Manager key function for bearer authentication")
		}
		traditionalAuthorizerKeyFunc = asmAuthz.GetPublicKey
	}

	if traditionalAuthorizerKeyFunc != nil {
		bearerAuth.traditional = NewBearerAuthorizer(
			authConfig.Bearer.Realm,
			authConfig.Bearer.Service,
			traditionalAuthorizerKeyFunc,
		)
	}

	if authConfig.IsOIDCBearerAuthEnabled() {
		oidcAuthorizer, err := NewOIDCBearerAuthorizer(authConfig.Bearer.OIDC, logger)
		if err != nil {
			logger.Panic().Err(err).Msg("failed to initialize OIDC bearer authorizer")
		}

		bearerAuth.oidc = oidcAuthorizer
	}

	return bearerAuth
}

func (b *BearerAuth) Middleware(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}

			// Reject requests with multiple Authorization headers as a security measure.
			if hasMultipleAuthorizationHeaders(request) {
				ctlr.Log.Error().Msg("failed to parse Authorization header: multiple Authorization headers detected")
				response.Header().Set("Content-Type", "application/json")
				zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNSUPPORTED))

				return
			}

			acCtrlr := NewAccessController(ctlr.Config)

			// we want to bypass auth for mgmt route
			isMgmtRequested := request.RequestURI == constants.FullMgmt

			header := request.Header.Get("Authorization")

			if isAuthorizationHeaderEmpty(request) && isMgmtRequested {
				next.ServeHTTP(response, request)

				return
			}

			// Allow anonymous access to the metrics endpoint only if configured.
			accessControlConfig := ctlr.Config.CopyAccessControlConfig()
			extensionsConfig := ctlr.Config.CopyExtensionsConfig()

			if isAnonymousMetricsRequest(request, accessControlConfig, extensionsConfig) {
				next.ServeHTTP(response, request)

				return
			}

			var requestedAccess *ResourceAction

			if request.RequestURI != "/v2/" {
				// if this is not the base route, the requested repository/action must be authorized
				vars := mux.Vars(request)
				name := vars["name"]

				var action string
				switch m := request.Method; m {
				case http.MethodHead, http.MethodGet:
					action = "pull"
				case http.MethodPost, http.MethodPatch, http.MethodPut:
					action = "push"
				case http.MethodDelete:
					action = "delete"
				default:
					action = "pull" // default to pull for other methods, e.g., OPTIONS
				}

				requestedAccess = &ResourceAction{
					Type:   "repository",
					Name:   name,
					Action: action,
				}
			}

			// Try OIDC authentication first if configured.
			if b.oidc != nil {
				res, err := b.oidc.Authenticate(request.Context(), header)
				if err == nil && res != nil && res.Username != "" {
					identity := res.Username
					groups := res.Groups

					ctlr.Log.Debug().Str("identity", identity).Msg("the OIDC bearer authentication was successful")

					userAc := reqCtx.NewUserAccessControl()
					userAc.SetUsername(identity)
					userAc.AddGroups(groups)
					userAc.SetClaims(res.Claims)
					userAc.SaveOnRequest(request)

					if ctlr.MetaDB != nil {
						if err := ctlr.MetaDB.SetUserGroups(request.Context(), groups); err != nil {
							ctlr.Log.Error().Err(err).Str("identity", identity).Msg("failed to update user profile")
							response.WriteHeader(http.StatusInternalServerError)

							return
						}
					}

					// Use BEARER_OIDC to enable authorization via accessControl config.
					// Unlike traditional bearer tokens (which contain 'access' claims with permissions),
					// OIDC tokens contain identity only, so authorization must come from the config.
					amCtx := acCtrlr.getAuthnMiddlewareContext(BEARER_OIDC, request)
					next.ServeHTTP(response, request.WithContext(amCtx)) //nolint:contextcheck

					return
				}
			}

			// Fall back to traditional bearer token auth if OIDC didn't succeed.
			if b.traditional != nil {
				err := b.traditional.Authorize(request.Context(), header, requestedAccess)
				if err != nil {
					var challenge *AuthChallengeError
					if errors.As(err, &challenge) {
						ctlr.Log.Debug().Err(challenge).Msg("bearer token authorization failed")
						response.Header().Set("Content-Type", "application/json")
						response.Header().Set("WWW-Authenticate", challenge.Header())
						zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))

						return
					}

					ctlr.Log.Error().Err(err).Msg("failed to parse Authorization header")
					response.Header().Set("Content-Type", "application/json")
					zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNSUPPORTED))

					return
				}

				amCtx := acCtrlr.getAuthnMiddlewareContext(BEARER, request)
				next.ServeHTTP(response, request.WithContext(amCtx)) //nolint:contextcheck

				return
			}

			if isAuthorizationHeaderEmpty(request) {
				ctlr.Log.Debug().Msg("no bearer token provided")
			} else {
				ctlr.Log.Error().Msg("failed to authenticate with bearer token")
			}

			setBearerAuthChallenge(response, b.authConfig, requestedAccess)
			response.Header().Set("Content-Type", "application/json")
			zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))
		})
	}
}

func (b *BearerAuth) TokenExchangeHandler() http.HandlerFunc {
	if b == nil || !b.authConfig.IsOIDCBearerAuthEnabled() || b.oidc == nil {
		return nil
	}

	return func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Pragma", "no-cache")

		if hasMultipleAuthorizationHeaders(request) {
			b.log.Error().Msg("failed to parse Authorization header: multiple Authorization headers detected")
			response.Header().Set("Content-Type", "application/json")
			zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNSUPPORTED))

			return
		}

		tokenRequest, err := normalizeTokenExchangeRequest(request)
		if err != nil {
			b.log.Debug().Err(err).Msg("failed to parse token exchange request")
			if errors.Is(err, errTokenRequestBodyTooLarge) {
				writeTokenExchangeError(response, http.StatusRequestEntityTooLarge, "token request body too large")

				return
			}

			if errors.Is(err, zerr.ErrInvalidTokenProxyForm) {
				writeTokenExchangeError(response, http.StatusBadRequest, "invalid token request form body")

				return
			}

			writeTokenExchangeError(response, http.StatusBadRequest, "failed to parse token request")

			return
		}

		locallyOwned := false

		for _, credential := range tokenRequest.credentials {
			switch localOIDCTokenOwnerForCredential(credential, b.authConfig) {
			case localOIDCTokenOwnerBearer:
				locallyOwned = true

				res, err := b.oidc.Authenticate(request.Context(), "Bearer "+credential)
				if err == nil && res != nil && res.Username != "" {
					zcommon.WriteJSON(response, http.StatusOK,
						newOIDCBearerTokenResponse(credential, res.Claims, time.Now()))

					return
				}

				b.log.Debug().Err(err).Msg("oidc bearer token exchange failed")
			case localOIDCTokenOwnerOpenID:
				locallyOwned = true
				b.log.Debug().Msg("token exchange request matched browser OpenID provider; refusing proxy fallback")
			case localOIDCTokenOwnerNone:
			}
		}

		if locallyOwned {
			oidcTokenExchangeUnauthorized(response, b.authConfig)

			return
		}

		if b.authConfig.IsUpstreamTokenEndpointConfigured() {
			if err := b.proxyOIDCBearerTokenExchange(response, request); err != nil {
				b.log.Error().Err(err).Msg("failed to proxy oidc bearer token exchange")
				writeTokenExchangeError(response, http.StatusBadGateway, "failed to proxy token request")
			}

			return
		}

		oidcTokenExchangeUnauthorized(response, b.authConfig)
	}
}

func (b *BearerAuth) proxyOIDCBearerTokenExchange(response http.ResponseWriter, request *http.Request) error {
	bearerConfig := b.bearerConfig
	upstreamTokenEndpoint := bearerConfig.UpstreamTokenEndpoint
	proxyURL, err := url.Parse(upstreamTokenEndpoint.Realm)
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrInvalidUpstreamTokenEndpoint, err)
	}

	if proxyURL.Scheme == "" || proxyURL.Host == "" {
		return fmt.Errorf("%w: must be an absolute URL", zerr.ErrInvalidUpstreamTokenEndpoint)
	}

	if !strings.EqualFold(proxyURL.Scheme, constants.SchemeHTTPS) {
		if !strings.EqualFold(proxyURL.Scheme, constants.SchemeHTTP) || !upstreamTokenEndpoint.AllowInsecureHTTP {
			return fmt.Errorf("%w: upstreamTokenEndpoint.realm must use https unless "+
				"upstreamTokenEndpoint.allowInsecureHttp is true", zerr.ErrInvalidUpstreamTokenEndpoint)
		}
	}

	query := proxyURL.Query()
	for key, values := range request.URL.Query() {
		query.Del(key)

		for _, value := range values {
			query.Add(key, value)
		}
	}
	query.Set("service", upstreamTokenEndpoint.Service)
	proxyURL.RawQuery = query.Encode()

	body, contentLength, err := tokenProxyRequestBody(request, upstreamTokenEndpoint.Service)
	if err != nil {
		return err
	}

	proxyReq, err := http.NewRequestWithContext(request.Context(), request.Method, proxyURL.String(), body)
	if err != nil {
		return err
	}
	if contentLength >= 0 {
		proxyReq.ContentLength = contentLength
	}

	copyTokenProxyHeaders(proxyReq.Header, request.Header)

	proxyClient, err := zcommon.CreateHTTPClient(&zcommon.HTTPClientOptions{
		TLSEnabled: strings.EqualFold(proxyURL.Scheme, "https"),
		VerifyTLS:  true,
		Host:       proxyURL.Hostname(),
	})
	if err != nil {
		return err
	}

	proxyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	//nolint:gosec // upstreamTokenEndpoint.realm is an administrator-configured token service URL.
	proxyResp, err := proxyClient.Do(proxyReq)
	if err != nil {
		return err
	}
	defer proxyResp.Body.Close()

	copyTokenProxyHeaders(response.Header(), proxyResp.Header)
	response.WriteHeader(proxyResp.StatusCode)
	_, err = io.Copy(response, proxyResp.Body)

	return err
}

func tokenProxyRequestBody(request *http.Request, upstreamService string) (io.Reader, int64, error) {
	if request.Body == nil || request.Body == http.NoBody {
		return nil, 0, nil
	}

	if !isFormURLEncoded(request.Header.Get("Content-Type")) {
		return request.Body, request.ContentLength, nil
	}

	bodyBytes, err := readTokenRequestFormBody(request.Body)
	if err != nil {
		return nil, 0, err
	}

	form, parseErr := url.ParseQuery(string(bodyBytes))
	if parseErr != nil {
		return nil, 0, fmt.Errorf("%w: %w", zerr.ErrInvalidTokenProxyForm, parseErr)
	}

	form.Set("service", upstreamService)
	encodedBody := []byte(form.Encode())

	return bytes.NewReader(encodedBody), int64(len(encodedBody)), nil
}

func isFormURLEncoded(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}

func copyTokenProxyHeaders(dst, src http.Header) {
	connectionHeaders := map[string]struct{}{}

	for _, value := range src.Values("Connection") {
		for part := range strings.SplitSeq(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				connectionHeaders[http.CanonicalHeaderKey(part)] = struct{}{}
			}
		}
	}

	for key, values := range src {
		canonicalKey := http.CanonicalHeaderKey(key)
		if tokenProxyHeaderShouldBeSkipped(canonicalKey) {
			continue
		}
		if _, ok := connectionHeaders[canonicalKey]; ok {
			continue
		}

		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func tokenProxyHeaderShouldBeSkipped(header string) bool {
	switch header {
	case "Connection", "Content-Length", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func oidcTokenExchangeUnauthorized(response http.ResponseWriter, authConfig *config.AuthConfig) {
	realm := "zot"
	if authConfig != nil && authConfig.Bearer != nil && authConfig.Bearer.Realm != "" {
		realm = authConfig.Bearer.Realm
	}

	response.Header().Set("WWW-Authenticate", "Basic realm="+strconv.Quote(realm))
	zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))
}

func tokenExchangeOptions(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusNoContent)
}

func writeTokenExchangeError(response http.ResponseWriter, status int, reason string) {
	response.Header().Set("Content-Type", "application/json")
	zcommon.WriteJSON(response, status, apiErr.NewError(apiErr.UNSUPPORTED).AddDetail(map[string]string{"reason": reason}))
}
