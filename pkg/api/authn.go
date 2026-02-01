package api

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	guuid "github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v62/github"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	godigest "github.com/opencontainers/go-digest"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

const (
	issuedAtOffset           = 5 * time.Second
	relyingPartyCookieMaxAge = 120
)

type AuthnMiddleware struct {
	htpasswd   *HTPasswd
	ldapClient *LDAPClient
	log        log.Logger
}

func AuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	authnMiddleware := &AuthnMiddleware{
		htpasswd: ctlr.HTPasswd,
		log:      ctlr.Log,
	}

	authConfig := ctlr.Config.CopyAuthConfig()
	if authConfig.IsBearerAuthEnabled() {
		return bearerAuthHandler(ctlr)
	}

	return authnMiddleware.tryAuthnHandlers(ctlr)
}

func (amw *AuthnMiddleware) sessionAuthn(ctlr *Controller, userAc *reqCtx.UserAccessControl,
	response http.ResponseWriter, request *http.Request,
) (bool, error) {
	identity, ok := GetAuthUserFromRequestSession(ctlr.CookieStore, request, ctlr.Log)
	if !ok {
		// let the client know that this session is invalid/expired
		cookie := &http.Cookie{
			Name:    "session",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),

			HttpOnly: true,
		}

		http.SetCookie(response, cookie)

		return false, nil
	}

	userAc.SetUsername(identity)
	userAc.SaveOnRequest(request)

	groups, err := ctlr.MetaDB.GetUserGroups(request.Context())
	if err != nil {
		ctlr.Log.Err(err).Str("identity", identity).Msg("failed to get user profile in DB")

		if errors.Is(err, zerr.ErrUserDataNotFound) {
			// we handle this case as an authentication failure, not an internal server error
			err = nil
		}

		return false, err
	}

	userAc.AddGroups(groups)
	userAc.SaveOnRequest(request)

	return true, nil
}

func (amw *AuthnMiddleware) mTLSAuthn(ctlr *Controller, userAc *reqCtx.UserAccessControl,
	request *http.Request,
) (bool, error) {
	// Check if mTLS is configured and client certificates are present
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return false, nil
	}

	// Check if client certificate has verified chain
	verifiedChains := request.TLS.VerifiedChains
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		ctlr.Log.Debug().Msg("mTLS authentication failed - user provided certificate not signed by CA")

		return false, nil
	}

	// Extract identity from certificate
	leafCert := request.TLS.PeerCertificates[0]

	// Get mTLS config from auth config
	authConfig := ctlr.Config.CopyAuthConfig()
	mtlsConfig := authConfig.GetMTLSConfig()

	identity, err := extractMTLSIdentity(leafCert, mtlsConfig)
	if err != nil || identity == "" {
		ctlr.Log.Debug().Err(err).Msg("mTLS authentication failed - could not extract identity")

		return false, nil
	}

	// Process request with mTLS identity
	var groups []string

	accessControl := ctlr.Config.CopyAccessControlConfig()
	if accessControl != nil {
		ac := NewAccessController(ctlr.Config)
		groups = ac.getUserGroups(identity)
	}

	userAc.SetUsername(identity)
	userAc.AddGroups(groups)
	userAc.SaveOnRequest(request)

	// Update user groups in MetaDB if available
	if ctlr.MetaDB != nil {
		if err := ctlr.MetaDB.SetUserGroups(request.Context(), groups); err != nil {
			ctlr.Log.Error().Err(err).Str("identity", identity).Msg("failed to update user profile")

			return false, err
		}
	}

	ctlr.Log.Debug().Str("identity", identity).Msg("mTLS authentication successful")

	return true, nil
}

func (amw *AuthnMiddleware) basicAuthn(ctlr *Controller, userAc *reqCtx.UserAccessControl,
	response http.ResponseWriter, request *http.Request,
) (bool, error) {
	cookieStore := ctlr.CookieStore

	// Get auth config once to avoid multiple calls
	authConfig := ctlr.Config.CopyAuthConfig()
	if authConfig == nil {
		return false, nil
	}

	identity, passphrase, err := getUsernamePasswordBasicAuth(request)
	if err != nil {
		ctlr.Log.Error().Err(err).Msg("failed to parse authorization header")

		return false, nil
	}

	// first, HTTPPassword authN (which is local)
	htOk, _ := amw.htpasswd.Authenticate(identity, passphrase)
	if htOk {
		// Process request
		var groups []string

		accessControl := ctlr.Config.CopyAccessControlConfig()
		if accessControl != nil {
			ac := NewAccessController(ctlr.Config)
			groups = ac.getUserGroups(identity)
		}

		userAc.SetUsername(identity)
		userAc.AddGroups(groups)
		userAc.SaveOnRequest(request)

		// saved logged session only if the request comes from web (has UI session header value)
		if hasSessionHeader(request) {
			secure := ctlr.Config.UseSecureSession()
			if err := saveUserLoggedSession(cookieStore, response, request, identity, secure, ctlr.Log); err != nil {
				return false, err
			}
		}

		// we have already populated the request context with userAc
		if err := ctlr.MetaDB.SetUserGroups(request.Context(), groups); err != nil {
			ctlr.Log.Error().Err(err).Str("identity", identity).Msg("failed to update user profile")

			return false, err
		}

		ctlr.Log.Info().Str("identity", identity).Msgf("user profile successfully set")

		return true, nil
	}

	// next, LDAP if configured (network-based which can lose connectivity)
	if authConfig.IsLdapAuthEnabled() {
		ok, _, ldapgroups, err := amw.ldapClient.Authenticate(identity, passphrase)
		if ok && err == nil {
			// Process request
			var groups []string

			accessControl := ctlr.Config.CopyAccessControlConfig()
			if accessControl != nil {
				ac := NewAccessController(ctlr.Config)
				groups = ac.getUserGroups(identity)
			}

			groups = append(groups, ldapgroups...)

			userAc.SetUsername(identity)
			userAc.AddGroups(groups)
			userAc.SaveOnRequest(request)

			// saved logged session only if the request comes from web (has UI session header value)
			if hasSessionHeader(request) {
				secure := ctlr.Config.UseSecureSession()
				if err := saveUserLoggedSession(cookieStore, response, request, identity, secure, ctlr.Log); err != nil {
					return false, err
				}
			}

			// we have already populated the request context with userAc
			if err := ctlr.MetaDB.SetUserGroups(request.Context(), groups); err != nil {
				ctlr.Log.Error().Err(err).Str("identity", identity).Msg("failed to update user profile")

				return false, err
			}

			return true, nil
		}
	}

	// last try API keys
	if authConfig.IsAPIKeyEnabled() {
		apiKey := passphrase

		if !strings.HasPrefix(apiKey, constants.APIKeysPrefix) {
			ctlr.Log.Error().Msg("invalid api token format")

			return false, nil
		}

		trimmedAPIKey := strings.TrimPrefix(apiKey, constants.APIKeysPrefix)

		hashedKey := hashUUID(trimmedAPIKey)

		storedIdentity, err := ctlr.MetaDB.GetUserAPIKeyInfo(hashedKey)
		if err != nil {
			if errors.Is(err, zerr.ErrUserAPIKeyNotFound) {
				ctlr.Log.Info().Err(err).Msgf("failed to find any user info for hashed key %s in DB", hashedKey)

				return false, nil
			}

			ctlr.Log.Error().Err(err).Msgf("failed to get user info for hashed key %s in DB", hashedKey)

			return false, err
		}

		if storedIdentity == identity {
			userAc.SetUsername(identity)
			userAc.SaveOnRequest(request)

			// check if api key expired
			isExpired, err := ctlr.MetaDB.IsAPIKeyExpired(request.Context(), hashedKey)
			if err != nil {
				ctlr.Log.Err(err).Str("identity", identity).Msg("failed to verify if api key expired")

				return false, err
			}

			if isExpired {
				return false, nil
			}

			err = ctlr.MetaDB.UpdateUserAPIKeyLastUsed(request.Context(), hashedKey)
			if err != nil {
				ctlr.Log.Err(err).Str("identity", identity).Msg("failed to update user profile in DB")

				return false, err
			}

			groups, err := ctlr.MetaDB.GetUserGroups(request.Context())
			if err != nil {
				ctlr.Log.Err(err).Str("identity", identity).Msg("failed to get user's groups in DB")

				return false, err
			}

			userAc.AddGroups(groups)
			userAc.SaveOnRequest(request)

			return true, nil
		}
	}

	return false, nil
}

func (amw *AuthnMiddleware) tryAuthnHandlers(ctlr *Controller) mux.MiddlewareFunc { //nolint: gocyclo
	// Get auth config once to avoid multiple calls
	authConfig := ctlr.Config.CopyAuthConfig()

	// ldap and htpasswd based authN
	if authConfig.IsLdapAuthEnabled() {
		ldapConfig := authConfig.LDAP

		ctlr.LDAPClient = &LDAPClient{
			Host:               ldapConfig.Address,
			Port:               ldapConfig.Port,
			UseSSL:             !ldapConfig.Insecure,
			SkipTLS:            !ldapConfig.StartTLS,
			Base:               ldapConfig.BaseDN,
			BindDN:             ldapConfig.BindDN(),
			BindPassword:       ldapConfig.BindPassword(),
			UserGroupAttribute: ldapConfig.UserGroupAttribute, // from config
			UserAttribute:      ldapConfig.UserAttribute,
			UserFilter:         ldapConfig.UserFilter,
			InsecureSkipVerify: ldapConfig.SkipVerify,
			ServerName:         ldapConfig.Address,
			Log:                ctlr.Log,
			SubtreeSearch:      ldapConfig.SubtreeSearch,
		}

		amw.ldapClient = ctlr.LDAPClient

		if authConfig.LDAP.CACert != "" {
			caCert, err := os.ReadFile(authConfig.LDAP.CACert)
			if err != nil {
				amw.log.Panic().Err(err).Str("caCert", authConfig.LDAP.CACert).
					Msg("failed to read caCert")
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				amw.log.Panic().Err(zerr.ErrBadCACert).Str("caCert", authConfig.LDAP.CACert).
					Msg("failed to read caCert")
			}

			amw.ldapClient.ClientCAs = caCertPool
		} else {
			// default to system cert pool
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				amw.log.Panic().Err(zerr.ErrBadCACert).Str("caCert", authConfig.LDAP.CACert).
					Msg("failed to get system cert pool")
			}

			amw.ldapClient.ClientCAs = caCertPool
		}
	}

	if authConfig.IsHtpasswdAuthEnabled() {
		err := amw.htpasswd.Reload(authConfig.HTPasswd.Path)
		if err != nil {
			amw.log.Panic().Err(err).Str("credsFile", authConfig.HTPasswd.Path).
				Msg("failed to open creds-file")
		}
	}

	// openid based authN
	if authConfig.IsOpenIDAuthEnabled() {
		ctlr.RelyingParties = make(map[string]rp.RelyingParty)

		for provider := range authConfig.OpenID.Providers {
			if config.IsOpenIDSupported(provider) {
				rp := NewRelyingPartyOIDC(context.TODO(), ctlr.Config, provider, authConfig.SessionHashKey,
					authConfig.SessionEncryptKey, ctlr.Log)
				ctlr.RelyingParties[provider] = rp
			} else if config.IsOauth2Supported(provider) {
				rp := NewRelyingPartyGithub(ctlr.Config, provider, authConfig.SessionHashKey,
					authConfig.SessionEncryptKey, ctlr.Log)
				ctlr.RelyingParties[provider] = rp
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}

			isMgmtRequested := request.RequestURI == constants.FullMgmt

			// Get auth config safely
			authConfig := ctlr.Config.CopyAuthConfig()
			delay := authConfig.GetFailDelay()
			realm := ctlr.Config.GetRealm()

			// Get access control config safely
			accessControlConfig := ctlr.Config.CopyAccessControlConfig()
			allowAnonymous := accessControlConfig != nil && accessControlConfig.AnonymousPolicyExists()

			// build user access control info
			userAc := reqCtx.NewUserAccessControl()
			// if it will not be populated by authn handlers, this represents an anonymous user
			userAc.SaveOnRequest(request)

			authenticated := false

			var err error

			// Switch authentication methods based on provided request context
			switch {
			// Reject requests with multiple Authorization headers as a security measure
			case hasMultipleAuthorizationHeaders(request):
				authenticated = false

			// The authorization header presence is an explicit attempt to use basic authentication
			case !isAuthorizationHeaderEmpty(request) && authConfig.IsBasicAuthnEnabled():
				authenticated, err = amw.basicAuthn(ctlr, userAc, response, request)

			// The session header is an explicit attempt to use session authentication
			case hasSessionHeader(request):
				authenticated, err = amw.sessionAuthn(ctlr, userAc, response, request)
				if err != nil {
					break
				}

				// If session authentication fails, but anonymous or management access is allowed,
				// treat the request as authenticated. This fallback is necessary because the session
				// header may be present for anonymous or management requests.
				authenticated = authenticated || allowAnonymous || isMgmtRequested

			// Try mTLS authentication if client certificates are present
			case ctlr.Config.IsMTLSAuthEnabled() && request.TLS != nil && len(request.TLS.PeerCertificates) > 0:
				authenticated, err = amw.mTLSAuthn(ctlr, userAc, request)

			// If no auth methods enabled at all - then just authenticate anything
			case !authConfig.IsBasicAuthnEnabled() && !ctlr.Config.IsMTLSAuthEnabled():
				authenticated = true

			// If no credentials provided - check for anonymous / mgmt requests
			case allowAnonymous || isMgmtRequested:
				authenticated = true
			}

			// If error occurred during authn process - return 500 error
			if err != nil {
				response.WriteHeader(http.StatusInternalServerError)

				return
			}

			if authenticated {
				next.ServeHTTP(response, request)
			} else {
				authFail(response, request, realm, delay)
			}
		})
	}
}

func bearerAuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	// Get auth config safely
	authConfig := ctlr.Config.CopyAuthConfig()

	var traditionalAuthorizerKeyFunc BearerAuthorizerKeyFunc

	// Traditional bearer auth with public key/certificate
	if authConfig.Bearer.Cert != "" {
		// although the configuration option is called 'cert', this function will also parse a public key directly
		// see https://github.com/project-zot/zot/issues/3173 for info
		publicKey, err := loadPublicKeyFromFile(authConfig.Bearer.Cert)
		if err != nil {
			ctlr.Log.Panic().Err(err).Msg("failed to load public key for bearer authentication")
		}

		traditionalAuthorizerKeyFunc = func(_ context.Context, token *jwt.Token) (any, error) {
			return publicKey, nil
		}
	}

	// Traditional bearer auth with AWS Secrets Manager
	if authConfig.Bearer.AWSSecretsManager != nil {
		asmAuthz, err := NewAWSSecretsManager(
			authConfig.Bearer.AWSSecretsManager, AWSSecretsManagerProviderImplementation{}, ctlr.Log)
		if err != nil {
			ctlr.Log.Panic().Err(err).Msg("failed to create AWS Secrets Manager key function for bearer authentication")
		}
		traditionalAuthorizerKeyFunc = asmAuthz.GetPublicKey
	}

	// Initialize authorizers based on configuration
	var traditionalAuthorizer *BearerAuthorizer
	if traditionalAuthorizerKeyFunc != nil {
		traditionalAuthorizer = NewBearerAuthorizer(
			authConfig.Bearer.Realm,
			authConfig.Bearer.Service,
			traditionalAuthorizerKeyFunc,
		)
	}

	// OIDC bearer auth for workload identity
	var oidcAuthorizer *OIDCBearerAuthorizer
	if len(authConfig.Bearer.OIDC) > 0 {
		var err error
		oidcAuthorizer, err = NewOIDCBearerAuthorizer(authConfig.Bearer.OIDC, ctlr.Log)
		if err != nil {
			ctlr.Log.Panic().Err(err).Msg("failed to initialize OIDC bearer authorizer")
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}

			// Reject requests with multiple Authorization headers as a security measure
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

			var requestedAccess *ResourceAction

			if request.RequestURI != "/v2/" {
				// if this is not the base route, the requested repository/action must be authorized
				vars := mux.Vars(request)
				name := vars["name"]

				action := "pull"
				if m := request.Method; m != http.MethodGet && m != http.MethodHead {
					action = "push"
				}

				requestedAccess = &ResourceAction{
					Type:   "repository",
					Name:   name,
					Action: action,
				}
			}

			// Try OIDC authentication first if configured
			var username string

			var groups []string

			if oidcAuthorizer != nil {
				var err error

				var authenticated bool

				username, groups, authenticated, err = oidcAuthorizer.AuthenticateRequest(request.Context(), header)
				if err == nil && authenticated {
					// OIDC authentication succeeded
					ctlr.Log.Debug().Str("username", username).Msg("the OIDC bearer authentication was successful")

					// Set user context for authorization
					userAc := reqCtx.NewUserAccessControl()
					userAc.SetUsername(username)
					userAc.AddGroups(groups)
					userAc.SaveOnRequest(request)

					// Update user groups in MetaDB if available
					if ctlr.MetaDB != nil {
						if err := ctlr.MetaDB.SetUserGroups(request.Context(), groups); err != nil {
							ctlr.Log.Error().Err(err).Str("username", username).Msg("failed to update user profile")
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

			// Fall back to traditional bearer token auth if OIDC didn't succeed
			if traditionalAuthorizer != nil {
				err := traditionalAuthorizer.Authorize(request.Context(), header, requestedAccess)
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

			// No authentication succeeded
			if isAuthorizationHeaderEmpty(request) {
				// No bearer token provided and no authentication method configured
				ctlr.Log.Debug().Msg("no bearer token provided")
			} else {
				// Bearer token provided but authentication failed
				ctlr.Log.Error().Msg("failed to authenticate with bearer token")
			}

			response.Header().Set("Content-Type", "application/json")
			zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))
		})
	}
}

func (rh *RouteHandler) AuthURLHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		callbackUI := query.Get(constants.CallbackUIQueryParam)

		provider := query.Get("provider")

		client, ok := rh.c.RelyingParties[provider]
		if !ok {
			rh.c.Log.Error().Msg("failed to authenticate due to unrecognized openid provider")

			w.WriteHeader(http.StatusBadRequest)

			return
		}

		/* save cookie containing state to later verify it and
		callback ui where we will redirect after openid/oauth2 logic is completed*/
		session, _ := rh.c.CookieStore.Get(r, "statecookie")

		session.Options.Secure = rh.c.Config.UseSecureSession()
		session.Options.HttpOnly = true
		session.Options.SameSite = http.SameSiteDefaultMode
		session.Options.Path = constants.CallbackBasePath

		state := uuid.New().String()

		session.Values["state"] = state
		session.Values["callback"] = callbackUI

		// let the session set its own id
		err := session.Save(r, w)
		if err != nil {
			rh.c.Log.Error().Err(err).Msg("failed to save http session")

			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		stateFunc := func() string {
			return state
		}

		rp.AuthURLHandler(stateFunc, client)(w, r)
	}
}

func NewRelyingPartyOIDC(ctx context.Context, config *config.Config, provider string,
	hashKey, encryptKey []byte, log log.Logger,
) rp.RelyingParty {
	issuer, clientID, clientSecret, redirectURI, scopes, options := getRelyingPartyArgs(config,
		provider, hashKey, encryptKey, log)

	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		log.Panic().Err(err).Str("issuer", issuer).Str("redirectURI", redirectURI).Strs("scopes", scopes).
			Msg("failed to initialize new relying party oidc")
	}

	return relyingParty
}

func NewRelyingPartyGithub(config *config.Config, provider string, hashKey, encryptKey []byte, log log.Logger,
) rp.RelyingParty {
	_, clientID, clientSecret, redirectURI, scopes,
		options := getRelyingPartyArgs(config, provider, hashKey, encryptKey, log)

	var endpoint oauth2.Endpoint

	// Use custom endpoints if provided, otherwise fallback to GitHub's endpoints
	if provider := config.HTTP.Auth.OpenID.Providers[provider]; provider.AuthURL != "" && provider.TokenURL != "" {
		endpoint = oauth2.Endpoint{
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
		}
	} else {
		endpoint = githubOAuth.Endpoint
	}

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopes,
		Endpoint:     endpoint,
	}

	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		log.Panic().Err(err).Str("redirectURI", redirectURI).Strs("scopes", scopes).
			Msg("failed to initialize new relying party oauth")
	}

	return relyingParty
}

func getRelyingPartyArgs(cfg *config.Config, provider string, hashKey, encryptKey []byte, log log.Logger) (
	string, string, string, string, []string, []rp.Option,
) {
	if _, ok := cfg.HTTP.Auth.OpenID.Providers[provider]; !ok {
		log.Panic().Err(zerr.ErrOpenIDProviderDoesNotExist).Str("provider", provider).Msg("")
	}

	providerConfig := cfg.HTTP.Auth.OpenID.Providers[provider]
	clientID := providerConfig.ClientID
	clientSecret := providerConfig.ClientSecret

	scopes := providerConfig.Scopes
	// openid scope must be the first one in list
	if !slices.Contains(scopes, oidc.ScopeOpenID) && config.IsOpenIDSupported(provider) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	port := cfg.HTTP.Port
	issuer := providerConfig.Issuer
	keyPath := providerConfig.KeyPath
	baseURL := net.JoinHostPort(cfg.HTTP.Address, port)

	callback := constants.CallbackBasePath + "/" + provider

	var redirectURI string

	if cfg.HTTP.ExternalURL != "" {
		externalURL := strings.TrimSuffix(cfg.HTTP.ExternalURL, "/")
		redirectURI = fmt.Sprintf("%s%s", externalURL, callback)
	} else {
		scheme := "http"
		if cfg.HTTP.TLS != nil {
			scheme = "https"
		}

		redirectURI = fmt.Sprintf("%s://%s%s", scheme, baseURL, callback)
	}

	options := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(issuedAtOffset)),
	}

	cookieHandler := httphelper.NewCookieHandler(hashKey, encryptKey, httphelper.WithMaxAge(relyingPartyCookieMaxAge))

	options = append(options, rp.WithCookieHandler(cookieHandler))

	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	return issuer, clientID, clientSecret, redirectURI, scopes, options
}

func authFail(w http.ResponseWriter, r *http.Request, realm string, delay int) {
	if !isAuthorizationHeaderEmpty(r) || hasSessionHeader(r) {
		time.Sleep(time.Duration(delay) * time.Second)
	}

	// don't send auth headers if request is coming from UI
	if r.Header.Get(constants.SessionClientHeaderName) != constants.SessionClientHeaderValue {
		if realm == "" {
			realm = "Authorization Required"
		}

		realm = "Basic realm=" + strconv.Quote(realm)

		w.Header().Set("WWW-Authenticate", realm)
	}

	w.Header().Set("Content-Type", "application/json")
	zcommon.WriteJSON(w, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))
}

func isAuthorizationHeaderEmpty(request *http.Request) bool {
	header := request.Header.Get("Authorization")

	if header == "" || (strings.ToLower(header) == "basic og==") {
		return true
	}

	return false
}

// hasMultipleAuthorizationHeaders checks if the request has multiple Authorization headers.
// This is a security concern as it could be used to bypass authentication or cause confusion.
func hasMultipleAuthorizationHeaders(request *http.Request) bool {
	authHeaders := request.Header.Values("Authorization")

	return len(authHeaders) > 1
}

func hasSessionHeader(request *http.Request) bool {
	clientHeader := request.Header.Get(constants.SessionClientHeaderName)

	return clientHeader == constants.SessionClientHeaderValue
}

func getUsernamePasswordBasicAuth(request *http.Request) (string, string, error) {
	basicAuth := request.Header.Get("Authorization")

	if basicAuth == "" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	splitStr := strings.SplitN(basicAuth, " ", 2) //nolint:mnd
	if len(splitStr) != 2 || strings.ToLower(splitStr[0]) != "basic" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	decodedStr, err := base64.StdEncoding.DecodeString(splitStr[1])
	if err != nil {
		return "", "", err
	}

	pair := strings.SplitN(string(decodedStr), ":", 2) //nolint:mnd
	if len(pair) != 2 {                                //nolint:mnd
		return "", "", zerr.ErrParsingAuthHeader
	}

	username := pair[0]
	passphrase := pair[1]

	return username, passphrase, nil
}

func GetGithubUserInfo(ctx context.Context, client *github.Client, log log.Logger) (string, []string, error) {
	var primaryEmail string

	userEmails, _, err := client.Users.ListEmails(ctx, nil)
	if err != nil {
		log.Error().Msg("failed to set user record for empty email value")

		return "", []string{}, err
	}

	if len(userEmails) != 0 {
		for _, email := range userEmails { // should have at least one primary email, if any
			if email.GetPrimary() { // check if it's primary email
				primaryEmail = email.GetEmail()

				break
			}
		}
	}

	orgs, _, err := client.Organizations.List(ctx, "", nil)
	if err != nil {
		log.Error().Msg("failed to set user record for empty email value")

		return "", []string{}, err
	}

	groups := []string{}
	for _, org := range orgs {
		groups = append(groups, *org.Login)
	}

	return primaryEmail, groups, nil
}

func saveUserLoggedSession(cookieStore sessions.Store, response http.ResponseWriter,
	request *http.Request, identity string, secure bool, log log.Logger,
) error {
	session, _ := cookieStore.Get(request, "session")

	session.Options.Secure = secure
	session.Options.HttpOnly = true
	session.Options.SameSite = http.SameSiteDefaultMode
	session.Values["authStatus"] = true
	session.Values["user"] = identity

	// let the session set its own id
	err := session.Save(request, response)
	if err != nil {
		log.Error().Err(err).Str("identity", identity).Msg("failed to save http session")

		return err
	}

	userInfoCookie := sessions.NewCookie("user", identity, &sessions.Options{
		Secure:   secure,
		HttpOnly: false,
		MaxAge:   cookiesMaxAge,
		SameSite: http.SameSiteDefaultMode,
		Path:     "/",
	})

	http.SetCookie(response, userInfoCookie)

	return nil
}

// OAuth2Callback is the callback logic where openid/oauth2 will redirect back to our app.
func OAuth2Callback(ctlr *Controller, w http.ResponseWriter, r *http.Request, state, email string,
	groups []string,
) (string, error) {
	stateCookie, _ := ctlr.CookieStore.Get(r, "statecookie")

	stateOrigin, ok := stateCookie.Values["state"].(string)
	if !ok {
		ctlr.Log.Error().Err(zerr.ErrInvalidStateCookie).Str("component", "openID").
			Msg("failed to get 'state' cookie from request")

		return "", zerr.ErrInvalidStateCookie
	}

	if stateOrigin != state {
		ctlr.Log.Error().Err(zerr.ErrInvalidStateCookie).Str("component", "openID").
			Msg("'state' cookie differs from the actual one")

		return "", zerr.ErrInvalidStateCookie
	}

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername(email)
	userAc.AddGroups(groups)
	userAc.SaveOnRequest(r)

	// if this line has been reached, then a new session should be created
	// if the `session` key is already on the cookie, it's not a valid one
	secure := ctlr.Config.UseSecureSession()
	if err := saveUserLoggedSession(ctlr.CookieStore, w, r, email, secure, ctlr.Log); err != nil {
		return "", err
	}

	if err := ctlr.MetaDB.SetUserGroups(r.Context(), groups); err != nil {
		ctlr.Log.Error().Err(err).Str("identity", email).Msg("failed to update the user profile")

		return "", err
	}

	ctlr.Log.Info().Msgf("user profile set successfully for email %s", email)

	// redirect to UI
	callbackUI, _ := stateCookie.Values["callback"].(string)

	return callbackUI, nil
}

func hashUUID(uuid string) string {
	digester := sha256.New()
	digester.Write([]byte(uuid))

	return godigest.NewDigestFromEncoded(godigest.SHA256, hex.EncodeToString(digester.Sum(nil))).Encoded()
}

/*
GetAuthUserFromRequestSession returns identity
and auth status if on the request's cookie session is a logged in user.
*/
func GetAuthUserFromRequestSession(cookieStore sessions.Store, request *http.Request, log log.Logger,
) (string, bool) {
	session, err := cookieStore.Get(request, "session")
	if err != nil {
		log.Error().Err(err).Msg("failed to decode existing session")
		// expired cookie, no need to return err
		return "", false
	}

	// at this point we should have a session set on cookie.
	// if created in the earlier Get() call then user is not logged in with sessions.
	if session.IsNew {
		return "", false
	}

	authenticated := session.Values["authStatus"]
	if authenticated != true {
		log.Error().Msg("failed to get `user` session value")

		return "", false
	}

	identity, ok := session.Values["user"].(string)
	if !ok {
		log.Error().Msg("failed to get `user` session value")

		return "", false
	}

	return identity, true
}

func GenerateAPIKey(uuidGenerator guuid.Generator, log log.Logger,
) (string, string, error) {
	apiKeyBase, err := uuidGenerator.NewV4()
	if err != nil {
		log.Error().Err(err).Msg("failed to generate uuid for api key base")

		return "", "", err
	}

	apiKey := strings.ReplaceAll(apiKeyBase.String(), "-", "")

	// will be used for identifying a specific api key
	apiKeyID, err := uuidGenerator.NewV4()
	if err != nil {
		log.Error().Err(err).Msg("failed to generate uuid for api key id")

		return "", "", err
	}

	return apiKey, apiKeyID.String(), err
}

// extractIdentityFromCertificate attempts to extract identity from a specific identity attribute.
func extractIdentityFromCertificate(cert *x509.Certificate, identityAttribute string, mtlsConfig *config.MTLSConfig,
) (string, error) {
	// Normalize to lowercase for case-insensitive matching
	normalizedIdentityAttribute := strings.ToLower(strings.TrimSpace(identityAttribute))

	switch normalizedIdentityAttribute {
	case "commonname", "cn":
		if cert.Subject.CommonName == "" {
			return "", zerr.ErrNoIdentityInCommonName
		}

		return cert.Subject.CommonName, nil

	case "subject", "dn":
		return cert.Subject.String(), nil

	case "url", "uri":
		if len(cert.URIs) == 0 {
			return "", zerr.ErrNoURISANFound
		}
		idx := 0
		if mtlsConfig != nil {
			idx = mtlsConfig.URISANIndex
		}
		if idx < 0 || idx >= len(cert.URIs) {
			return "", fmt.Errorf("%w: %d", zerr.ErrURISANIndexOutOfRange, idx)
		}
		uri := cert.URIs[idx].String()

		// Apply pattern if specified
		if mtlsConfig != nil && mtlsConfig.URISANPattern != "" {
			re, err := regexp.Compile(mtlsConfig.URISANPattern)
			if err != nil {
				return "", fmt.Errorf("%w: %w", zerr.ErrInvalidURISANPattern, err)
			}
			matches := re.FindStringSubmatch(uri)
			if len(matches) < 2 {
				return "", fmt.Errorf("%w", zerr.ErrURISANPatternDidNotMatch)
			}

			return matches[1], nil // Return first capture group
		}

		return uri, nil

	case "dnsname", "dns":
		if len(cert.DNSNames) == 0 {
			return "", zerr.ErrNoDNSANFound
		}
		idx := 0
		if mtlsConfig != nil {
			idx = mtlsConfig.DNSANIndex
		}
		if idx < 0 || idx >= len(cert.DNSNames) {
			return "", fmt.Errorf("%w: %d", zerr.ErrDNSANIndexOutOfRange, idx)
		}

		return cert.DNSNames[idx], nil

	case "email", "rfc822name":
		if len(cert.EmailAddresses) == 0 {
			return "", zerr.ErrNoEmailSANFound
		}
		idx := 0
		if mtlsConfig != nil {
			idx = mtlsConfig.EmailSANIndex
		}
		if idx < 0 || idx >= len(cert.EmailAddresses) {
			return "", fmt.Errorf("%w: %d", zerr.ErrEmailSANIndexOutOfRange, idx)
		}

		return cert.EmailAddresses[idx], nil

	default:
		return "", fmt.Errorf("%w: %s", zerr.ErrUnsupportedIdentityAttribute, identityAttribute)
	}
}

// extractMTLSIdentity extracts identity from certificate using configured soidentity attributes with fallback chain.
func extractMTLSIdentity(cert *x509.Certificate, mtlsConfig *config.MTLSConfig) (string, error) {
	identityAttributes := []string{"CommonName"} // Default
	if mtlsConfig != nil && len(mtlsConfig.IdentityAttibutes) > 0 {
		identityAttributes = mtlsConfig.IdentityAttibutes
	}

	var cummulatedErr error

	for _, identityAttribute := range identityAttributes {
		identity, err := extractIdentityFromCertificate(cert, identityAttribute, mtlsConfig)
		if err == nil {
			return identity, nil
		}

		cummulatedErr = errors.Join(cummulatedErr, err)
	}

	return "", fmt.Errorf("no identity found in any configured identity attributes: %w", cummulatedErr)
}

func loadPublicKeyFromFile(path string) (crypto.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w, path %s", zerr.ErrCouldNotLoadPublicKey, err, path)
	}

	return loadPublicKeyFromBytes(raw)
}

func loadPublicKeyFromBytes(raw []byte) (crypto.PublicKey, error) {
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &keySet); err == nil {
		if len(keySet.Keys) != 1 {
			return nil, fmt.Errorf("%w: expected 1 key in JWKS, found %d", zerr.ErrCouldNotLoadPublicKey, len(keySet.Keys))
		}

		return keySet.Keys[0].Key, nil
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: no valid PEM data found", zerr.ErrCouldNotLoadPublicKey)
	}

	pemBytes := block.Bytes

	if cert, err := x509.ParseCertificate(pemBytes); err == nil {
		return cert.PublicKey, nil
	}

	if key, err := x509.ParsePKIXPublicKey(pemBytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(pemBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("%w: no valid x509 certificate or public key found", zerr.ErrCouldNotLoadPublicKey)
}
