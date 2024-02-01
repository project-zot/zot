package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	guuid "github.com/gofrs/uuid"
	"github.com/google/go-github/v52/github"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	godigest "github.com/opencontainers/go-digest"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	apiErr "zotregistry.dev/zot/pkg/api/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
)

const (
	bearerAuthDefaultAccessEntryType = "repository"
	issuedAtOffset                   = 5 * time.Second
	relyingPartyCookieMaxAge         = 120
)

type AuthnMiddleware struct {
	credMap    map[string]string
	ldapClient *LDAPClient
	log        log.Logger
}

func AuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	authnMiddleware := &AuthnMiddleware{log: ctlr.Log}

	if ctlr.Config.IsBearerAuthEnabled() {
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

		return false, err
	}

	userAc.AddGroups(groups)
	userAc.SaveOnRequest(request)

	return true, nil
}

func (amw *AuthnMiddleware) basicAuthn(ctlr *Controller, userAc *reqCtx.UserAccessControl,
	response http.ResponseWriter, request *http.Request,
) (bool, error) {
	cookieStore := ctlr.CookieStore

	identity, passphrase, err := getUsernamePasswordBasicAuth(request)
	if err != nil {
		ctlr.Log.Error().Err(err).Msg("failed to parse authorization header")

		return false, nil
	}

	passphraseHash, ok := amw.credMap[identity]
	if ok {
		// first, HTTPPassword authN (which is local)
		if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err == nil {
			// Process request
			var groups []string

			if ctlr.Config.HTTP.AccessControl != nil {
				ac := NewAccessController(ctlr.Config)
				groups = ac.getUserGroups(identity)
			}

			userAc.SetUsername(identity)
			userAc.AddGroups(groups)
			userAc.SaveOnRequest(request)

			// saved logged session only if the request comes from web (has UI session header value)
			if hasSessionHeader(request) {
				if err := saveUserLoggedSession(cookieStore, response, request, identity, ctlr.Log); err != nil {
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
	}

	// next, LDAP if configured (network-based which can lose connectivity)
	if ctlr.Config.HTTP.Auth != nil && ctlr.Config.HTTP.Auth.LDAP != nil {
		ok, _, ldapgroups, err := amw.ldapClient.Authenticate(identity, passphrase)
		if ok && err == nil {
			// Process request
			var groups []string

			if ctlr.Config.HTTP.AccessControl != nil {
				ac := NewAccessController(ctlr.Config)
				groups = ac.getUserGroups(identity)
			}

			groups = append(groups, ldapgroups...)

			userAc.SetUsername(identity)
			userAc.AddGroups(groups)
			userAc.SaveOnRequest(request)

			// saved logged session only if the request comes from web (has UI session header value)
			if hasSessionHeader(request) {
				if err := saveUserLoggedSession(cookieStore, response, request, identity, ctlr.Log); err != nil {
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
	if ctlr.Config.IsAPIKeyEnabled() {
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
	// no password based authN, if neither LDAP nor HTTP BASIC is enabled
	if !ctlr.Config.IsBasicAuthnEnabled() {
		return noPasswdAuth(ctlr)
	}

	amw.credMap = make(map[string]string)

	delay := ctlr.Config.HTTP.Auth.FailDelay

	// ldap and htpasswd based authN
	if ctlr.Config.IsLdapAuthEnabled() {
		ldapConfig := ctlr.Config.HTTP.Auth.LDAP

		ctlr.LDAPClient = &LDAPClient{
			Host:               ldapConfig.Address,
			Port:               ldapConfig.Port,
			UseSSL:             !ldapConfig.Insecure,
			SkipTLS:            !ldapConfig.StartTLS,
			Base:               ldapConfig.BaseDN,
			BindDN:             ldapConfig.BindDN(),
			BindPassword:       ldapConfig.BindPassword(),
			UserGroupAttribute: ldapConfig.UserGroupAttribute, // from config
			UserFilter:         fmt.Sprintf("(%s=%%s)", ldapConfig.UserAttribute),
			InsecureSkipVerify: ldapConfig.SkipVerify,
			ServerName:         ldapConfig.Address,
			Log:                ctlr.Log,
			SubtreeSearch:      ldapConfig.SubtreeSearch,
		}

		amw.ldapClient = ctlr.LDAPClient

		if ctlr.Config.HTTP.Auth.LDAP.CACert != "" {
			caCert, err := os.ReadFile(ctlr.Config.HTTP.Auth.LDAP.CACert)
			if err != nil {
				amw.log.Panic().Err(err).Str("caCert", ctlr.Config.HTTP.Auth.LDAP.CACert).
					Msg("failed to read caCert")
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				amw.log.Panic().Err(zerr.ErrBadCACert).Str("caCert", ctlr.Config.HTTP.Auth.LDAP.CACert).
					Msg("failed to read caCert")
			}

			amw.ldapClient.ClientCAs = caCertPool
		} else {
			// default to system cert pool
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				amw.log.Panic().Err(zerr.ErrBadCACert).Str("caCert", ctlr.Config.HTTP.Auth.LDAP.CACert).
					Msg("failed to get system cert pool")
			}

			amw.ldapClient.ClientCAs = caCertPool
		}
	}

	if ctlr.Config.IsHtpasswdAuthEnabled() {
		credsFile, err := os.Open(ctlr.Config.HTTP.Auth.HTPasswd.Path)
		if err != nil {
			amw.log.Panic().Err(err).Str("credsFile", ctlr.Config.HTTP.Auth.HTPasswd.Path).
				Msg("failed to open creds-file")
		}
		defer credsFile.Close()

		scanner := bufio.NewScanner(credsFile)

		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, ":") {
				tokens := strings.Split(scanner.Text(), ":")
				amw.credMap[tokens[0]] = tokens[1]
			}
		}
	}

	// openid based authN
	if ctlr.Config.IsOpenIDAuthEnabled() {
		ctlr.RelyingParties = make(map[string]rp.RelyingParty)

		for provider := range ctlr.Config.HTTP.Auth.OpenID.Providers {
			if config.IsOpenIDSupported(provider) {
				rp := NewRelyingPartyOIDC(ctlr.Config, provider, ctlr.Log)
				ctlr.RelyingParties[provider] = rp
			} else if config.IsOauth2Supported(provider) {
				rp := NewRelyingPartyGithub(ctlr.Config, provider, ctlr.Log)
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
			allowAnonymous := ctlr.Config.HTTP.AccessControl.AnonymousPolicyExists()

			// build user access control info
			userAc := reqCtx.NewUserAccessControl()
			// if it will not be populated by authn handlers, this represents an anonymous user
			userAc.SaveOnRequest(request)

			// try basic auth if authorization header is given
			if !isAuthorizationHeaderEmpty(request) { //nolint: gocritic
				//nolint: contextcheck
				authenticated, err := amw.basicAuthn(ctlr, userAc, response, request)
				if err != nil {
					response.WriteHeader(http.StatusInternalServerError)

					return
				}

				if authenticated {
					next.ServeHTTP(response, request)

					return
				}
			} else if hasSessionHeader(request) {
				// try session auth
				//nolint: contextcheck
				authenticated, err := amw.sessionAuthn(ctlr, userAc, response, request)
				if err != nil {
					if errors.Is(err, zerr.ErrUserDataNotFound) {
						ctlr.Log.Err(err).Msg("failed to find user profile in DB")

						authFail(response, request, ctlr.Config.HTTP.Realm, delay)
					}

					response.WriteHeader(http.StatusInternalServerError)

					return
				}

				if authenticated {
					next.ServeHTTP(response, request)

					return
				}

				// the session header can be present also for anonymous calls
				if allowAnonymous || isMgmtRequested {
					next.ServeHTTP(response, request)

					return
				}
			} else if allowAnonymous || isMgmtRequested {
				// try anonymous auth only if basic auth/session was not given
				next.ServeHTTP(response, request)

				return
			}

			authFail(response, request, ctlr.Config.HTTP.Realm, delay)
		})
	}
}

func bearerAuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	authorizer, err := auth.NewAuthorizer(&auth.AuthorizerOptions{
		Realm:                 ctlr.Config.HTTP.Auth.Bearer.Realm,
		Service:               ctlr.Config.HTTP.Auth.Bearer.Service,
		PublicKeyPath:         ctlr.Config.HTTP.Auth.Bearer.Cert,
		AccessEntryType:       bearerAuthDefaultAccessEntryType,
		EmptyDefaultNamespace: true,
	})
	if err != nil {
		ctlr.Log.Panic().Err(err).Msg("failed to create bearer authorizer")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}
			acCtrlr := NewAccessController(ctlr.Config)
			vars := mux.Vars(request)
			name := vars["name"]

			// we want to bypass auth for mgmt route
			isMgmtRequested := request.RequestURI == constants.FullMgmt

			header := request.Header.Get("Authorization")

			if isAuthorizationHeaderEmpty(request) && isMgmtRequested {
				next.ServeHTTP(response, request)

				return
			}

			action := auth.PullAction
			if m := request.Method; m != http.MethodGet && m != http.MethodHead {
				action = auth.PushAction
			}

			var permissions *auth.Permission

			// Empty scope should be allowed according to the distribution auth spec
			// This is only necessary for the bearer auth type
			if request.RequestURI == "/v2/" && authorizer.Type == auth.BearerAuthAuthorizerType {
				if header == "" {
					// first request that clients make (without any header)
					WWWAuthenticateHeader := fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"\"",
						authorizer.Realm, authorizer.Service)

					permissions = &auth.Permission{
						// challenge for the client to use to authenticate to /v2/
						WWWAuthenticateHeader: WWWAuthenticateHeader,
						Allowed:               false,
					}
				} else {
					// subsequent requests with token on /v2/
					bearerTokenMatch := regexp.MustCompile("(?i)bearer (.*)")

					signedString := bearerTokenMatch.ReplaceAllString(header, "$1")

					// If the token is valid, our job is done
					// Since this is the /v2 base path and we didn't pass a scope to the auth header in the previous step
					// there is no access check to enforce
					_, err := authorizer.TokenDecoder.DecodeToken(signedString)
					if err != nil {
						ctlr.Log.Error().Err(err).Msg("failed to parse Authorization header")
						response.Header().Set("Content-Type", "application/json")
						zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNSUPPORTED))

						return
					}

					permissions = &auth.Permission{
						Allowed: true,
					}
				}
			} else {
				var err error

				// subsequent requests with token on /v2/<resource>/
				permissions, err = authorizer.Authorize(header, action, name)
				if err != nil {
					ctlr.Log.Error().Err(err).Msg("failed to parse Authorization header")
					response.Header().Set("Content-Type", "application/json")
					zcommon.WriteJSON(response, http.StatusInternalServerError, apiErr.NewError(apiErr.UNSUPPORTED))

					return
				}
			}

			if !permissions.Allowed {
				response.Header().Set("Content-Type", "application/json")
				response.Header().Set("WWW-Authenticate", permissions.WWWAuthenticateHeader)

				zcommon.WriteJSON(response, http.StatusUnauthorized, apiErr.NewError(apiErr.UNAUTHORIZED))

				return
			}

			amCtx := acCtrlr.getAuthnMiddlewareContext(BEARER, request)
			next.ServeHTTP(response, request.WithContext(amCtx)) //nolint:contextcheck
		})
	}
}

func noPasswdAuth(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}

			userAc := reqCtx.NewUserAccessControl()

			// if no basic auth enabled then try to get identity from mTLS auth
			if request.TLS != nil {
				verifiedChains := request.TLS.VerifiedChains
				if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
					for _, cert := range request.TLS.PeerCertificates {
						identity := cert.Subject.CommonName
						if identity != "" {
							// assign identity to authz context, needed for extensions
							userAc.SetUsername(identity)
						}
					}
				}
			}

			if ctlr.Config.IsMTLSAuthEnabled() && userAc.IsAnonymous() {
				authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			userAc.SaveOnRequest(request)

			// Process request
			next.ServeHTTP(response, request)
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

		session.Options.Secure = true
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

func NewRelyingPartyOIDC(config *config.Config, provider string, log log.Logger) rp.RelyingParty {
	issuer, clientID, clientSecret, redirectURI, scopes, options := getRelyingPartyArgs(config, provider, log)

	relyingParty, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		log.Panic().Err(err).Str("issuer", issuer).Str("redirectURI", redirectURI).Strs("scopes", scopes).
			Msg("failed to get new relying party oicd")
	}

	return relyingParty
}

func NewRelyingPartyGithub(config *config.Config, provider string, log log.Logger) rp.RelyingParty {
	_, clientID, clientSecret, redirectURI, scopes, options := getRelyingPartyArgs(config, provider, log)

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopes,
		Endpoint:     githubOAuth.Endpoint,
	}

	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		log.Panic().Err(err).Str("redirectURI", redirectURI).Strs("scopes", scopes).
			Msg("failed to get new relying party oauth")
	}

	return relyingParty
}

func getRelyingPartyArgs(cfg *config.Config, provider string, log log.Logger) (
	string, string, string, string, []string, []rp.Option,
) {
	if _, ok := cfg.HTTP.Auth.OpenID.Providers[provider]; !ok {
		log.Panic().Err(zerr.ErrOpenIDProviderDoesNotExist).Str("provider", provider).Msg("")
	}

	clientID := cfg.HTTP.Auth.OpenID.Providers[provider].ClientID
	clientSecret := cfg.HTTP.Auth.OpenID.Providers[provider].ClientSecret

	scopes := cfg.HTTP.Auth.OpenID.Providers[provider].Scopes
	// openid scope must be the first one in list
	if !zcommon.Contains(scopes, oidc.ScopeOpenID) && config.IsOpenIDSupported(provider) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	port := cfg.HTTP.Port
	issuer := cfg.HTTP.Auth.OpenID.Providers[provider].Issuer
	keyPath := cfg.HTTP.Auth.OpenID.Providers[provider].KeyPath
	baseURL := net.JoinHostPort(cfg.HTTP.Address, port)

	callback := constants.CallbackBasePath + fmt.Sprintf("/%s", provider)

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

	key := securecookie.GenerateRandomKey(32) //nolint: gomnd

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithMaxAge(relyingPartyCookieMaxAge))
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

func hasSessionHeader(request *http.Request) bool {
	clientHeader := request.Header.Get(constants.SessionClientHeaderName)

	return clientHeader == constants.SessionClientHeaderValue
}

func getUsernamePasswordBasicAuth(request *http.Request) (string, string, error) {
	basicAuth := request.Header.Get("Authorization")

	if basicAuth == "" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	splitStr := strings.SplitN(basicAuth, " ", 2) //nolint: gomnd
	if len(splitStr) != 2 || strings.ToLower(splitStr[0]) != "basic" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	decodedStr, err := base64.StdEncoding.DecodeString(splitStr[1])
	if err != nil {
		return "", "", err
	}

	pair := strings.SplitN(string(decodedStr), ":", 2) //nolint: gomnd
	if len(pair) != 2 {                                //nolint: gomnd
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
	request *http.Request, identity string, log log.Logger,
) error {
	session, _ := cookieStore.Get(request, "session")

	session.Options.Secure = true
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
		Secure:   true,
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
			Msg(": failed to get 'state' cookie from request")

		return "", zerr.ErrInvalidStateCookie
	}

	if stateOrigin != state {
		ctlr.Log.Error().Err(zerr.ErrInvalidStateCookie).Str("component", "openID").
			Msg(": 'state' cookie differs from the actual one")

		return "", zerr.ErrInvalidStateCookie
	}

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername(email)
	userAc.AddGroups(groups)
	userAc.SaveOnRequest(r)

	// if this line has been reached, then a new session should be created
	// if the `session` key is already on the cookie, it's not a valid one
	if err := saveUserLoggedSession(ctlr.CookieStore, w, r, email, ctlr.Log); err != nil {
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

	return godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil))).Encoded()
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
