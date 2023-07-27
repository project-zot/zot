package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
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

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	apiErr "zotregistry.io/zot/pkg/api/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

const (
	bearerAuthDefaultAccessEntryType = "repository"
	issuedAtOffset                   = 5 * time.Second
	relyingPartyCookieMaxAge         = 120
)

type AuthnMiddleware struct {
	credMap    map[string]string
	ldapClient *LDAPClient
}

func AuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	authnMiddleware := &AuthnMiddleware{}

	if ctlr.Config.IsBearerAuthEnabled() {
		return bearerAuthHandler(ctlr)
	}

	return authnMiddleware.TryAuthnHandlers(ctlr)
}

func (amw *AuthnMiddleware) sessionAuthn(ctlr *Controller, response http.ResponseWriter,
	request *http.Request,
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

	ctx := getReqContextWithAuthorization(identity, []string{}, request)

	groups, err := ctlr.MetaDB.GetUserGroups(ctx)
	if err != nil {
		ctlr.Log.Err(err).Str("identity", identity).Msg("can not get user profile in DB")

		return false, err
	}

	ctx = getReqContextWithAuthorization(identity, groups, request)
	*request = *request.WithContext(ctx)

	return true, nil
}

func (amw *AuthnMiddleware) basicAuthn(ctlr *Controller, response http.ResponseWriter,
	request *http.Request,
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

			ctx := getReqContextWithAuthorization(identity, groups, request)
			*request = *request.WithContext(ctx)

			// saved logged session
			if err := saveUserLoggedSession(cookieStore, response, request, identity, ctlr.Log); err != nil {
				return false, err
			}

			if err := ctlr.MetaDB.SetUserGroups(ctx, groups); err != nil {
				ctlr.Log.Error().Err(err).Str("identity", identity).Msg("couldn't update user profile")

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

			ctx := getReqContextWithAuthorization(identity, groups, request)
			*request = *request.WithContext(ctx)

			if err := saveUserLoggedSession(cookieStore, response, request, identity, ctlr.Log); err != nil {
				return false, err
			}

			if err := ctlr.MetaDB.SetUserGroups(ctx, groups); err != nil {
				ctlr.Log.Error().Err(err).Str("identity", identity).Msg("couldn't update user profile")

				return false, err
			}

			return true, nil
		}
	}

	// last try API keys
	if ctlr.Config.IsAPIKeyEnabled() {
		apiKey := passphrase

		if !strings.HasPrefix(apiKey, constants.APIKeysPrefix) {
			ctlr.Log.Error().Msg("api token has invalid format")

			return false, nil
		}

		trimmedAPIKey := strings.TrimPrefix(apiKey, constants.APIKeysPrefix)

		hashedKey := hashUUID(trimmedAPIKey)

		storedIdentity, err := ctlr.MetaDB.GetUserAPIKeyInfo(hashedKey)
		if err != nil {
			if errors.Is(err, zerr.ErrUserAPIKeyNotFound) {
				ctlr.Log.Info().Err(err).Msgf("can not find any user info for hashed key %s in DB", hashedKey)

				return false, nil
			}

			ctlr.Log.Error().Err(err).Msgf("can not get user info for hashed key %s in DB", hashedKey)

			return false, err
		}

		if storedIdentity == identity {
			ctx := getReqContextWithAuthorization(identity, []string{}, request)

			err := ctlr.MetaDB.UpdateUserAPIKeyLastUsed(ctx, hashedKey)
			if err != nil {
				ctlr.Log.Err(err).Str("identity", identity).Msg("can not update user profile in DB")

				return false, err
			}

			groups, err := ctlr.MetaDB.GetUserGroups(ctx)
			if err != nil {
				ctlr.Log.Err(err).Str("identity", identity).Msg("can not get user's groups in DB")

				return false, err
			}

			ctx = getReqContextWithAuthorization(identity, groups, request)
			*request = *request.WithContext(ctx)

			return true, nil
		}
	}

	return false, nil
}

func (amw *AuthnMiddleware) TryAuthnHandlers(ctlr *Controller) mux.MiddlewareFunc { //nolint: gocyclo
	// no password based authN, if neither LDAP nor HTTP BASIC is enabled
	if !ctlr.Config.IsBasicAuthnEnabled() {
		return noPasswdAuth(ctlr.Config)
	}

	amw.credMap = make(map[string]string)

	delay := ctlr.Config.HTTP.Auth.FailDelay

	// setup sessions cookie store used to preserve logged in user in web sessions
	if ctlr.Config.IsBasicAuthnEnabled() {
		// To store custom types in our cookies
		// we must first register them using gob.Register
		gob.Register(map[string]interface{}{})

		cookieStoreHashKey := securecookie.GenerateRandomKey(64)
		if cookieStoreHashKey == nil {
			panic(zerr.ErrHashKeyNotCreated)
		}

		// if storage is filesystem then use zot's rootDir to store sessions
		if ctlr.Config.Storage.StorageDriver == nil {
			sessionsDir := path.Join(ctlr.Config.Storage.RootDirectory, "_sessions")
			if err := os.MkdirAll(sessionsDir, storageConstants.DefaultDirPerms); err != nil {
				panic(err)
			}

			cookieStore := sessions.NewFilesystemStore(sessionsDir, cookieStoreHashKey)

			cookieStore.MaxAge(cookiesMaxAge)

			ctlr.CookieStore = cookieStore
		} else {
			cookieStore := sessions.NewCookieStore(cookieStoreHashKey)

			cookieStore.MaxAge(cookiesMaxAge)

			ctlr.CookieStore = cookieStore
		}
	}

	// ldap and htpasswd based authN
	if ctlr.Config.IsLdapAuthEnabled() {
		ldapConfig := ctlr.Config.HTTP.Auth.LDAP
		amw.ldapClient = &LDAPClient{
			Host:               ldapConfig.Address,
			Port:               ldapConfig.Port,
			UseSSL:             !ldapConfig.Insecure,
			SkipTLS:            !ldapConfig.StartTLS,
			Base:               ldapConfig.BaseDN,
			BindDN:             ldapConfig.BindDN,
			UserGroupAttribute: ldapConfig.UserGroupAttribute, // from config
			BindPassword:       ldapConfig.BindPassword,
			UserFilter:         fmt.Sprintf("(%s=%%s)", ldapConfig.UserAttribute),
			InsecureSkipVerify: ldapConfig.SkipVerify,
			ServerName:         ldapConfig.Address,
			Log:                ctlr.Log,
			SubtreeSearch:      ldapConfig.SubtreeSearch,
		}

		if ctlr.Config.HTTP.Auth.LDAP.CACert != "" {
			caCert, err := os.ReadFile(ctlr.Config.HTTP.Auth.LDAP.CACert)
			if err != nil {
				panic(err)
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				panic(zerr.ErrBadCACert)
			}

			amw.ldapClient.ClientCAs = caCertPool
		} else {
			// default to system cert pool
			caCertPool, err := x509.SystemCertPool()
			if err != nil {
				panic(zerr.ErrBadCACert)
			}

			amw.ldapClient.ClientCAs = caCertPool
		}
	}

	if ctlr.Config.IsHtpasswdAuthEnabled() {
		credsFile, err := os.Open(ctlr.Config.HTTP.Auth.HTPasswd.Path)
		if err != nil {
			panic(err)
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
				rp := NewRelyingPartyOIDC(ctlr.Config, provider)
				ctlr.RelyingParties[provider] = rp
			} else if config.IsOauth2Supported(provider) {
				rp := NewRelyingPartyGithub(ctlr.Config, provider)
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

			// try basic auth if authorization header is given
			if !isAuthorizationHeaderEmpty(request) { //nolint: gocritic
				//nolint: contextcheck
				authenticated, err := amw.basicAuthn(ctlr, response, request)
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
				authenticated, err := amw.sessionAuthn(ctlr, response, request)
				if err != nil {
					if errors.Is(err, zerr.ErrUserDataNotFound) {
						ctlr.Log.Err(err).Msg("can not find user profile in DB")

						authFail(response, request, ctlr.Config.HTTP.Realm, delay)
					}

					response.WriteHeader(http.StatusInternalServerError)

					return
				}

				if authenticated {
					next.ServeHTTP(response, request)

					return
				}
			} else {
				// try anonymous auth only if basic auth/session was not given
				// we want to bypass auth for mgmt route
				isMgmtRequested := request.RequestURI == constants.FullMgmtPrefix
				if ctlr.Config.HTTP.AccessControl.AnonymousPolicyExists() || isMgmtRequested {
					ctx := getReqContextWithAuthorization("", []string{}, request)
					*request = *request.WithContext(ctx) //nolint:contextcheck

					next.ServeHTTP(response, request)

					return
				}
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
		ctlr.Log.Panic().Err(err).Msg("error creating bearer authorizer")
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
			isMgmtRequested := request.RequestURI == constants.FullMgmtPrefix

			header := request.Header.Get("Authorization")

			if isAuthorizationHeaderEmpty(request) && isMgmtRequested {
				next.ServeHTTP(response, request)

				return
			}

			action := auth.PullAction
			if m := request.Method; m != http.MethodGet && m != http.MethodHead {
				action = auth.PushAction
			}

			permissions, err := authorizer.Authorize(header, action, name)
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("issue parsing Authorization header")
				response.Header().Set("Content-Type", "application/json")
				common.WriteJSON(response, http.StatusInternalServerError, apiErr.NewErrorList(apiErr.NewError(apiErr.UNSUPPORTED)))

				return
			}

			if !permissions.Allowed {
				response.Header().Set("Content-Type", "application/json")
				response.Header().Set("WWW-Authenticate", permissions.WWWAuthenticateHeader)

				common.WriteJSON(response, http.StatusUnauthorized,
					apiErr.NewErrorList(apiErr.NewError(apiErr.UNAUTHORIZED)))

				return
			}

			amCtx := acCtrlr.getAuthnMiddlewareContext(BEARER, request)
			next.ServeHTTP(response, request.WithContext(amCtx)) //nolint:contextcheck
		})
	}
}

func noPasswdAuth(config *config.Config) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)
				response.WriteHeader(http.StatusNoContent)

				return
			}

			ctx := getReqContextWithAuthorization("", []string{}, request)
			*request = *request.WithContext(ctx) //nolint:contextcheck

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
			http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.WriteHeader(http.StatusBadRequest)
			})(w, r)
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
			rh.c.Log.Error().Err(err).Msg("unable to save http session")

			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		stateFunc := func() string {
			return state
		}

		rp.AuthURLHandler(stateFunc, client)(w, r)
	}
}

func NewRelyingPartyOIDC(config *config.Config, provider string) rp.RelyingParty {
	issuer, clientID, clientSecret, redirectURI, scopes, options := getRelyingPartyArgs(config, provider)

	relyingParty, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		panic(err)
	}

	return relyingParty
}

func NewRelyingPartyGithub(config *config.Config, provider string) rp.RelyingParty {
	_, clientID, clientSecret, redirectURI, scopes, options := getRelyingPartyArgs(config, provider)

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopes,
		Endpoint:     githubOAuth.Endpoint,
	}

	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		panic(err)
	}

	return relyingParty
}

func getRelyingPartyArgs(cfg *config.Config, provider string) (
	string, string, string, string, []string, []rp.Option,
) {
	if _, ok := cfg.HTTP.Auth.OpenID.Providers[provider]; !ok {
		panic(zerr.ErrOpenIDProviderDoesNotExist)
	}

	scheme := "http"
	if cfg.HTTP.TLS != nil {
		scheme = "https"
	}

	clientID := cfg.HTTP.Auth.OpenID.Providers[provider].ClientID
	clientSecret := cfg.HTTP.Auth.OpenID.Providers[provider].ClientSecret

	scopes := cfg.HTTP.Auth.OpenID.Providers[provider].Scopes
	// openid scope must be the first one in list
	if !common.Contains(scopes, oidc.ScopeOpenID) && config.IsOpenIDSupported(provider) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	port := cfg.HTTP.Port
	issuer := cfg.HTTP.Auth.OpenID.Providers[provider].Issuer
	keyPath := cfg.HTTP.Auth.OpenID.Providers[provider].KeyPath
	baseURL := net.JoinHostPort(cfg.HTTP.Address, port)
	redirectURI := fmt.Sprintf("%s://%s%s", scheme, baseURL, constants.CallbackBasePath+fmt.Sprintf("/%s", provider))

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

func getReqContextWithAuthorization(username string, groups []string, request *http.Request) context.Context {
	acCtx := localCtx.AccessControlContext{
		Username: username,
		Groups:   groups,
	}

	authzCtxKey := localCtx.GetContextKey()
	ctx := context.WithValue(request.Context(), authzCtxKey, acCtx)

	return ctx
}

func authFail(w http.ResponseWriter, r *http.Request, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)

	// don't send auth headers if request is coming from UI
	if r.Header.Get(constants.SessionClientHeaderName) != constants.SessionClientHeaderValue {
		if realm == "" {
			realm = "Authorization Required"
		}

		realm = "Basic realm=" + strconv.Quote(realm)

		w.Header().Set("WWW-Authenticate", realm)
	}

	w.Header().Set("Content-Type", "application/json")
	common.WriteJSON(w, http.StatusUnauthorized, apiErr.NewErrorList(apiErr.NewError(apiErr.UNAUTHORIZED)))
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
		log.Error().Msg("couldn't set user record for empty email value")

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
		log.Error().Msg("couldn't set user record for empty email value")

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
		log.Error().Err(err).Str("identity", identity).Msg("unable to save http session")

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
		ctlr.Log.Error().Err(zerr.ErrInvalidStateCookie).Msg("openID: unable to get 'state' cookie from request")

		return "", zerr.ErrInvalidStateCookie
	}

	if stateOrigin != state {
		ctlr.Log.Error().Err(zerr.ErrInvalidStateCookie).Msg("openID: 'state' cookie differs from the actual one")

		return "", zerr.ErrInvalidStateCookie
	}

	ctx := getReqContextWithAuthorization(email, groups, r)

	// if this line has been reached, then a new session should be created
	// if the `session` key is already on the cookie, it's not a valid one
	if err := saveUserLoggedSession(ctlr.CookieStore, w, r, email, ctlr.Log); err != nil {
		return "", err
	}

	if err := ctlr.MetaDB.SetUserGroups(ctx, groups); err != nil {
		ctlr.Log.Error().Err(err).Str("identity", email).Msg("couldn't update the user profile")

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
		log.Error().Err(err).Msg("can not decode existing session")
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
		log.Error().Msg("can not get `user` session value")

		return "", false
	}

	identity, ok := session.Values["user"].(string)
	if !ok {
		log.Error().Msg("can not get `user` session value")

		return "", false
	}

	return identity, true
}
