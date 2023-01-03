package api

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/pkg/http"
	"golang.org/x/crypto/bcrypt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
)

const (
	bearerAuthDefaultAccessEntryType = "repository"
	issuedAtOffset                   = 5 * time.Second
	relyingPartyCookieMaxAge         = 120
)

type AuthnMiddlewareComponent interface {
	MdwFunc(prevMdwFinished bool) mux.MiddlewareFunc
	SetNext(AuthnMiddlewareComponent)
	GetNext() AuthnMiddlewareComponent
}

type OpenIDAuthMiddleware struct {
	nextAuthMdw AuthnMiddlewareComponent
	ctlr        *Controller
}
type BasicAuthMiddleware struct {
	nextAuthMdw AuthnMiddlewareComponent
	ctlr        *Controller
}

func AuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	var oidmdw *OpenIDAuthMiddleware

	basicmdw := &BasicAuthMiddleware{
		ctlr: ctlr,
	}

	if isBearerAuthEnabled(ctlr.Config) {
		return bearerAuthHandler(ctlr)
	}

	if isOpenIDAuthEnabled(ctlr.Config) {
		oidmdw = &OpenIDAuthMiddleware{
			ctlr: ctlr,
		}

		basicmdw.SetNext(oidmdw)
	}

	return basicmdw.MdwFunc(true)
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
				response.WriteHeader(http.StatusNoContent)

				return
			}
			acCtrlr := NewAccessController(ctlr.Config)
			vars := mux.Vars(request)
			name := vars["name"]
			header := request.Header.Get("Authorization")
			action := auth.PullAction
			if m := request.Method; m != http.MethodGet && m != http.MethodHead {
				action = auth.PushAction
			}
			permissions, err := authorizer.Authorize(header, action, name)
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("issue parsing Authorization header")
				response.Header().Set("Content-Type", "application/json")
				WriteJSON(response, http.StatusInternalServerError, NewErrorList(NewError(UNSUPPORTED)))

				return
			}

			if !permissions.Allowed {
				authFail(response, permissions.WWWAuthenticateHeader, 0)

				return
			}

			amCtx := acCtrlr.getAuthnMdwContext(BEARER, request)
			next.ServeHTTP(response, request.WithContext(amCtx)) //nolint:contextcheck
		})
	}
}

func noPasswdAuth(config *config.Config) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				response.WriteHeader(http.StatusNoContent)

				return
			}

			acCtrlr := NewAccessController(config)
			acCtx := acCtrlr.getContext("", []string{}, request)
			// Process request
			next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck
		})
	}
}

func (oidmdw *OpenIDAuthMiddleware) GetNext() AuthnMiddlewareComponent {
	return oidmdw.nextAuthMdw
}

func (oidmdw *OpenIDAuthMiddleware) SetNext(next AuthnMiddlewareComponent) {
	oidmdw.nextAuthMdw = next
}

func (oidmdw *OpenIDAuthMiddleware) MdwFunc(prevMdwFinished bool) mux.MiddlewareFunc {
	realm := oidmdw.ctlr.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}

	realm = "Basic realm=" + strconv.Quote(realm)
	delay := oidmdw.ctlr.Config.HTTP.Auth.FailDelay

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// needed for checking whether the current mdw work is finished or not
			canNextBegin := false

			if !prevMdwFinished {
				oidmdw.ctlr.Log.Info().
					Msg("previous middleware work not finished, not proceeding with this current one")
				// done = false
				return
			}

			defer func(next http.Handler) {
				if oidmdw.nextAuthMdw != nil {
					oidmdw.nextAuthMdw.MdwFunc(canNextBegin)(next).ServeHTTP(response, request)
				} else if canNextBegin {
					authFail(response, realm, delay)
				}
			}(next)

			clientHeader := request.Header.Get("X-ZOT-API-CLIENT")
			acCtrlr := NewAccessController(oidmdw.ctlr.Config)

			session, err := oidmdw.ctlr.CookieStore.Get(request, "session")
			if err != nil {
				oidmdw.ctlr.Log.Err(err).Msg("can not decode existing session")

				http.Error(response, "invalid session encoding", http.StatusInternalServerError)

				return
			}

			if clientHeader != "zot-hub" { //nolint:nestif
				if !session.IsNew {
					oidmdw.ctlr.Log.Error().Msg("request is missing client header")
					response.WriteHeader(http.StatusUnauthorized)

					return
				}
				// get api token from Authorization header - cli client use case

				// first, API key authn, db lookup
				if oidmdw.ctlr.Config.HTTP.Auth.OpenID.APIKeys {
					var apiKey string

					if request.Method == http.MethodOptions {
						response.WriteHeader(http.StatusNoContent)

						return
					}

					// we want to bypass auth for mgmt route
					isMgmtRequested := request.RequestURI == constants.FullMgmtPrefix
					if request.Header.Get("Authorization") == "" {
						if anonymousPolicyExists(oidmdw.ctlr.Config.HTTP.AccessControl) || isMgmtRequested {
							acCtx := acCtrlr.getContext("", []string{}, request)
							next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

							return
						}
					}

					username, apiKey, err := getUsernamePasswordBasicAuth(request)
					if err != nil {
						oidmdw.ctlr.Log.Error().Err(err).Msg("failed to parse Basic authorization header")
						// done = false
						authFail(response, realm, delay)

						return
					}

					// some client tools might send Authorization: Basic Og== (decoded into ":")
					// empty username and password
					if username == "" && apiKey == "" {
						if anonymousPolicyExists(oidmdw.ctlr.Config.HTTP.AccessControl) || isMgmtRequested {
							// Process request
							acCtx := acCtrlr.getContext("", []string{}, request)
							next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

							return
						}
					}

					if apiKey != "" {
						if !strings.HasPrefix(apiKey, constants.APIKeysPrefix) {
							oidmdw.ctlr.Log.Error().Msg("api token has invalid format")
							response.WriteHeader(http.StatusUnauthorized)

							return
						}

						trimmedAPIKey := strings.TrimPrefix(apiKey, constants.APIKeysPrefix)
						hashedKey := hashUUID(trimmedAPIKey)
						email, err := oidmdw.ctlr.UserSecDB.GetUserAPIKeyInfo(hashedKey)
						if err != nil {
							oidmdw.ctlr.Log.Err(err).Msgf("can not get user info for hashed key %s from DB", hashedKey)
							response.WriteHeader(http.StatusUnauthorized)

							return
						}

						if email == username {
							userProfile, err := oidmdw.ctlr.UserSecDB.GetUserProfile(email)
							if err != nil {
								oidmdw.ctlr.Log.Err(err).Msg("can not get user profile from DB")
								response.WriteHeader(http.StatusInternalServerError)

								return
							}
							acCtx := acCtrlr.getContext(username, userProfile.Groups, request)
							// hashedAPIkey entry in DB exists
							next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

							return
						}
					}

					canNextBegin = true
				}

				return
			}

			if session.IsNew {
				response.WriteHeader(http.StatusUnauthorized)

				return
			}

			authenticated := session.Values["authStatus"]
			if authenticated != true {
				response.WriteHeader(http.StatusUnauthorized)

				return
			}
			email, ok := session.Values["user"].(string)
			if !ok {
				oidmdw.ctlr.Log.Err(err).Msg("can not get `user` session value")
				response.WriteHeader(http.StatusInternalServerError)

				return
			}

			if email != "" {
				userProfile, err := oidmdw.ctlr.UserSecDB.GetUserProfile(email)
				if err != nil {
					oidmdw.ctlr.Log.Err(err).Msg("can not get user profile from DB")
					response.WriteHeader(http.StatusInternalServerError)

					return
				}
				acCtx := acCtrlr.getContext(email, userProfile.Groups, request)
				// allow data to be written, now that mdw has passed

				next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck
			}

			canNextBegin = true
		})
	}
}

func (rh *RouteHandler) AuthURLHandler(ctlr *Controller, provider string) http.HandlerFunc {
	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	client, ok := ctlr.RelyingParties[provider]
	if !ok {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.WriteHeader(http.StatusBadRequest)
		})
	}

	return rp.AuthURLHandler(state, client)
}

func NewRelyingPartyOIDC(config *config.Config, provider string) rp.RelyingParty {
	if _, ok := config.HTTP.Auth.OpenID.Providers[provider]; !ok {
		panic(zerr.ErrOpenIDProviderDoesNotExist)
	}

	var callback string

	switch provider {
	case "dex":
		callback = constants.DexCallbackPath
	default:
		panic(zerr.ErrOpenIDProviderDoesNotExist)
	}

	scheme := "http"
	if config.HTTP.TLS != nil {
		scheme = "https"
	}
	clientID := config.HTTP.Auth.OpenID.Providers[provider].ClientID
	clientSecret := config.HTTP.Auth.OpenID.Providers[provider].ClientSecret
	scopes := config.HTTP.Auth.OpenID.Providers[provider].Scopes
	port := config.HTTP.Port
	issuer := config.HTTP.Auth.OpenID.Providers[provider].Issuer
	keyPath := ""
	baseURL := net.JoinHostPort(config.HTTP.Address, port)
	redirectURI := fmt.Sprintf("%s://%s%s", scheme, baseURL, callback)
	secureCookieHashKey := []byte(config.HTTP.Auth.OpenID.SecureCookieHashKey)
	secureCookieEncryptionKey := []byte(config.HTTP.Auth.OpenID.SecureCookieEncryptionKey)
	cookieHandler := httphelper.NewCookieHandler(secureCookieHashKey, secureCookieEncryptionKey,
		httphelper.WithMaxAge(relyingPartyCookieMaxAge))

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(issuedAtOffset)),
	}

	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	relyingParty, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		panic(err)
	}

	return relyingParty
}

func (baum *BasicAuthMiddleware) GetNext() AuthnMiddlewareComponent {
	return baum.nextAuthMdw
}

func (baum *BasicAuthMiddleware) SetNext(next AuthnMiddlewareComponent) {
	baum.nextAuthMdw = next
}

//nolint:gocyclo
func (baum *BasicAuthMiddleware) MdwFunc(prevMdwFinished bool) mux.MiddlewareFunc {
	realm := baum.ctlr.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}

	realm = "Basic realm=" + strconv.Quote(realm)

	// no password based authN, if neither LDAP nor HTTP BASIC is enabled
	if baum.ctlr.Config.HTTP.Auth == nil ||
		(baum.ctlr.Config.HTTP.Auth.HTPasswd.Path == "" && baum.ctlr.Config.HTTP.Auth.LDAP == nil) {
		return noPasswdAuth(baum.ctlr.Config)
	}

	credMap := make(map[string]string)

	delay := baum.ctlr.Config.HTTP.Auth.FailDelay

	var ldapClient *LDAPClient

	if baum.ctlr.Config.HTTP.Auth != nil {
		if baum.ctlr.Config.HTTP.Auth.LDAP != nil {
			ldapConfig := baum.ctlr.Config.HTTP.Auth.LDAP
			ldapClient = &LDAPClient{
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
				Log:                baum.ctlr.Log,
				SubtreeSearch:      ldapConfig.SubtreeSearch,
			}

			if baum.ctlr.Config.HTTP.Auth.LDAP.CACert != "" {
				caCert, err := os.ReadFile(baum.ctlr.Config.HTTP.Auth.LDAP.CACert)
				if err != nil {
					panic(err)
				}

				caCertPool := x509.NewCertPool()

				if !caCertPool.AppendCertsFromPEM(caCert) {
					panic(zerr.ErrBadCACert)
				}

				ldapClient.ClientCAs = caCertPool
			} else {
				// default to system cert pool
				caCertPool, err := x509.SystemCertPool()
				if err != nil {
					panic(zerr.ErrBadCACert)
				}

				ldapClient.ClientCAs = caCertPool
			}
		}

		if baum.ctlr.Config.HTTP.Auth.HTPasswd.Path != "" {
			credsFile, err := os.Open(baum.ctlr.Config.HTTP.Auth.HTPasswd.Path)
			if err != nil {
				panic(err)
			}
			defer credsFile.Close()

			scanner := bufio.NewScanner(credsFile)

			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, ":") {
					tokens := strings.Split(scanner.Text(), ":")
					credMap[tokens[0]] = tokens[1]
				}
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// needed for checking whether the current mdw work is finished or not
			canNextBegin := false

			if !prevMdwFinished {
				baum.ctlr.Log.Info().
					Msg("previous middleware work not finished, not proceeding with this current one")

				return
			}
			defer func(next http.Handler) {
				if baum.nextAuthMdw != nil {
					baum.nextAuthMdw.MdwFunc(canNextBegin)(next).ServeHTTP(response, request)
				} else if canNextBegin {
					authFail(response, realm, delay)
				}
			}(next)
			if request.Method == http.MethodOptions {
				response.WriteHeader(http.StatusNoContent)

				return
			}

			// we want to bypass auth for mgmt route
			isMgmtRequested := request.RequestURI == constants.FullMgmtPrefix

			acCtrlr := NewAccessController(baum.ctlr.Config)
			_, cookieErr := request.Cookie("session")
			if request.Header.Get("Authorization") == "" {
				if (anonymousPolicyExists(baum.ctlr.Config.HTTP.AccessControl) &&
					errors.Is(cookieErr, http.ErrNoCookie)) || isMgmtRequested {
					acCtx := acCtrlr.getContext("", []string{}, request)
					// Process request
					next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

					return
				}
			}

			username, passphrase, err := getUsernamePasswordBasicAuth(request)
			if err != nil {
				baum.ctlr.Log.Error().Err(err).Msg("failed to parse authorization header")
				if cookieErr == nil { // so session cookie exists
					canNextBegin = true

					return
				}

				authFail(response, realm, delay)

				return
			}

			// some client tools might send Authorization: Basic Og== (decoded into ":")
			// empty username and password
			if username == "" && passphrase == "" {
				if (anonymousPolicyExists(baum.ctlr.Config.HTTP.AccessControl) &&
					errors.Is(cookieErr, http.ErrNoCookie)) || isMgmtRequested {
					acCtx := acCtrlr.getContext("", []string{}, request)
					next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

					return
				}
			}

			// first, HTTPPassword authN (which is local)
			passphraseHash, ok := credMap[username]
			if ok {
				if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err == nil {
					// Process request
					var userGroups []string

					if baum.ctlr.Config.HTTP.AccessControl != nil {
						userGroups = acCtrlr.getUserGroups(username)
					}

					// canNextBegin = false
					acCtx := acCtrlr.getContext(username, userGroups, request)
					next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

					return
				}
			}

			// next, LDAP if configured (network-based which can lose connectivity)
			if baum.ctlr.Config.HTTP.Auth != nil && baum.ctlr.Config.HTTP.Auth.LDAP != nil {
				ok, _, ldapgroups, err := ldapClient.Authenticate(username, passphrase)
				if ok && err == nil {
					// Process request
					var userGroups []string

					if baum.ctlr.Config.HTTP.AccessControl != nil {
						userGroups = acCtrlr.getUserGroups(username)
					}

					userGroups = append(userGroups, ldapgroups...)

					acCtx := acCtrlr.getContext(username, userGroups, request)
					next.ServeHTTP(response, request.WithContext(acCtx)) //nolint:contextcheck

					return
				}
			}
			canNextBegin = true
		})
	}
}

func isAuthnEnabled(config *config.Config) bool {
	if config.HTTP.Auth != nil &&
		(config.HTTP.Auth.HTPasswd.Path != "" || config.HTTP.Auth.LDAP != nil) {
		return true
	}

	return false
}

func isBearerAuthEnabled(config *config.Config) bool {
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.Bearer != nil &&
		config.HTTP.Auth.Bearer.Cert != "" &&
		config.HTTP.Auth.Bearer.Realm != "" &&
		config.HTTP.Auth.Bearer.Service != "" {
		return true
	}

	return false
}

func isOpenIDAuthEnabled(config *config.Config) bool {
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.OpenID != nil {
		if !isOpenIDAuthProviderEnabled(config, "dex") &&
			!isAPIKeyEnabled(config) { // API key support needed for cli clients
			return false
		}

		return true
	}

	return false
}

func isAPIKeyEnabled(config *config.Config) bool {
	if config.HTTP.Auth != nil && config.HTTP.Auth.OpenID != nil &&
		config.HTTP.Auth.OpenID.APIKeys {
		return true
	}

	return false
}

func isOpenIDAuthProviderEnabled(config *config.Config, provider string) bool {
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.OpenID != nil {
		if openIDConfig, ok := config.HTTP.Auth.OpenID.Providers[provider]; ok {
			if openIDConfig.ClientID != "" &&
				openIDConfig.ClientSecret != "" &&
				openIDConfig.Issuer != "" {
				return provider == "dex"
			}
		}
	}

	return false
}

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Add("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewErrorList(NewError(UNAUTHORIZED)))
}

func getUsernamePasswordBasicAuth(request *http.Request) (string, string, error) {
	basicAuth := request.Header.Get("Authorization")

	if basicAuth == "" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	splitStr := strings.SplitN(basicAuth, " ", 2) //nolint:gomnd
	if len(splitStr) != 2 || strings.ToLower(splitStr[0]) != "basic" {
		return "", "", zerr.ErrParsingAuthHeader
	}

	decodedStr, err := base64.StdEncoding.DecodeString(splitStr[1])
	if err != nil {
		return "", "", err
	}

	pair := strings.SplitN(string(decodedStr), ":", 2) //nolint:gomnd
	if len(pair) != 2 {                                //nolint:gomnd
		return "", "", zerr.ErrParsingAuthHeader
	}

	username := pair[0]
	passphrase := pair[1]

	return username, passphrase, nil
}
