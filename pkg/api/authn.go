package api

import (
	"bufio"
	// "context"
	"crypto/x509"
	"encoding/base64"

	// "encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	// "github.com/google/go-github/github"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"

	"github.com/zitadel/oidc/pkg/client/rp"
	// "github.com/zitadel/oidc/pkg/client/rp/cli"
	httphelper "github.com/zitadel/oidc/pkg/http"
	zerr "zotregistry.io/zot/errors"
)

var (
	openidLoginPath       = "/auth/login"
	githubOpenidLoginPath = "/github/auth/login"
	gitlabOpenidLoginPath = "/gitlab/auth/login"
	googleOpenidLoginPath = "/google/auth/login"
	callbackPath          = "/auth/callback"
	githubCallbackPath    = "/github/auth/callback"
	gitlabCallbackPath    = "/gitlab/auth/callback"
	googleCallbackPath    = "/google/auth/callback"
	key                   = []byte("test1234test1234")
	APIKeysPrefix         = "zak_"
)

var RelyingParty rp.RelyingParty

const (
	bearerAuthDefaultAccessEntryType = "repository"
)

func AuthHandler(c *Controller) mux.MiddlewareFunc {
	if isOpenIDAuthEnabled(c.Config) {
		return openIDAuthHandler(c)
	}
	if isBearerAuthEnabled(c.Config) {
		return bearerAuthHandler(c)
	}

	return basicAuthHandler(c)
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

			next.ServeHTTP(response, request)
		})
	}
}

func noPasswdAuth(realm string, config *config.Config) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				response.WriteHeader(http.StatusNoContent)

				return
			}

			// Process request
			next.ServeHTTP(response, request)
		})
	}
}

func getTokenBearerAuth(r *http.Request) (string, error) {
	rawToken := r.Header.Get("Authorization")
	if rawToken == "" {
		return "", errors.ErrParsingAuthHeader
	}
	pieces := strings.SplitN(rawToken, " ", 2)

	if len(pieces) < 2 {
		return "", errors.ErrParsingAuthHeader
	}

	token := strings.TrimSpace(pieces[1])

	return token, nil
}

func openIDAuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	realm := ctlr.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}

	realm = "Basic realm=" + strconv.Quote(realm)
	delay := ctlr.Config.HTTP.Auth.FailDelay

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			clientHeader := request.Header.Get("X-ZOT-API-CLIENT")
			acCtrlr := NewAccessController(ctlr.Config)
			if clientHeader != "zot-hub" {
				// get api token from Authorization header - cli client use case

				// first, API key authn, db lookup
				if ctlr.Config.HTTP.Auth.APIKeys {
					var apiKey string

					if request.Method == http.MethodOptions {
						response.WriteHeader(http.StatusNoContent)

						return
					}
					if request.Header.Get("Authorization") == "" && anonymousPolicyExists(ctlr.Config.AccessControl) {
						// Process request
						next.ServeHTTP(response, request)

						return
					}

					username, apiKey, err := getUsernamePasswordBasicAuth(request)
					if err != nil {
						ctlr.Log.Error().Err(err).Msg("failed to parse Basic authorization header")
						authFail(response, realm, delay)

						return

					}

					// some client tools might send Authorization: Basic Og== (decoded into ":")
					// empty username and password
					if username == "" && apiKey == "" && anonymousPolicyExists(ctlr.Config.AccessControl) {
						// Process request
						next.ServeHTTP(response, request)

						return
					}

					if apiKey != "" {
						if !strings.HasPrefix(apiKey, APIKeysPrefix) {
							ctlr.Log.Error().Msg("api token has invalid format")
							response.WriteHeader(http.StatusUnauthorized)

							return
						}

						trimmedAPIKey := strings.TrimPrefix(apiKey, APIKeysPrefix)
						hashedKey := hashUUID(trimmedAPIKey)
						userInfo, err := ctlr.UserSecDB.GetUserAPIKeyInfo(hashedKey)
						if err != nil {
							ctlr.Log.Err(err).Msgf("can not get user info for hashed key %s from DB", hashedKey)
							response.WriteHeader(http.StatusInternalServerError)

							return
						}

						if userInfo.Email == username {
							acCtx := acCtrlr.getContext(username, request)
							// hashedAPIkey entry in DB exists
							next.ServeHTTP(response, request.WithContext(acCtx))

							return

						}
					}
				}
			}

			session, err := ctlr.CookieStore.Get(request, "session")
			if err != nil {
				ctlr.Log.Err(err).Msg("can not decode existing session")

				http.Error(response, "invalid session encoding", http.StatusInternalServerError)

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
				ctlr.Log.Err(err).Msg("can not get `user` session value")
				response.WriteHeader(http.StatusInternalServerError)

				return
			}

			if email != "" {
				_, err := ctlr.UserSecDB.GetUserProfile(email)
				if err != nil {
					ctlr.Log.Err(err).Msg("can not get user profile from DB")
					response.WriteHeader(http.StatusInternalServerError)

					return
				}
				acCtx := acCtrlr.getContext(email, request)
				next.ServeHTTP(response, request.WithContext(acCtx))
			}
		})
	}
}

func authURLHandler(ctlr *Controller, provider string) http.HandlerFunc {
	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	client, ok := ctlr.RelyingParties[provider]
	if !ok {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.WriteHeader(http.StatusBadRequest)

			return
		})
	}

	return rp.AuthURLHandler(state, client)
}

func NewRelyingPartyOIDC(config *config.Config, provider string) rp.RelyingParty {
	if _, ok := config.HTTP.Auth.OpenID[provider]; !ok {
		panic(zerr.ErrOpenIDProvidertDoesNotExist)
	}
	if provider == "github" {
		return NewGithubRelyingParty(config, provider)
	}
	var callback string
	switch provider {
	case "gitlab":
		callback = gitlabCallbackPath

	case "google":
		callback = googleCallbackPath

	default:
		callback = callbackPath
	}

	clientID := config.HTTP.Auth.OpenID[provider].Client_id
	clientSecret := config.HTTP.Auth.OpenID[provider].Client_secret
	scopes := config.HTTP.Auth.OpenID[provider].Scopes
	port := config.HTTP.Port
	issuer := config.HTTP.Auth.OpenID[provider].Issuer
	keyPath := ""

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callback)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure(), httphelper.WithMaxAge(60))

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	var err error
	relyingParty, err := rp.NewRelyingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		// ctlr.Log.Fatal().Msgf("error creating provider %s", err.Error())

		panic(err)
	}

	return relyingParty
}

func NewGithubRelyingParty(config *config.Config, provider string) rp.RelyingParty {
	clientID := config.HTTP.Auth.OpenID[provider].Client_id
	clientSecret := config.HTTP.Auth.OpenID[provider].Client_secret
	port := config.HTTP.Port

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%v%v", port, githubCallbackPath),
		Scopes:       []string{"user:email"},
		Endpoint:     githubOAuth.Endpoint,
	}

	// ctx := context.Background()
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, rp.WithCookieHandler(cookieHandler))
	if err != nil {
		fmt.Printf("error creating relaying party: %v", err)
		panic(err)
	}

	return relyingParty
}

//nolint:gocyclo  // we use closure making this a complex subroutine
func basicAuthHandler(ctlr *Controller) mux.MiddlewareFunc {
	realm := ctlr.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}

	realm = "Basic realm=" + strconv.Quote(realm)

	// no password based authN, if neither LDAP nor HTTP BASIC is enabled
	if ctlr.Config.HTTP.Auth == nil ||
		(ctlr.Config.HTTP.Auth.HTPasswd.Path == "" && ctlr.Config.HTTP.Auth.LDAP == nil) {
		return noPasswdAuth(realm, ctlr.Config)
	}

	credMap := make(map[string]string)

	delay := ctlr.Config.HTTP.Auth.FailDelay

	var ldapClient *LDAPClient

	if ctlr.Config.HTTP.Auth != nil {
		if ctlr.Config.HTTP.Auth.LDAP != nil {
			ldapConfig := ctlr.Config.HTTP.Auth.LDAP
			ldapClient = &LDAPClient{
				Host:               ldapConfig.Address,
				Port:               ldapConfig.Port,
				UseSSL:             !ldapConfig.Insecure,
				SkipTLS:            !ldapConfig.StartTLS,
				Base:               ldapConfig.BaseDN,
				BindDN:             ldapConfig.BindDN,
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
					panic(errors.ErrBadCACert)
				}

				ldapClient.ClientCAs = caCertPool
			} else {
				// default to system cert pool
				caCertPool, err := x509.SystemCertPool()
				if err != nil {
					panic(errors.ErrBadCACert)
				}

				ldapClient.ClientCAs = caCertPool
			}
		}

		if ctlr.Config.HTTP.Auth.HTPasswd.Path != "" {
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
					credMap[tokens[0]] = tokens[1]
				}
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				response.WriteHeader(http.StatusNoContent)

				return
			}
			if request.Header.Get("Authorization") == "" && anonymousPolicyExists(ctlr.Config.AccessControl) {
				// Process request
				next.ServeHTTP(response, request)

				return
			}

			username, passphrase, err := getUsernamePasswordBasicAuth(request)
			if err != nil {
				ctlr.Log.Error().Err(err).Msg("failed to parse authorization header")
				authFail(response, realm, delay)

				return
			}

			// some client tools might send Authorization: Basic Og== (decoded into ":")
			// empty username and password
			if username == "" && passphrase == "" && anonymousPolicyExists(ctlr.Config.AccessControl) {
				// Process request
				next.ServeHTTP(response, request)

				return
			}

			// first, HTTPPassword authN (which is local)
			passphraseHash, ok := credMap[username]
			if ok {
				if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err == nil {
					// Process request
					next.ServeHTTP(response, request)

					return
				}
			}

			// next, LDAP if configured (network-based which can lose connectivity)
			if ctlr.Config.HTTP.Auth != nil && ctlr.Config.HTTP.Auth.LDAP != nil {
				ok, _, err := ldapClient.Authenticate(username, passphrase)
				if ok && err == nil {
					// Process request
					next.ServeHTTP(response, request)

					return
				}
			}

			authFail(response, realm, delay)
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
	enabled := false
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.OpenID != nil {
		if isOpenIDAuthProviderEnabled(config, "github") {
			enabled = true
		}
		if isOpenIDAuthProviderEnabled(config, "gitlab") {
			enabled = true
		}
		if isOpenIDAuthProviderEnabled(config, "google") {
			enabled = true
		}
		if isOpenIDAuthProviderEnabled(config, "local") {
			enabled = true
		}

		enabled = isAPIKeyEnabled(config)

	}

	return enabled
}

func isAPIKeyEnabled(config *config.Config) bool {
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.APIKeys {
		return true
	}

	return false
}

func isOpenIDAuthProviderEnabled(config *config.Config, provider string) bool {
	if config.HTTP.Auth != nil &&
		config.HTTP.Auth.OpenID != nil {
		if openIDConfig, ok := config.HTTP.Auth.OpenID[provider]; ok {
			if openIDConfig.Client_id != "" &&
				openIDConfig.Client_secret != "" &&
				openIDConfig.Issuer != "" {
				if provider != "github" && len(openIDConfig.Scopes) == 0 {
					return false
				}
				return true
			}
		}
	}
	return false
}

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewErrorList(NewError(UNAUTHORIZED)))
}

func getUsernamePasswordBasicAuth(request *http.Request) (string, string, error) {
	basicAuth := request.Header.Get("Authorization")

	if basicAuth == "" {
		return "", "", errors.ErrParsingAuthHeader
	}

	splitStr := strings.SplitN(basicAuth, " ", 2) //nolint:gomnd
	if len(splitStr) != 2 || strings.ToLower(splitStr[0]) != "basic" {
		return "", "", errors.ErrParsingAuthHeader
	}

	decodedStr, err := base64.StdEncoding.DecodeString(splitStr[1])
	if err != nil {
		return "", "", err
	}

	pair := strings.SplitN(string(decodedStr), ":", 2) //nolint:gomnd
	if len(pair) != 2 {                                //nolint:gomnd
		return "", "", errors.ErrParsingAuthHeader
	}

	username := pair[0]
	passphrase := pair[1]

	return username, passphrase, nil
}
