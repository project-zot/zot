package api

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
)

const (
	bearerAuthDefaultAccessEntryType = "repository"
)

func AuthHandler(c *Controller) mux.MiddlewareFunc {
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

			if config.HTTP.AllowReadAccess &&
				config.HTTP.TLS.CACert != "" &&
				request.TLS.VerifiedChains == nil &&
				request.Method != http.MethodGet && request.Method != http.MethodHead {
				authFail(response, realm, 5) //nolint:gomnd

				return
			}

			if (request.Method != http.MethodGet && request.Method != http.MethodHead) && config.HTTP.ReadOnly {
				// Reject modification requests in read-only mode
				response.WriteHeader(http.StatusMethodNotAllowed)

				return
			}

			// Process request
			next.ServeHTTP(response, request)
		})
	}
}

// nolint:gocyclo  // we use closure making this a complex subroutine
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
				caCert, err := ioutil.ReadFile(ctlr.Config.HTTP.Auth.LDAP.CACert)
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
			if (request.Method == http.MethodGet || request.Method == http.MethodHead) && ctlr.Config.HTTP.AllowReadAccess {
				// Process request
				next.ServeHTTP(response, request)

				return
			}

			if (request.Method != http.MethodGet && request.Method != http.MethodHead) && ctlr.Config.HTTP.ReadOnly {
				response.WriteHeader(http.StatusMethodNotAllowed)

				return
			}

			basicAuth := request.Header.Get("Authorization")
			if basicAuth == "" {
				authFail(response, realm, delay)

				return
			}

			splitStr := strings.SplitN(basicAuth, " ", 2) //nolint:gomnd

			if len(splitStr) != 2 || strings.ToLower(splitStr[0]) != "basic" {
				authFail(response, realm, delay)

				return
			}

			decodedStr, err := base64.StdEncoding.DecodeString(splitStr[1])
			if err != nil {
				authFail(response, realm, delay)

				return
			}

			pair := strings.SplitN(string(decodedStr), ":", 2) //nolint:gomnd
			// nolint:gomnd
			if len(pair) != 2 {
				authFail(response, realm, delay)

				return
			}

			username := pair[0]
			passphrase := pair[1]

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

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewErrorList(NewError(UNAUTHORIZED)))
}
