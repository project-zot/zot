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

	"github.com/anuvu/zot/errors"
	"github.com/chartmuseum/auth"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	bearerAuthDefaultAccessEntryType = "repository"
)

func AuthHandler(c *Controller) mux.MiddlewareFunc {
	if c.Config.HTTP.Auth != nil &&
		c.Config.HTTP.Auth.Bearer != nil &&
		c.Config.HTTP.Auth.Bearer.Cert != "" &&
		c.Config.HTTP.Auth.Bearer.Realm != "" &&
		c.Config.HTTP.Auth.Bearer.Service != "" {
		return bearerAuthHandler(c)
	}

	return basicAuthHandler(c)
}

func bearerAuthHandler(c *Controller) mux.MiddlewareFunc {
	authorizer, err := auth.NewAuthorizer(&auth.AuthorizerOptions{
		Realm:                 c.Config.HTTP.Auth.Bearer.Realm,
		Service:               c.Config.HTTP.Auth.Bearer.Service,
		PublicKeyPath:         c.Config.HTTP.Auth.Bearer.Cert,
		AccessEntryType:       bearerAuthDefaultAccessEntryType,
		EmptyDefaultNamespace: true,
	})
	if err != nil {
		c.Log.Panic().Err(err).Msg("error creating bearer authorizer")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)
			name := vars["name"]
			header := r.Header.Get("Authorization")
			action := auth.PullAction
			if m := r.Method; m != http.MethodGet && m != http.MethodHead {
				action = auth.PushAction
			}
			permissions, err := authorizer.Authorize(header, action, name)
			if err != nil {
				c.Log.Error().Err(err).Msg("issue parsing Authorization header")
				w.Header().Set("Content-Type", "application/json")
				WriteJSON(w, http.StatusInternalServerError, NewErrorList(NewError(UNSUPPORTED)))
				return
			}
			if !permissions.Allowed {
				authFail(w, permissions.WWWAuthenticateHeader, 0)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// nolint (gocyclo) - we use closure making this a complex subroutine
func basicAuthHandler(c *Controller) mux.MiddlewareFunc {
	realm := c.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)

	// no password based authN, if neither LDAP nor HTTP BASIC is enabled
	if c.Config.HTTP.Auth == nil || (c.Config.HTTP.Auth.HTPasswd.Path == "" && c.Config.HTTP.Auth.LDAP == nil) {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.Config.HTTP.AllowReadAccess &&
					c.Config.HTTP.TLS.CACert != "" &&
					r.TLS.VerifiedChains == nil &&
					r.Method != http.MethodGet && r.Method != http.MethodHead {
					authFail(w, realm, 5)
					return
				}
				// Process request
				next.ServeHTTP(w, r)
			})
		}
	}

	credMap := make(map[string]string)
	delay := c.Config.HTTP.Auth.FailDelay
	var ldapClient *LDAPClient

	if c.Config.HTTP.Auth != nil {
		if c.Config.HTTP.Auth.LDAP != nil {
			l := c.Config.HTTP.Auth.LDAP
			ldapClient = &LDAPClient{
				Host:               l.Address,
				Port:               l.Port,
				UseSSL:             !l.Insecure,
				SkipTLS:            !l.StartTLS,
				Base:               l.BaseDN,
				BindDN:             l.BindDN,
				BindPassword:       l.BindPassword,
				UserFilter:         fmt.Sprintf("(%s=%%s)", l.UserAttribute),
				InsecureSkipVerify: l.SkipVerify,
				ServerName:         l.Address,
				Log:                c.Log,
				SubtreeSearch:      l.SubtreeSearch,
			}
			if c.Config.HTTP.Auth.LDAP.CACert != "" {
				caCert, err := ioutil.ReadFile(c.Config.HTTP.Auth.LDAP.CACert)
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
		if c.Config.HTTP.Auth.HTPasswd.Path != "" {
			f, err := os.Open(c.Config.HTTP.Auth.HTPasswd.Path)
			if err != nil {
				panic(err)
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)

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
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && c.Config.HTTP.AllowReadAccess {
				// Process request
				next.ServeHTTP(w, r)
				return
			}

			basicAuth := r.Header.Get("Authorization")
			if basicAuth == "" {
				authFail(w, realm, delay)
				return
			}

			s := strings.SplitN(basicAuth, " ", 2)
			if len(s) != 2 || strings.ToLower(s[0]) != "basic" {
				authFail(w, realm, delay)
				return
			}

			b, err := base64.StdEncoding.DecodeString(s[1])
			if err != nil {
				authFail(w, realm, delay)
				return
			}

			pair := strings.SplitN(string(b), ":", 2)
			if len(pair) != 2 {
				authFail(w, realm, delay)
				return
			}

			username := pair[0]
			passphrase := pair[1]

			// first, HTTPPassword authN (which is local)
			passphraseHash, ok := credMap[username]
			if ok {
				if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err == nil {
					// Process request
					next.ServeHTTP(w, r)
					return
				}
			}

			// next, LDAP if configured (network-based which can lose connectivity)
			if c.Config.HTTP.Auth != nil && c.Config.HTTP.Auth.LDAP != nil {
				ok, _, err := ldapClient.Authenticate(username, passphrase)
				if ok && err == nil {
					// Process request
					next.ServeHTTP(w, r)
					return
				}
			}

			authFail(w, realm, delay)
			return
		})
	}
}

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewErrorList(NewError(UNAUTHORIZED)))
}
