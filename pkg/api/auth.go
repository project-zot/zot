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
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewError(UNAUTHORIZED))
}

// nolint (gocyclo) - we use closure making this a complex subroutine
func BasicAuthHandler(c *Controller) mux.MiddlewareFunc {
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
					r.Method != "GET" && r.Method != "HEAD" {
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

			for {
				r := bufio.NewReader(f)
				line, err := r.ReadString('\n')
				if err != nil {
					break
				}
				tokens := strings.Split(line, ":")
				credMap[tokens[0]] = tokens[1]
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if (r.Method == "GET" || r.Method == "HEAD") && c.Config.HTTP.AllowReadAccess {
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

			// prefer LDAP if configured
			if c.Config.HTTP.Auth != nil && c.Config.HTTP.Auth.LDAP != nil {
				ok, _, err := ldapClient.Authenticate(username, passphrase)
				if ok && err == nil {
					// Process request
					next.ServeHTTP(w, r)
					return
				}
			}

			// fallback to HTTPPassword
			passphraseHash, ok := credMap[username]
			if !ok {
				authFail(w, realm, delay)
				return
			}

			if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err != nil {
				authFail(w, realm, delay)
				return
			}

			// Process request
			next.ServeHTTP(w, r)
		})
	}
}
