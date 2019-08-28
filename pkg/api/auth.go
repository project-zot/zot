package api

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func authFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusUnauthorized, NewError(UNAUTHORIZED))
}

func BasicAuthHandler(c *Controller) mux.MiddlewareFunc {
	realm := c.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)
	delay := c.Config.HTTP.Auth.FailDelay

	if c.Config.HTTP.Auth.HTPasswd.Path == "" {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.Config.HTTP.AllowReadAccess &&
					c.Config.HTTP.TLS.CACert != "" &&
					r.TLS.VerifiedChains == nil &&
					r.Method != "GET" && r.Method != "HEAD" {
					authFail(w, realm, delay)
					return
				}

				// Process request
				next.ServeHTTP(w, r)
			})
		}
	}

	credMap := make(map[string]string)

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
