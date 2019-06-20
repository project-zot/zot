package api

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func authFail(ginCtx *gin.Context, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	ginCtx.Header("WWW-Authenticate", realm)
	ginCtx.AbortWithStatusJSON(http.StatusUnauthorized, NewError(UNAUTHORIZED))
}

func BasicAuthHandler(c *Controller) gin.HandlerFunc {
	if c.Config.HTTP.Auth.HTPasswd.Path == "" {
		// no authentication
		return func(ginCtx *gin.Context) {
		}
	}

	realm := c.Config.HTTP.Realm
	if realm == "" {
		realm = "Authorization Required"
	}
	realm = "Basic realm=" + strconv.Quote(realm)
	delay := c.Config.HTTP.Auth.FailDelay
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

	return func(ginCtx *gin.Context) {
		basicAuth := ginCtx.Request.Header.Get("Authorization")
		if basicAuth == "" {
			authFail(ginCtx, realm, delay)
			return
		}

		s := strings.SplitN(basicAuth, " ", 2)
		if len(s) != 2 || strings.ToLower(s[0]) != "basic" {
			authFail(ginCtx, realm, delay)
			return
		}

		b, err := base64.StdEncoding.DecodeString(s[1])
		if err != nil {
			authFail(ginCtx, realm, delay)
			return
		}

		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			authFail(ginCtx, realm, delay)
			return
		}

		username := pair[0]
		passphrase := pair[1]

		passphraseHash, ok := credMap[username]
		if !ok {
			authFail(ginCtx, realm, delay)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passphraseHash), []byte(passphrase)); err != nil {
			authFail(ginCtx, realm, delay)
			return
		}
	}
}
