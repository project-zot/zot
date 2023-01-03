package common

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	jsoniter "github.com/json-iterator/go"

	"zotregistry.io/zot/pkg/api/constants"
	apiErr "zotregistry.io/zot/pkg/api/errors"
	"zotregistry.io/zot/pkg/log"
)

func AllowedMethods(methods ...string) []string {
	return append(methods, http.MethodOptions)
}

func AddExtensionSecurityHeaders() mux.MiddlewareFunc { //nolint:varnamelen
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("X-Content-Type-Options", "nosniff")

			next.ServeHTTP(resp, req)
		})
	}
}

func ACHeadersHandler(allowedMethods ...string) mux.MiddlewareFunc {
	headerValue := strings.Join(allowedMethods, ",")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("Access-Control-Allow-Methods", headerValue)
			resp.Header().Set("Access-Control-Allow-Headers", "Authorization,content-type,"+constants.SessionClientHeaderName)
			resp.Header().Set("Access-Control-Allow-Credentials", "true")

			if req.Method == http.MethodOptions {
				return
			}

			next.ServeHTTP(resp, req)
		})
	}
}

func AuthzFail(w http.ResponseWriter, r *http.Request, realm string, delay int) {
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
	WriteJSON(w, http.StatusForbidden, apiErr.NewErrorList(apiErr.NewError(apiErr.DENIED)))
}

func WriteJSON(response http.ResponseWriter, status int, data interface{}) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	body, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	WriteData(response, status, constants.DefaultMediaType, body)
}

func WriteData(w http.ResponseWriter, status int, mediaType string, data []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
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
