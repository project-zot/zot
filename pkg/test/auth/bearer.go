package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/mitchellh/mapstructure"
)

type (
	AccessTokenResponse struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // token format
	}

	AuthHeader struct {
		Realm   string
		Service string
		Scope   string
	}
)

func MakeAuthTestServer(serverKey string, unauthorizedNamespace string) *httptest.Server {
	cmTokenGenerator, err := auth.NewTokenGenerator(&auth.TokenGeneratorOptions{
		PrivateKeyPath: serverKey,
		Audience:       "Zot Registry",
		Issuer:         "Zot",
		AddKIDHeader:   true,
	})
	if err != nil {
		panic(err)
	}

	authTestServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var access []auth.AccessEntry

		scope := request.URL.Query().Get("scope")
		if scope != "" {
			parts := strings.Split(scope, ":")
			name := parts[1]
			actions := strings.Split(parts[2], ",")
			if name == unauthorizedNamespace {
				actions = []string{}
			}
			access = []auth.AccessEntry{
				{
					Name:    name,
					Type:    "repository",
					Actions: actions,
				},
			}
		}

		token, err := cmTokenGenerator.GenerateToken(access, time.Minute*1)
		if err != nil {
			panic(err)
		}
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(response, `{"access_token": "%s"}`, token)
	}))

	return authTestServer
}

func ParseBearerAuthHeader(authHeaderRaw string) *AuthHeader {
	re := regexp.MustCompile(`([a-zA-z]+)="(.+?)"`)
	matches := re.FindAllStringSubmatch(authHeaderRaw, -1)
	matchmap := make(map[string]string)

	for i := 0; i < len(matches); i++ {
		matchmap[matches[i][1]] = matches[i][2]
	}

	var h AuthHeader
	if err := mapstructure.Decode(matchmap, &h); err != nil {
		panic(err)
	}

	return &h
}
