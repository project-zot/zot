package auth

import (
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"

	"zotregistry.dev/zot/pkg/api"
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

func MakeAuthTestServer(serverKey, signAlg string, unauthorizedNamespace string) *httptest.Server {
	signingKey := loadPrivateKeyFromFile(serverKey)
	signingMethod := jwt.GetSigningMethod(signAlg)

	authTestServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var access []api.ResourceAccess

		scope := request.URL.Query().Get("scope")
		if scope != "" {
			parts := strings.Split(scope, ":")
			name := parts[1]
			actions := strings.Split(parts[2], ",")

			if name == unauthorizedNamespace {
				actions = []string{}
			}

			access = []api.ResourceAccess{
				{
					Name:    name,
					Type:    "repository",
					Actions: actions,
				},
			}
		}

		now := time.Now()
		claims := api.ClaimsWithAccess{
			Access: access,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 1)),
				IssuedAt:  jwt.NewNumericDate(now),
				Issuer:    "Zot",
				Audience:  []string{"Zot Registry"},
			},
		}

		token := jwt.NewWithClaims(signingMethod, claims)

		signedString, err := token.SignedString(signingKey)
		if err != nil {
			panic(err)
		}

		response.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(response, `{"access_token": "%s"}`, signedString)
	}))

	return authTestServer
}

// MakeAuthTestServerLegacy makes a test HTTP server to generate bearer tokens using the github.com/chartmuseum/auth
// package, to verify backward compatibility of the token authentication process with older versions of zot.
func MakeAuthTestServerLegacy(serverKey string, unauthorizedNamespace string) *httptest.Server {
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

func loadPrivateKeyFromFile(path string) crypto.PrivateKey {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err == nil {
		return rsaKey
	}

	ecKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyBytes)
	if err == nil {
		return ecKey
	}

	edKey, err := jwt.ParseEdPrivateKeyFromPEM(privateKeyBytes)
	if err == nil {
		return edKey
	}

	panic("no valid private key found in file " + path)
}
