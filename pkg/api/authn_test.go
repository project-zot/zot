//go:build mgmt

package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	guuid "github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	godigest "github.com/opencontainers/go-digest"
	"github.com/project-zot/mockoidc"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	authutils "zotregistry.dev/zot/v2/pkg/test/auth"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

const (
	sessionCookieName = "session"
	userCookieName    = "user"
	testSubject       = "test-user"
	testKeyID         = "test-key-id"
)

type (
	apiKeyResponse struct {
		mTypes.APIKeyDetails

		APIKey string `json:"apiKey"`
	}
)

type (
	apiKeyListResponse struct {
		APIKeys []mTypes.APIKeyDetails `json:"apiKeys"`
	}
)

func TestAllowedMethodsHeaderAPIKey(t *testing.T) {
	defaultVal := true

	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		conf.HTTP.Auth.APIKey = defaultVal
		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)
		defer ctrlManager.StopServer()

		resp, _ := resty.R().Options(baseURL + constants.APIKeyPath)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,POST,DELETE,OPTIONS")
		So(resp.Header().Get("Access-Control-Allow-Origin"), ShouldResemble, "*")
		So(resp.Header().Get("Access-Control-Allow-Headers"), ShouldResemble, "Authorization,content-type,X-ZOT-API-CLIENT")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
	})
}

func TestValidateCallbackUI(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		allowOrigins []string
		expected     string
	}{
		{name: "empty", input: "", expected: ""},
		{name: "relative path", input: "/v2/", expected: "/v2/"},
		{name: "root path", input: "/", expected: "/"},
		{name: "relative with path", input: "/zot/auth/login", expected: "/zot/auth/login"},
		{name: "absolute URL rejected (not allowlisted)", input: "https://evil.com/phish", expected: "/"},
		{
			name:         "absolute URL allowed when allowlisted (https default port)",
			input:        "https://example.com/home",
			allowOrigins: []string{"https://example.com"},
			expected:     "https://example.com/home",
		},
		{
			name:         "absolute URL allowed when allowlisted (explicit port)",
			input:        "http://localhost:3000/home",
			allowOrigins: []string{"http://localhost:3000"},
			expected:     "http://localhost:3000/home",
		},
		{
			name:         "absolute URL rejected when port differs",
			input:        "http://localhost:3001/home",
			allowOrigins: []string{"http://localhost:3000"},
			expected:     "/",
		},
		{name: "protocol-relative rejected", input: "//evil.com/path", expected: "/"},
		{name: "no leading slash rejected", input: "v2/", expected: "/"},
		{name: "relative path without leading slash rejected", input: "path/segment", expected: "/"},
		{name: "javascript scheme rejected", input: "javascript:alert(1)", expected: "/"},
		{name: "absolute URL with empty host rejected", input: "http:///path", expected: "/"},
		{
			name:         "allowlist entry invalid causes continue then match",
			input:        "https://example.com/home",
			allowOrigins: []string{"  \t  ", "https://example.com"},
			expected:     "https://example.com/home",
		},
		{name: "header injection rejected (newline)", input: "/v2/\nSet-Cookie: x=y", expected: "/"},
		{name: "header injection rejected (carriage return)", input: "/v2/\rSet-Cookie: x=y", expected: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := api.ValidateCallbackUI(tt.input, tt.allowOrigins)
			if got != tt.expected {
				t.Errorf("ValidateCallbackUI(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAPIKeys(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		mockOIDCServer, err := authutils.MockOIDCRun()
		if err != nil {
			panic(err)
		}

		defer func() {
			err := mockOIDCServer.Shutdown()
			if err != nil {
				panic(err)
			}
		}()

		mockOIDCConfig := mockOIDCServer.Config()
		defaultVal := true

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email", "groups"},
					},
				},
			},
			APIKey: defaultVal,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("Random seed for username & password")
		dir := t.TempDir()

		ctlr.Config.Storage.RootDirectory = dir

		cm := test.NewControllerManager(ctlr)

		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		payload := api.APIKeyPayload{
			Label:  "test",
			Scopes: []string{"test"},
		}
		reqBody, err := json.Marshal(payload)
		So(err, ShouldBeNil)

		Convey("API key retrieved with basic auth", func() {
			resp, err := resty.R().
				SetBody(reqBody).
				SetBasicAuth(username, password).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			user := mockoidc.DefaultUser()

			// get API key and email from apikey route response
			var apiKeyResponse apiKeyResponse
			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			email := user.Email
			So(email, ShouldNotBeEmpty)

			resp, err = resty.R().
				SetBasicAuth(username, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// get API key list with basic auth
			resp, err = resty.R().
				SetBasicAuth(username, password).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var apiKeyListResponse apiKeyListResponse
			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)
			So(apiKeyListResponse.APIKeys[0].CreatedAt, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatedAt)
			So(apiKeyListResponse.APIKeys[0].CreatorUA, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatorUA)
			So(apiKeyListResponse.APIKeys[0].Label, ShouldEqual, apiKeyResponse.APIKeyDetails.Label)
			So(apiKeyListResponse.APIKeys[0].Scopes, ShouldEqual, apiKeyResponse.APIKeyDetails.Scopes)
			So(apiKeyListResponse.APIKeys[0].UUID, ShouldEqual, apiKeyResponse.APIKeyDetails.UUID)

			// add another one
			resp, err = resty.R().
				SetBody(reqBody).
				SetBasicAuth(username, password).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			resp, err = resty.R().
				SetBasicAuth(username, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// get API key list with api key auth
			resp, err = resty.R().
				SetBasicAuth(username, apiKeyResponse.APIKey).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 2)
		})

		Convey("API key retrieved with openID and with no expire", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// first login user - in OAuth2 flow, redirect policy automatically follows and gets cookies
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			cookies := resp.Cookies()

			// call endpoint without session - use a new client without cookies
			clientWithoutSession := resty.New()
			resp, err = clientWithoutSession.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			client.SetCookies(cookies)

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			user := mockoidc.DefaultUser()

			// get API key and email from apikey route response
			var apiKeyResponse apiKeyResponse
			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			email := user.Email
			So(email, ShouldNotBeEmpty)

			// get API key list
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var apiKeyListResponse apiKeyListResponse

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)
			So(apiKeyListResponse.APIKeys[0].CreatedAt, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatedAt)
			So(apiKeyListResponse.APIKeys[0].CreatorUA, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatorUA)
			So(apiKeyListResponse.APIKeys[0].Label, ShouldEqual, apiKeyResponse.APIKeyDetails.Label)
			So(apiKeyListResponse.APIKeys[0].Scopes, ShouldEqual, apiKeyResponse.APIKeyDetails.Scopes)
			So(apiKeyListResponse.APIKeys[0].UUID, ShouldEqual, apiKeyResponse.APIKeyDetails.UUID)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// trigger errors
			ctlr.MetaDB = mocks.MetaDBMock{
				GetUserAPIKeyInfoFn: func(hashedKey string) (string, error) {
					return "", ErrUnexpectedError
				},
			}

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			ctlr.MetaDB = mocks.MetaDBMock{
				GetUserAPIKeyInfoFn: func(hashedKey string) (string, error) {
					return user.Email, nil
				},
				GetUserGroupsFn: func(ctx context.Context) ([]string, error) {
					return []string{}, ErrUnexpectedError
				},
			}

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			ctlr.MetaDB = mocks.MetaDBMock{
				GetUserAPIKeyInfoFn: func(hashedKey string) (string, error) {
					return user.Email, nil
				},
				UpdateUserAPIKeyLastUsedFn: func(ctx context.Context, hashedKey string) error {
					return ErrUnexpectedError
				},
			}

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			client = resty.New()

			// call endpoint without session
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})

		Convey("API key retrieved with openID and with long expire", func() {
			payload := api.APIKeyPayload{
				Label:          "test",
				Scopes:         []string{"test"},
				ExpirationDate: time.Now().Add(time.Hour).Local().Format(constants.APIKeyTimeFormat),
			}

			reqBody, err := json.Marshal(payload)
			So(err, ShouldBeNil)

			client := resty.New()

			// mgmt should work both unauthenticated and authenticated
			resp, err := client.R().Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			// first login user
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			cookies := resp.Cookies()
			verifySessionCookiesSecureFlag(cookies, false) // No TLS configured

			client.SetCookies(cookies)

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			var apiKeyResponse apiKeyResponse
			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			// get API key list
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var apiKeyListResponse apiKeyListResponse

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)
			So(apiKeyListResponse.APIKeys[0].CreatedAt, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatedAt)
			So(apiKeyListResponse.APIKeys[0].CreatorUA, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatorUA)
			So(apiKeyListResponse.APIKeys[0].Label, ShouldEqual, apiKeyResponse.APIKeyDetails.Label)
			So(apiKeyListResponse.APIKeys[0].Scopes, ShouldEqual, apiKeyResponse.APIKeyDetails.Scopes)
			So(apiKeyListResponse.APIKeys[0].UUID, ShouldEqual, apiKeyResponse.APIKeyDetails.UUID)

			user := mockoidc.DefaultUser()
			email := user.Email
			So(email, ShouldNotBeEmpty)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// auth with API key
			// we need new client without session cookie set
			client = resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// get API key list
			resp, err = resty.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)

			// invalid api keys
			resp, err = client.R().
				SetBasicAuth("invalidEmail", apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			resp, err = client.R().
				SetBasicAuth(email, "noprefixAPIKey").
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			resp, err = client.R().
				SetBasicAuth(email, "zak_notworkingAPIKey").
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			userAc := reqCtx.NewUserAccessControl()
			userAc.SetUsername(email)
			ctx := userAc.DeriveContext(context.Background())

			err = ctlr.MetaDB.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			client = resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// without creds should work
			resp, err = client.R().Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// login again
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			cookies = resp.Cookies()
			verifySessionCookiesSecureFlag(cookies, false) // No TLS configured

			client.SetCookies(cookies)

			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			// should work with session
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// should work with api key
			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmt)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			// delete api key
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("id", apiKeyResponse.UUID).
				Delete(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// apiKey removed, should get 401
			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Delete(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// get API key list
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 0)

			resp, err = client.R().
				SetBasicAuth(username, password).
				SetQueryParam("id", apiKeyResponse.UUID).
				Delete(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// unsupported method
			resp, err = client.R().
				Put(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
		})

		Convey("API key retrieved with openID and with short expire", func() {
			expirationDate := time.Now().Add(1 * time.Second).Local().Round(time.Second)
			payload := api.APIKeyPayload{
				Label:          "test",
				Scopes:         []string{"test"},
				ExpirationDate: expirationDate.Format(constants.APIKeyTimeFormat),
			}

			reqBody, err := json.Marshal(payload)
			So(err, ShouldBeNil)

			client := resty.New()

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			client.SetCookies(resp.Cookies())

			// call endpoint with session (added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			var apiKeyResponse apiKeyResponse
			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			user := mockoidc.DefaultUser()
			email := user.Email
			So(email, ShouldNotBeEmpty)

			// get API key list
			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var apiKeyListResponse apiKeyListResponse

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)
			So(apiKeyListResponse.APIKeys[0].CreatedAt, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatedAt)
			So(apiKeyListResponse.APIKeys[0].CreatorUA, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatorUA)
			So(apiKeyListResponse.APIKeys[0].Label, ShouldEqual, apiKeyResponse.APIKeyDetails.Label)
			So(apiKeyListResponse.APIKeys[0].Scopes, ShouldEqual, apiKeyResponse.APIKeyDetails.Scopes)
			So(apiKeyListResponse.APIKeys[0].UUID, ShouldEqual, apiKeyResponse.APIKeyDetails.UUID)
			So(apiKeyListResponse.APIKeys[0].IsExpired, ShouldEqual, false)
			So(apiKeyListResponse.APIKeys[0].ExpirationDate.Equal(expirationDate), ShouldBeTrue)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// sleep past expire time
			time.Sleep(1500 * time.Millisecond)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// again for coverage
			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// get API key list with session authn
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 1)
			So(apiKeyListResponse.APIKeys[0].CreatedAt, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatedAt)
			So(apiKeyListResponse.APIKeys[0].CreatorUA, ShouldEqual, apiKeyResponse.APIKeyDetails.CreatorUA)
			So(apiKeyListResponse.APIKeys[0].Label, ShouldEqual, apiKeyResponse.APIKeyDetails.Label)
			So(apiKeyListResponse.APIKeys[0].Scopes, ShouldEqual, apiKeyResponse.APIKeyDetails.Scopes)
			So(apiKeyListResponse.APIKeys[0].UUID, ShouldEqual, apiKeyResponse.APIKeyDetails.UUID)
			So(apiKeyListResponse.APIKeys[0].IsExpired, ShouldEqual, true)
			So(apiKeyListResponse.APIKeys[0].ExpirationDate.Equal(expirationDate), ShouldBeTrue)

			// delete expired api key
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("id", apiKeyResponse.UUID).
				Delete(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// get API key list with session authn
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &apiKeyListResponse)
			So(err, ShouldBeNil)
			So(len(apiKeyListResponse.APIKeys), ShouldEqual, 0)
		})

		Convey("Create API key with expirationDate before actual date", func() {
			expirationDate := time.Now().Add(-5 * time.Second).Local().Round(time.Second)
			payload := api.APIKeyPayload{
				Label:          "test",
				Scopes:         []string{"test"},
				ExpirationDate: expirationDate.Format(constants.APIKeyTimeFormat),
			}

			reqBody, err := json.Marshal(payload)
			So(err, ShouldBeNil)

			client := resty.New()

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			cookies := resp.Cookies()
			verifySessionCookiesSecureFlag(cookies, false) // No TLS configured

			client.SetCookies(cookies)

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("Create API key with unparsable expirationDate", func() {
			expirationDate := time.Now().Add(-5 * time.Second).Local().Round(time.Second)
			payload := api.APIKeyPayload{
				Label:          "test",
				Scopes:         []string{"test"},
				ExpirationDate: expirationDate.Format(time.RFC1123Z),
			}

			reqBody, err := json.Marshal(payload)
			So(err, ShouldBeNil)

			client := resty.New()

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			cookies := resp.Cookies()
			verifySessionCookiesSecureFlag(cookies, false) // No TLS configured

			client.SetCookies(cookies)

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.APIKeyPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("Test error handling when API Key handler reads the request body", func() {
			request, _ := http.NewRequestWithContext(context.TODO(),
				http.MethodPost, "baseURL", errReader(0))
			response := httptest.NewRecorder()

			rthdlr := api.NewRouteHandler(ctlr)
			rthdlr.CreateAPIKey(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestMultipleAuthorizationHeaders(t *testing.T) {
	Convey("Test rejection of multiple Authorization headers", t, func() {
		Convey("Test multiple and single Authorization headers in basic auth handler", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			username, _ := test.GenerateRandomString()
			password, _ := test.GenerateRandomString()

			htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			Convey("Multiple Authorization headers should be rejected - basic first", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple Authorization headers
				basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
				req.Header.Add("Authorization", "Basic "+basicAuth)
				req.Header.Add("Authorization", "Bearer token123")

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Multiple Authorization headers should be rejected - bearer first", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple Authorization headers
				req.Header.Add("Authorization", "Bearer token123")
				basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
				req.Header.Add("Authorization", "Basic "+basicAuth)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Multiple Authorization headers should be rejected - basic twice", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple Authorization headers with correct values
				basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
				req.Header.Add("Authorization", "Basic "+basicAuth)
				req.Header.Add("Authorization", "Basic "+basicAuth)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Single Authorization header should work", func() {
				// Create a request with single Authorization header
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add single Authorization header
				basicAuth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
				req.Header.Add("Authorization", "Basic "+basicAuth)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should succeed
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			})
		})

		Convey("Test multiple Authorization headers in bearer auth handler", func() {
			tempDir := t.TempDir()

			// Generate CA certificate
			caCert, caKey, err := tlsutils.GenerateCACert()
			So(err, ShouldBeNil)

			// Generate server certificate for bearer auth
			serverCertPath := path.Join(tempDir, "server.cert")
			serverKeyPath := path.Join(tempDir, "server.key")
			opts := &tlsutils.CertificateOptions{
				Hostname: "localhost",
			}
			err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
			So(err, ShouldBeNil)

			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Cert:    serverCertPath,
					Realm:   "test-realm",
					Service: "test-service",
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Load the private key to sign the token
			keyBytes, err := os.ReadFile(serverKeyPath)
			So(err, ShouldBeNil)

			keyBlock, _ := pem.Decode(keyBytes)
			So(keyBlock, ShouldNotBeNil)

			privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			So(err, ShouldBeNil)

			// Create a valid JWT token with proper claims
			// For /v2/_catalog, the requestedAccess will have Name="" (no repository name in URL)
			// So we need to provide access to repository with empty name or use wildcard
			claims := &api.ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Access: []api.ResourceAccess{
					{
						Type:    "repository",
						Name:    "", // Empty name matches /v2/_catalog
						Actions: []string{"pull"},
					},
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			validTokenString, err := token.SignedString(privateKey)
			So(err, ShouldBeNil)

			Convey("Multiple Authorization headers should be rejected - bearer and basic - bearer first", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple Authorization headers
				req.Header.Add("Authorization", "Bearer "+validTokenString)
				req.Header.Add("Authorization", "Basic dXNlcjpwYXNz")

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Multiple Authorization headers should be rejected - bearer and basic - basic first", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple Authorization headers
				req.Header.Add("Authorization", "Basic dXNlcjpwYXNz")
				req.Header.Add("Authorization", "Bearer "+validTokenString)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Multiple Authorization headers should be rejected - two bearer headers", func() {
				// Create a request with multiple Authorization headers
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add multiple bearer Authorization headers
				req.Header.Add("Authorization", "Bearer "+validTokenString)
				req.Header.Add("Authorization", "Bearer "+validTokenString)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should be rejected with 401 Unauthorized
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Single Authorization header should work - invalid token", func() {
				// Create a request with single Authorization header
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add single bearer Authorization header with invalid token
				req.Header.Add("Authorization", "Bearer token123")

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// The token is invalid, so we expect 401, but not due to multiple headers
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})

			Convey("Single Authorization header should work - correct bearer token", func() {
				// Create a request with single Authorization header
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
				So(err, ShouldBeNil)

				// Add single bearer Authorization header with valid token
				req.Header.Add("Authorization", "Bearer "+validTokenString)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				// Should succeed with valid token
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			})
		})
	})
}

func TestBearerOIDCWorkloadIdentity(t *testing.T) {
	Convey("Test bearer auth with OIDC workload identity", t, func() {
		// Generate test keys for mock OIDC server
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)
		pubKey := &privKey.PublicKey

		// Start mock OIDC server
		server := mockWorkloadOIDCServer(t, pubKey)
		defer server.Close()

		issuer := server.URL
		audience := "test-zot"

		Convey("OIDC authentication success", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Create a valid OIDC token
			token, err := createWorkloadOIDCToken(privKey, issuer, audience, nil)
			So(err, ShouldBeNil)

			// Test successful authentication
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("OIDC token exchange returns the password token", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   baseURL + constants.TokenPath,
					Service: "test-zot",
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			token, err := createWorkloadOIDCToken(privKey, issuer, audience, nil)
			So(err, ShouldBeNil)

			challengeResp, err := resty.R().Get(baseURL + "/v2/testrepo/tags/list")
			So(err, ShouldBeNil)
			So(challengeResp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			challenge := authutils.ParseBearerAuthHeader(challengeResp.Header().Get("WWW-Authenticate"))
			So(challenge.Realm, ShouldEqual, baseURL+constants.TokenPath)
			So(challenge.Service, ShouldEqual, "test-zot")
			So(challenge.Scope, ShouldEqual, "repository:testrepo:pull")

			optionsResp, err := resty.R().Options(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(optionsResp.StatusCode(), ShouldEqual, http.StatusNoContent)

			missingBasicResp, err := resty.R().Get(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(missingBasicResp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			So(missingBasicResp.Header().Get("WWW-Authenticate"), ShouldEqual,
				`Basic realm="`+baseURL+constants.TokenPath+`"`)
			So(missingBasicResp.Header().Get("Cache-Control"), ShouldEqual, "no-store")
			So(missingBasicResp.Header().Get("Pragma"), ShouldEqual, "no-cache")

			exchangeResp, err := resty.R().
				SetBasicAuth("<token>", token).
				SetQueryParam("service", challenge.Service).
				SetQueryParam("scope", challenge.Scope).
				Get(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(exchangeResp.StatusCode(), ShouldEqual, http.StatusOK)
			So(exchangeResp.Header().Get("Cache-Control"), ShouldEqual, "no-store")
			So(exchangeResp.Header().Get("Pragma"), ShouldEqual, "no-cache")

			tokenResp := struct {
				Token       string `json:"token"`
				AccessToken string `json:"access_token"` //nolint:tagliatelle
				ExpiresIn   int64  `json:"expires_in"`   //nolint:tagliatelle
				IssuedAt    string `json:"issued_at"`    //nolint:tagliatelle
			}{}
			err = json.Unmarshal(exchangeResp.Body(), &tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.Token, ShouldEqual, token)
			So(tokenResp.AccessToken, ShouldEqual, token)
			So(tokenResp.ExpiresIn, ShouldBeGreaterThan, 0)
			So(tokenResp.IssuedAt, ShouldNotBeEmpty)

			postExchangeResp, err := resty.R().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				SetBody("grant_type=password&username=%3Ctoken%3E&password=" + url.QueryEscape(token)).
				Post(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(postExchangeResp.StatusCode(), ShouldEqual, http.StatusOK)

			postTokenResp := struct {
				Token       string `json:"token"`
				AccessToken string `json:"access_token"` //nolint:tagliatelle
			}{}
			err = json.Unmarshal(postExchangeResp.Body(), &postTokenResp)
			So(err, ShouldBeNil)
			So(postTokenResp.Token, ShouldEqual, token)
			So(postTokenResp.AccessToken, ShouldEqual, token)

			for _, credentialField := range []string{"id_token", "access_token", "refresh_token", "token"} {
				postExchangeResp, err := resty.R().
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					SetBody("grant_type=password&" + credentialField + "=" + url.QueryEscape(token)).
					Post(baseURL + constants.TokenPath)
				So(err, ShouldBeNil)
				So(postExchangeResp.StatusCode(), ShouldEqual, http.StatusOK)
			}

			registryResp, err := resty.R().
				SetHeader("Authorization", "Bearer "+tokenResp.Token).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(registryResp.StatusCode(), ShouldEqual, http.StatusOK)

			invalidResp, err := resty.R().
				SetBasicAuth("<token>", "invalid-token").
				Get(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(invalidResp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			So(invalidResp.Header().Get("Cache-Control"), ShouldEqual, "no-store")
			So(invalidResp.Header().Get("Pragma"), ShouldEqual, "no-cache")
		})

		Convey("OIDC token exchange refuses to proxy locally owned bearer OIDC tokens that fail authentication", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			proxyHit := false
			proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				proxyHit = true
				response.WriteHeader(http.StatusOK)
			}))
			defer proxyServer.Close()

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   baseURL + constants.TokenPath,
					Service: "zot-service",
					UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
						Realm:             proxyServer.URL + "/token",
						Service:           "upstream-service",
						AllowInsecureHTTP: true,
					},
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
			So(err, ShouldBeNil)

			ownedInvalidToken, err := createWorkloadOIDCToken(wrongKey, issuer, audience, nil)
			So(err, ShouldBeNil)

			resp, err := resty.R().
				SetBasicAuth("<token>", ownedInvalidToken).
				Get(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			So(proxyHit, ShouldBeFalse)
		})

		Convey("OIDC token exchange refuses to proxy browser OpenID-owned tokens", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			humanClientID := "human-client"

			proxyHit := false
			proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				proxyHit = true
				response.WriteHeader(http.StatusOK)
			}))
			defer proxyServer.Close()

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   baseURL + constants.TokenPath,
					Service: "zot-service",
					UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
						Realm:             proxyServer.URL + "/token",
						Service:           "upstream-service",
						AllowInsecureHTTP: true,
					},
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClientID: humanClientID,
							Issuer:   issuer,
							Scopes:   []string{"openid", "email"},
						},
					},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			humanToken, err := createWorkloadOIDCToken(privKey, issuer, humanClientID, nil)
			So(err, ShouldBeNil)

			resp, err := resty.R().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				SetBody("grant_type=password&id_token=" + url.QueryEscape(humanToken)).
				Post(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			So(proxyHit, ShouldBeFalse)
		})

		Convey("OIDC token exchange proxies GET requests when no local backend owns the credential", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			var gotMethod, gotUsername, gotPassword, gotService, gotScope, gotClientID, gotFrom string
			proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				gotMethod = request.Method
				gotUsername, gotPassword, _ = request.BasicAuth()
				gotService = request.URL.Query().Get("service")
				gotScope = request.URL.Query().Get("scope")
				gotClientID = request.URL.Query().Get("client_id")
				gotFrom = request.URL.Query().Get("from")

				response.Header().Set("Content-Type", "application/json")
				response.Header().Set("X-Token-Proxy", "hit")
				response.WriteHeader(http.StatusAccepted)
				_, _ = response.Write([]byte(`{"token":"proxied-token"}`))
			}))
			defer proxyServer.Close()

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   baseURL + constants.TokenPath,
					Service: "zot-service",
					UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
						Realm:             proxyServer.URL + "/token?from=proxy",
						Service:           "upstream-service",
						AllowInsecureHTTP: true,
					},
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			proxyResp, err := resty.R().
				SetBasicAuth("user", "not-an-oidc-token").
				SetQueryParam("service", "zot-service").
				SetQueryParam("scope", "repository:testrepo:pull").
				SetQueryParam("client_id", "test-client").
				Get(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(proxyResp.StatusCode(), ShouldEqual, http.StatusAccepted)
			So(proxyResp.Header().Get("X-Token-Proxy"), ShouldEqual, "hit")
			So(string(proxyResp.Body()), ShouldEqual, `{"token":"proxied-token"}`)

			So(gotMethod, ShouldEqual, http.MethodGet)
			So(gotUsername, ShouldEqual, "user")
			So(gotPassword, ShouldEqual, "not-an-oidc-token")
			So(gotService, ShouldEqual, "upstream-service")
			So(gotScope, ShouldEqual, "repository:testrepo:pull")
			So(gotClientID, ShouldEqual, "test-client")
			So(gotFrom, ShouldEqual, "proxy")
		})

		Convey("OIDC token exchange proxies POST form requests when no local backend owns the credential", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			var gotMethod, gotService, gotScope, gotGrantType, gotUsername, gotPassword string
			proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				gotMethod = request.Method
				if err := request.ParseForm(); err != nil {
					t.Errorf("failed to parse upstream token request form: %v", err)
				}
				gotService = request.PostForm.Get("service")
				gotScope = request.PostForm.Get("scope")
				gotGrantType = request.PostForm.Get("grant_type")
				gotUsername = request.PostForm.Get("username")
				gotPassword = request.PostForm.Get("password")

				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"access_token":"proxied-access-token"}`))
			}))
			defer proxyServer.Close()

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   baseURL + constants.TokenPath,
					Service: "zot-service",
					UpstreamTokenEndpoint: &config.UpstreamTokenEndpointConfig{
						Realm:             proxyServer.URL + "/token",
						Service:           "upstream-service",
						AllowInsecureHTTP: true,
					},
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			proxyResp, err := resty.R().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				SetBody("grant_type=password&username=user&password=not-an-oidc-token" +
					"&service=zot-service&scope=repository:testrepo:pull").
				Post(baseURL + constants.TokenPath)
			So(err, ShouldBeNil)
			So(proxyResp.StatusCode(), ShouldEqual, http.StatusOK)
			So(string(proxyResp.Body()), ShouldEqual, `{"access_token":"proxied-access-token"}`)

			So(gotMethod, ShouldEqual, http.MethodPost)
			So(gotService, ShouldEqual, "upstream-service")
			So(gotScope, ShouldEqual, "repository:testrepo:pull")
			So(gotGrantType, ShouldEqual, "password")
			So(gotUsername, ShouldEqual, "user")
			So(gotPassword, ShouldEqual, "not-an-oidc-token")
		})

		Convey("OIDC authentication success with groups", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
						ClaimMapping: &config.CELClaimValidationAndMapping{
							Groups: "claims.groups",
						},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Create a valid OIDC token with groups
			token, err := createWorkloadOIDCToken(privKey, issuer, audience, map[string]any{
				"groups": []string{"admin", "developers"},
			})
			So(err, ShouldBeNil)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("OIDC authentication fails with MetaDB error", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartServer()
			defer cm.StopServer()
			test.WaitTillServerReady(baseURL)

			// Replace MetaDB with a mock that returns an error
			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return ErrUnexpectedError
				},
			}

			// Create a valid OIDC token
			token, err := createWorkloadOIDCToken(privKey, issuer, audience, nil)
			So(err, ShouldBeNil)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			// Should fail with internal server error due to MetaDB failure
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("OIDC authentication fails, falls back to traditional bearer auth", func() {
			tempDir := t.TempDir()

			// Generate certificate for traditional bearer auth
			caCert, caKey, err := tlsutils.GenerateCACert()
			So(err, ShouldBeNil)

			serverCertPath := path.Join(tempDir, "server.cert")
			serverKeyPath := path.Join(tempDir, "server.key")
			opts := &tlsutils.CertificateOptions{
				Hostname: "localhost",
			}
			err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
			So(err, ShouldBeNil)

			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Cert:    serverCertPath,
					Realm:   "test-realm",
					Service: "test-service",
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Load the private key to sign traditional bearer token
			keyBytes, err := os.ReadFile(serverKeyPath)
			So(err, ShouldBeNil)

			keyBlock, _ := pem.Decode(keyBytes)
			So(keyBlock, ShouldNotBeNil)

			privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			So(err, ShouldBeNil)

			// Create a traditional bearer token (not OIDC)
			claims := &api.ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Access: []api.ResourceAccess{
					{
						Type:    "repository",
						Name:    "",
						Actions: []string{"pull"},
					},
				},
			}

			traditionalToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			traditionalTokenString, err := traditionalToken.SignedString(privateKey)
			So(err, ShouldBeNil)

			// Request with traditional bearer token should succeed via fallback
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+traditionalTokenString)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("OIDC authentication with invalid token", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Test with invalid token
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer invalid-token")

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		})

		Convey("OIDC authentication with no token provided", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Test without any authorization header
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		})

		Convey("OIDC authentication with wrong audience", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Create a token with wrong audience
			token, err := createWorkloadOIDCToken(privKey, issuer, "wrong-audience", nil)
			So(err, ShouldBeNil)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+token)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		})

		Convey("OIDC fails, traditional bearer auth with insufficient scope returns challenge", func() {
			tempDir := t.TempDir()

			// Generate certificate for traditional bearer auth
			caCert, caKey, err := tlsutils.GenerateCACert()
			So(err, ShouldBeNil)

			serverCertPath := path.Join(tempDir, "server.cert")
			serverKeyPath := path.Join(tempDir, "server.key")
			opts := &tlsutils.CertificateOptions{
				Hostname: "localhost",
			}
			err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
			So(err, ShouldBeNil)

			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Cert:    serverCertPath,
					Realm:   "test-realm",
					Service: "test-service",
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Load the private key to sign traditional bearer token
			keyBytes, err := os.ReadFile(serverKeyPath)
			So(err, ShouldBeNil)

			keyBlock, _ := pem.Decode(keyBytes)
			So(keyBlock, ShouldNotBeNil)

			privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			So(err, ShouldBeNil)

			// Create a traditional bearer token with access to different repository (insufficient scope)
			claims := &api.ClaimsWithAccess{
				RegisteredClaims: jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
				Access: []api.ResourceAccess{
					{
						Type:    "repository",
						Name:    "other-repo", // Different repo than what we're accessing
						Actions: []string{"pull"},
					},
				},
			}

			traditionalToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			traditionalTokenString, err := traditionalToken.SignedString(privateKey)
			So(err, ShouldBeNil)

			// Request access to a different repository than what the token allows
			// This should fail with AuthChallengeError (insufficient scope)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/v2/testrepo/tags/list", nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+traditionalTokenString)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			// Should get 401 Unauthorized with WWW-Authenticate challenge header
			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			So(resp.Header.Get("WWW-Authenticate"), ShouldNotBeEmpty)
		})

		Convey("OIDC authentication with OPTIONS method", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Test OPTIONS method - should be allowed without authentication
			req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, baseURL+"/v2/_catalog", nil)
			So(err, ShouldBeNil)

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			// OPTIONS requests should be allowed without authentication
			So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
		})

		Convey("OIDC authentication with push action", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    issuer,
						Audiences: []string{audience},
					}},
				},
			}
			conf.Storage.RootDirectory = t.TempDir()

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(port)
			defer cm.StopServer()

			// Create a valid OIDC token
			token, err := createWorkloadOIDCToken(privKey, issuer, audience, nil)
			So(err, ShouldBeNil)

			// Test POST method which triggers push action
			uploadURL := baseURL + "/v2/testrepo/blobs/uploads/"
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, uploadURL, nil)
			So(err, ShouldBeNil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/octet-stream")

			client := &http.Client{}
			resp, err := client.Do(req)
			So(err, ShouldBeNil)
			defer resp.Body.Close()

			// Should be able to authenticate, but may fail with 403 due to no write access configured
			// The key is that authentication succeeded (not 401)
			So(resp.StatusCode, ShouldNotEqual, http.StatusUnauthorized)
		})
	})
}

func TestTraditionalBearerMethodActionMapping(t *testing.T) {
	Convey("Traditional bearer maps HTTP methods to expected scope actions", t, func() {
		tempDir := t.TempDir()

		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.cert")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{Hostname: "localhost"}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    serverCertPath,
				Realm:   "test-realm",
				Service: "test-service",
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		keyBytes, err := os.ReadFile(serverKeyPath)
		So(err, ShouldBeNil)

		keyBlock, _ := pem.Decode(keyBytes)
		So(keyBlock, ShouldNotBeNil)

		privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		So(err, ShouldBeNil)

		// Keep the token valid but scoped to another repository so requests fail with
		// insufficient scope and expose the requested action in WWW-Authenticate.
		claims := &api.ClaimsWithAccess{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Access: []api.ResourceAccess{
				{
					Type:    "repository",
					Name:    "other-repo",
					Actions: []string{"pull", "push", "delete"},
				},
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString(privateKey)
		So(err, ShouldBeNil)

		testCases := []struct {
			name          string
			method        string
			path          string
			expectedScope string
		}{
			{
				name:          "GET maps to pull",
				method:        http.MethodGet,
				path:          "/v2/testrepo/tags/list",
				expectedScope: "repository:testrepo:pull",
			},
			{
				name:          "POST maps to push",
				method:        http.MethodPost,
				path:          "/v2/testrepo/blobs/uploads/",
				expectedScope: "repository:testrepo:push",
			},
			{
				name:          "PATCH maps to push",
				method:        http.MethodPatch,
				path:          "/v2/testrepo/blobs/uploads/upload-uuid",
				expectedScope: "repository:testrepo:push",
			},
			{
				name:          "PUT maps to push",
				method:        http.MethodPut,
				path:          "/v2/testrepo/manifests/latest",
				expectedScope: "repository:testrepo:push",
			},
			{
				name:          "DELETE maps to delete",
				method:        http.MethodDelete,
				path:          "/v2/testrepo/manifests/latest",
				expectedScope: "repository:testrepo:delete",
			},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				req, err := http.NewRequestWithContext(context.Background(), testCase.method, baseURL+testCase.path, nil)
				So(err, ShouldBeNil)
				req.Header.Set("Authorization", "Bearer "+tokenString)

				client := &http.Client{}
				resp, err := client.Do(req)
				So(err, ShouldBeNil)
				defer resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
				So(resp.Header.Get("WWW-Authenticate"), ShouldContainSubstring, "scope=\""+testCase.expectedScope+"\"")
			})
		}
	})
}

// mockWorkloadOIDCServer creates a mock OIDC provider server for workload identity testing.
func mockWorkloadOIDCServer(t *testing.T, pubKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// OpenID configuration endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		oidcConfig := map[string]any{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		}

		_ = json.NewEncoder(w).Encode(oidcConfig)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Calculate modulus and exponent for JWK
		nBytes := pubKey.N.Bytes()
		eBytes := make([]byte, 4)
		eBytes[0] = byte(pubKey.E >> 24) //nolint: gosec
		eBytes[1] = byte(pubKey.E >> 16) //nolint: gosec
		eBytes[2] = byte(pubKey.E >> 8)  //nolint: gosec
		eBytes[3] = byte(pubKey.E)       //nolint: gosec

		// Trim leading zeros from exponent
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}

		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": testKeyID,
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(nBytes),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		}

		_ = json.NewEncoder(w).Encode(jwks)
	})

	return httptest.NewServer(mux)
}

// createWorkloadOIDCToken creates a test OIDC ID token for workload identity testing.
func createWorkloadOIDCToken(privKey *rsa.PrivateKey, issuer, audience string,
	extraClaims map[string]any,
) (string, error) {
	now := time.Now()

	tokenClaims := jwt.MapClaims{
		"iss": issuer,
		"aud": []string{audience},
		"sub": testSubject,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	// Add extra claims
	maps.Copy(tokenClaims, extraClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = testKeyID

	return token.SignedString(privKey)
}

func TestAPIKeysOpenDBError(t *testing.T) {
	Convey("Test API keys - unable to create database", t, func() {
		conf := config.New()
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		mockOIDCServer, err := authutils.MockOIDCRun()
		if err != nil {
			panic(err)
		}

		defer func() {
			err := mockOIDCServer.Shutdown()
			if err != nil {
				panic(err)
			}
		}()

		mockOIDCConfig := mockOIDCServer.Config()
		defaultVal := true

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},

			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},

			APIKey: defaultVal,
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		dir := t.TempDir()

		err = os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		ctlr.Config.Storage.RootDirectory = dir
		cm := test.NewControllerManager(ctlr)

		So(func() {
			cm.StartServer()
		}, ShouldPanic)
	})
}

func TestAPIKeysGeneratorErrors(t *testing.T) {
	Convey("Test API keys - unable to generate API keys and API Key IDs", t, func() {
		log := log.NewTestLogger()

		apiKey, apiKeyID, err := api.GenerateAPIKey(guuid.DefaultGenerator, log)
		So(err, ShouldBeNil)
		So(apiKey, ShouldNotEqual, "")
		So(apiKeyID, ShouldNotEqual, "")

		generator := &mockUUIDGenerator{
			guuid.DefaultGenerator, 0, 0,
		}

		apiKey, apiKeyID, err = api.GenerateAPIKey(generator, log)
		So(err, ShouldNotBeNil)
		So(apiKey, ShouldEqual, "")
		So(apiKeyID, ShouldEqual, "")

		generator = &mockUUIDGenerator{
			guuid.DefaultGenerator, 1, 0,
		}

		apiKey, apiKeyID, err = api.GenerateAPIKey(generator, log)
		So(err, ShouldNotBeNil)
		So(apiKey, ShouldEqual, "")
		So(apiKeyID, ShouldEqual, "")
	})
}

func TestCookiestoreCleanup(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(true, log)

	defer metrics.Stop() // Clean up metrics server to prevent resource leaks

	authCfgTestCases := []struct {
		name string
		cfg  config.AuthConfig
	}{
		{
			"empty Auth config",
			config.AuthConfig{},
		},
		{
			"local session driver",
			config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "local",
				},
			},
		},
	}

	for _, testCase := range authCfgTestCases {
		Convey("Test cookiestore cleanup works with "+testCase.name, t, func() {
			taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
			taskScheduler.RateLimit = 50 * time.Millisecond
			taskScheduler.RunScheduler()

			rootDir := t.TempDir()

			err := os.MkdirAll(path.Join(rootDir, "_sessions"), storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)

			sessionPath := path.Join(rootDir, "_sessions", "session_1234")

			err = os.WriteFile(sessionPath, []byte("session"), storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			changeTime := time.Now().Add(-4 * time.Hour)

			err = os.Chtimes(sessionPath, changeTime, changeTime)
			So(err, ShouldBeNil)

			imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

			storeController := storage.StoreController{
				DefaultStore: imgStore,
			}

			cookieStore, err := api.NewCookieStore(&testCase.cfg, storeController, log)
			So(err, ShouldBeNil)

			cookieStore.RunSessionCleaner(taskScheduler)

			time.Sleep(2 * time.Second)

			taskScheduler.Shutdown()

			// make sure session is removed
			_, err = os.Stat(sessionPath)
			So(err, ShouldNotBeNil)
		})
	}

	Convey("Test cookiestore cleanup without permissions on rootDir", t, func() {
		taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
		taskScheduler.RateLimit = 50 * time.Millisecond
		taskScheduler.RunScheduler()

		rootDir := t.TempDir()

		err := os.MkdirAll(path.Join(rootDir, "_sessions"), storageConstants.DefaultDirPerms)
		So(err, ShouldBeNil)

		sessionPath := path.Join(rootDir, "_sessions", "session_1234")

		err = os.WriteFile(sessionPath, []byte("session"), storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imgStore,
		}

		authCfg := config.AuthConfig{
			SessionHashKey: []byte("secret"),
		}

		cookieStore, err := api.NewCookieStore(&authCfg, storeController, log)
		So(err, ShouldBeNil)

		err = os.Chmod(rootDir, 0o000)
		So(err, ShouldBeNil)

		defer func() {
			err = os.Chmod(rootDir, storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)
		}()

		cookieStore.RunSessionCleaner(taskScheduler)

		time.Sleep(1 * time.Second)

		taskScheduler.Shutdown()
	})

	Convey("Test session expiration checks", t, func() {
		rootDir := t.TempDir()

		err := os.MkdirAll(path.Join(rootDir, "_sessions"), storageConstants.DefaultDirPerms)
		So(err, ShouldBeNil)

		sessionPath := path.Join(rootDir, "_sessions", "session_1234")

		err = os.WriteFile(sessionPath, []byte("session"), storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		Convey("New session file should not be expired", func() {
			fileInfo, err := os.Stat(sessionPath)
			So(err, ShouldBeNil)

			dirEntry := fs.FileInfoToDirEntry(fileInfo)
			So(api.IsExpiredSession(dirEntry), ShouldBeFalse)
		})

		Convey("Deleted session file should not flagged as expired", func() {
			fileInfo, err := os.Stat(sessionPath)
			So(err, ShouldBeNil)

			err = os.Remove(sessionPath)
			So(err, ShouldBeNil)

			dirEntry := fs.FileInfoToDirEntry(fileInfo)
			So(api.IsExpiredSession(dirEntry), ShouldBeFalse)
		})

		// Fix flaky coverage in integration tests
		Convey("Error on dirEntry.Info()", func() {
			fileInfo, err := os.Stat(sessionPath)
			So(err, ShouldBeNil)

			dirEntry := badDirInfo{fileInfo: fileInfo}

			So(api.IsExpiredSession(dirEntry), ShouldBeFalse)
		})

		Convey("File with invalid name should not be expired", func() {
			newSessionPath := path.Join(rootDir, "_sessions", "1234")
			err := os.Rename(sessionPath, newSessionPath)
			So(err, ShouldBeNil)

			changeTime := time.Now().Add(-4 * time.Hour)

			err = os.Chtimes(newSessionPath, changeTime, changeTime)
			So(err, ShouldBeNil)

			fileInfo, err := os.Stat(newSessionPath)
			So(err, ShouldBeNil)

			dirEntry := fs.FileInfoToDirEntry(fileInfo)
			So(api.IsExpiredSession(dirEntry), ShouldBeFalse)
		})

		Convey("Old session file should be expired", func() {
			changeTime := time.Now().Add(-4 * time.Hour)

			err = os.Chtimes(sessionPath, changeTime, changeTime)
			So(err, ShouldBeNil)

			fileInfo, err := os.Stat(sessionPath)
			So(err, ShouldBeNil)

			dirEntry := fs.FileInfoToDirEntry(fileInfo)
			So(api.IsExpiredSession(dirEntry), ShouldBeTrue)
		})
	})
}

func TestCookieSecureFlag(t *testing.T) {
	Convey("Test cookie Secure flag based on configuration", t, func() {
		// Generate certificates dynamically for the test
		tempDir := t.TempDir()
		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)

		caCertPath := path.Join(tempDir, "ca.crt")
		err = os.WriteFile(caCertPath, caCert, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "127.0.0.1",
		}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		mockOIDCServer, err := authutils.MockOIDCRun()
		So(err, ShouldBeNil)

		defer func() {
			err := mockOIDCServer.Shutdown()
			So(err, ShouldBeNil)
		}()

		mockOIDCConfig := mockOIDCServer.Config()

		username, _ := test.GenerateRandomString()
		password, _ := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		defaultVal := true

		Convey("Test with TLS configured - cookies should be Secure=true", func() {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetSecureBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.TLS = &config.TLSConfig{
				Cert: serverCertPath,
				Key:  serverKeyPath,
			}
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"openid", "email", "groups"},
						},
					},
				},
				APIKey: defaultVal,
			}

			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)
			cm.StartServer()

			defer cm.StopServer()

			// Load CA certificate for proper TLS verification
			caCert, err := os.ReadFile(caCertPath)
			So(err, ShouldBeNil)

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

			for {
				if _, err := client.R().Get(baseURL); err == nil {
					break
				}

				// wait for server to be ready
				time.Sleep(test.SleepTime)
			}

			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			cookies := resp.Cookies()
			So(len(cookies), ShouldBeGreaterThan, 0)

			// Verify cookies have Secure=true when TLS is configured
			verifySessionCookiesSecureFlag(cookies, true)
		})

		Convey("Test with SecureSession=true configured - cookies should be Secure=true", func() {
			secureTrue := true
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port
			conf.HTTP.TLS = nil // No TLS
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"openid", "email", "groups"},
						},
					},
				},
				APIKey:        defaultVal,
				SecureSession: &secureTrue,
			}

			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			cm := test.NewControllerManager(ctlr)

			cm.StartServer()

			defer cm.StopServer()
			test.WaitTillServerReady(baseURL)

			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			cookies := resp.Cookies()
			So(len(cookies), ShouldBeGreaterThan, 0)

			// Verify cookies have Secure=true when SecureSession is set to true
			verifySessionCookiesSecureFlag(cookies, true)
		})
	})
}

func TestRedisCookieStore(t *testing.T) {
	log := log.NewTestLogger()

	testRedis := miniredis.RunT(t)

	storeController := storage.StoreController{
		DefaultStore: &mocks.MockedImageStore{
			GetImageManifestFn: func(repo string, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", zerr.ErrRepoBadVersion
			},
		},
	}

	testCases := []struct {
		testName       string
		shouldErrBeNil bool
		expectedErrStr string
		inputCfg       *config.AuthConfig
	}{
		{
			"Cookie store creation should not fail if the driver is local",
			true,
			"",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "local",
				},
			},
		},
		{
			"Cookie store creation should fail if the driver is unsupported",
			false,
			"invalid server config: sessiondriver unknowndriver not supported",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "unknowndriver",
				},
			},
		},
		{
			"Cookie store creation should not fail if the keyPrefix for Redis is not a string",
			true,
			"",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name":      "redis",
					"keyprefix": 8,
					"url":       "redis://" + testRedis.Addr(),
				},
			},
		},
		{
			"Cookie store creation should not fail if the SessionDriver Config is nil",
			true,
			"",
			&config.AuthConfig{},
		},
		{
			"Cookie store creation and use should succeed with valid configuration",
			true,
			"",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "redis",
					"url":  "redis://" + testRedis.Addr(),
				},
			},
		},
		{
			"Cookie store creation should fail if the url for Redis is incorrect",
			false,
			"dial tcp: lookup unknown on 127.0.0.53:53: server misbehaving",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "redis",
					"url":  "redis://unknown:1000",
				},
			},
		},
		{
			"Cookie store creation should fail if the url for Redis has an invalid value",
			false,
			"invalid server config: cachedriver map[name:redis url:%!s(int=100)] has invalid value for url",
			&config.AuthConfig{
				SessionDriver: map[string]any{
					"name": "redis",
					"url":  100,
				},
			},
		},
	}

	for _, testCase := range testCases {
		Convey(testCase.testName, t, func() {
			cookieStore, err := api.NewCookieStore(testCase.inputCfg, storeController, log)
			if testCase.shouldErrBeNil {
				So(err, ShouldBeNil)
				So(cookieStore, ShouldNotBeNil)
			} else {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, testCase.expectedErrStr)
				So(cookieStore, ShouldBeNil)
			}
		})
	}
}

type mockUUIDGenerator struct {
	guuid.Generator

	succeedAttempts int
	attemptCount    int
}

func (gen *mockUUIDGenerator) NewV4() (
	guuid.UUID, error,
) {
	defer func() {
		gen.attemptCount += 1
	}()

	if gen.attemptCount >= gen.succeedAttempts {
		return guuid.UUID{}, ErrUnexpectedError
	}

	return guuid.DefaultGenerator.NewV4()
}

type errReader int

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("test error") //nolint:err113
}

type badDirInfo struct {
	fileInfo fs.FileInfo
}

func (di badDirInfo) IsDir() bool {
	return di.fileInfo.IsDir()
}

func (di badDirInfo) Type() fs.FileMode {
	return di.fileInfo.Mode().Type()
}

func (di badDirInfo) Info() (fs.FileInfo, error) {
	return di.fileInfo, ErrUnexpectedError
}

func (di badDirInfo) Name() string {
	return di.fileInfo.Name()
}

func (di badDirInfo) String() string {
	return fs.FormatDirEntry(di)
}

func verifySessionCookiesSecureFlag(cookies []*http.Cookie, expectedSecure bool) {
	var sessionCookie, userCookie *http.Cookie

	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		} else if cookie.Name == userCookieName {
			userCookie = cookie
		}
	}

	// Verify both cookies exist and have correct Secure flag
	So(sessionCookie, ShouldNotBeNil)
	So(userCookie, ShouldNotBeNil)
	So(sessionCookie.Secure, ShouldEqual, expectedSecure)
	So(userCookie.Secure, ShouldEqual, expectedSecure)
}
