//go:build mgmt

package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
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
