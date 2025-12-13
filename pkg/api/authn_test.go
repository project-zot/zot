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

var ErrUnexpectedError = errors.New("error: unexpected error")

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

func TestMTLSAuthentication(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	// Generate CA certificate
	caCert, caKey, err := tlsutils.GenerateCACert()
	if err != nil {
		panic(err)
	}
	caCertPath := path.Join(tempDir, "ca.crt")
	err = os.WriteFile(caCertPath, caCert, 0o600)
	if err != nil {
		panic(err)
	}

	// Generate server certificate
	serverCertPath := path.Join(tempDir, "server.crt")
	serverKeyPath := path.Join(tempDir, "server.key")
	opts := &tlsutils.CertificateOptions{
		Hostname: "localhost",
	}
	err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
	if err != nil {
		panic(err)
	}

	// Generate valid client certificate for "testuser" user
	clientCertPath := path.Join(tempDir, "client.crt")
	clientKeyPath := path.Join(tempDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName: "testuser",
	}
	err = tlsutils.GenerateClientCertToFile(caCert, caKey, clientCertPath, clientKeyPath, clientOpts)
	if err != nil {
		panic(err)
	}

	// Generate self-signed client cert for "testuser" user
	selfSignedClientCertPath := path.Join(tempDir, "client-selfsigned.crt")
	selfSignedClientKeyPath := path.Join(tempDir, "client-selfsigned.key")
	selfSignedOpts := &tlsutils.CertificateOptions{
		CommonName: "testuser",
	}
	err = tlsutils.GenerateClientSelfSignedCertToFile(selfSignedClientCertPath, selfSignedClientKeyPath, selfSignedOpts)
	if err != nil {
		panic(err)
	}

	// Create htpasswd file with sample "httpuser"
	htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString("httpuser", "httppass"))
	defer os.Remove(htpasswdPath)

	Convey("Test mTLS-only authentication", t, func() {
		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{ // Default restrict all
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Test without client certificate - should fail
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS13})
		resp, err := client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// Test with valid client certificate - should succeed
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})

		resp, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Test with self-signed client certificate - should fail
		selfSignedClientCert, err := tls.LoadX509KeyPair(selfSignedClientCertPath, selfSignedClientKeyPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{selfSignedClientCert},
			RootCAs:      caCertPool,
		})

		resp, err = client.R().Get(baseURL + "/v2/test-selfsigned-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})

	Convey("Test mTLS with basic auth and user/group access policies", t, func() {
		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{ // Default restrict all
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"group-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Groups:  []string{"mtls-users"},
							Actions: []string{"read", "create"},
						},
					},
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
				"htpasswd-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"httpuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Load server CA certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		// Load self-signed client certificate
		selfSignedClientCert, err := tls.LoadX509KeyPair(selfSignedClientCertPath, selfSignedClientKeyPath)
		So(err, ShouldBeNil)

		// Load valid client certificate with CN "testuser"
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		// Tests without client certificate
		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS13})
		resp, err := client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		// Test without client CA but with htpasswd credentials - should pass because of valid htpasswd credentials
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Tests with self-signed (== non-acceptable by server) client certificate
		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{selfSignedClientCert},
			RootCAs:      caCertPool,
		})

		// Test with self-signed client certificate - should still pass because of correct htpasswd auth
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Tests with valid client certificate
		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})
		// Tests with valid client cert and creds - should fail with 403 due to no permissions for user from basic auth
		// This validates that identity from basic auth has higher priority over mTLS identity
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// Test with correct auth credentials and different basic auth username from client certificate CN - should success
		// This validates that identity from basic auth has higher priority over mTLS identity
		resp, err = client.R().SetBasicAuth("httpuser", "httppass").Get(baseURL + "/v2/htpasswd-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Should have access to test-repo for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth

		// Should not have access to other repos for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/unauthorized-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// Should have access to group-repo through group membership for identity from client-cert
		resp, err = client.R().Get(baseURL + "/v2/group-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 meaning we successfully passed auth
	})
}

func TestMTLSAuthenticationWithCertificateChain(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS with certificate chain - uses leaf certificate identity", t, func() {
		// Create certificate chain: Root CA -> Intermediate CA -> Client Certificate
		// Generate root CA
		rootCACert, rootCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		rootCACertPath := path.Join(tempDir, "root-ca.crt")
		err = os.WriteFile(rootCACertPath, rootCACert, 0o600)
		So(err, ShouldBeNil)

		// Generate intermediate CA (signed by root CA)
		intermediateCAOpts := &tlsutils.CertificateOptions{
			CommonName: "Intermediate CA",
		}
		intermediateCACert, intermediateCAKeyPEM, err := tlsutils.GenerateIntermediateCACert(
			rootCACert, rootCAKey, intermediateCAOpts)
		So(err, ShouldBeNil)

		// Generate client certificate with CN signed by intermediate CA
		clientWithCNOpts := &tlsutils.CertificateOptions{
			CommonName: "clientuser",
		}
		clientCertWithCN, clientKeyWithCN, err := tlsutils.GenerateClientCert(
			intermediateCACert, intermediateCAKeyPEM, clientWithCNOpts)
		So(err, ShouldBeNil)

		// Generate client certificate without CN signed by intermediate CA
		clientWithoutCNOpts := &tlsutils.CertificateOptions{
			// No CommonName - empty to test that identity is not taken from intermediate CA
		}
		clientCertWithoutCN, clientKeyWithoutCNPEM, err := tlsutils.GenerateClientCert(
			intermediateCACert, intermediateCAKeyPEM, clientWithoutCNOpts)
		So(err, ShouldBeNil)

		// Generate server certificate signed by root CA for this test
		serverCertForChainPath := path.Join(tempDir, "server-chain.crt")
		serverKeyForChainPath := path.Join(tempDir, "server-chain.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(
			rootCACert, rootCAKey, serverCertForChainPath, serverKeyForChainPath, serverOpts)
		So(err, ShouldBeNil)

		// Set up server with root CA
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertForChainPath,
			Key:    serverKeyForChainPath,
			CACert: rootCACertPath, // Server trusts root CA
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"client-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"clientuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(rootCACert)

		// Test 1: Client cert with CN in chain - should use client cert CN, not intermediate CA CN
		clientCertWithCNPath := path.Join(tempDir, "client-with-cn.crt")
		clientKeyWithCNPath := path.Join(tempDir, "client-with-cn.key")
		err = os.WriteFile(clientCertWithCNPath, clientCertWithCN, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(clientKeyWithCNPath, clientKeyWithCN, 0o600)
		So(err, ShouldBeNil)

		// Create certificate chain file (client cert + intermediate CA)
		chainCertPath := path.Join(tempDir, "client-with-cn-chain.crt")
		err = tlsutils.WriteCertificateChainToFile(chainCertPath, clientCertWithCN, intermediateCACert)
		So(err, ShouldBeNil)

		// Load certificate chain
		clientCertChain, err := tls.LoadX509KeyPair(chainCertPath, clientKeyWithCNPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCertChain},
			RootCAs:      caCertPool,
		})

		// Should succeed because client cert has CN "clientuser" which matches policy
		resp, err := client.R().Get(baseURL + "/v2/client-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound) // 404 means auth passed

		// Test 2: Client cert without CN in chain - should fail, not use intermediate CA CN
		clientCertWithoutCNPath := path.Join(tempDir, "client-without-cn.crt")
		clientKeyWithoutCNPath := path.Join(tempDir, "client-without-cn.key")
		err = os.WriteFile(clientCertWithoutCNPath, clientCertWithoutCN, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(clientKeyWithoutCNPath, clientKeyWithoutCNPEM, 0o600)
		So(err, ShouldBeNil)

		// Create certificate chain file (client cert without CN + intermediate CA)
		chainCertWithoutCNPath := path.Join(tempDir, "client-without-cn-chain.crt")
		err = tlsutils.WriteCertificateChainToFile(chainCertWithoutCNPath, clientCertWithoutCN, intermediateCACert)
		So(err, ShouldBeNil)

		// Load certificate chain
		clientCertChainWithoutCN, err := tls.LoadX509KeyPair(chainCertWithoutCNPath, clientKeyWithoutCNPath)
		So(err, ShouldBeNil)

		client = resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCertChainWithoutCN},
			RootCAs:      caCertPool,
		})

		// Should fail because client cert has no CN, even though intermediate CA has CN
		resp, err = client.R().Get(baseURL + "/v2/client-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestMTLSAuthenticationWithExpiredCertificate(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with expired certificate", t, func() {
		// Generate CA certificate
		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		caCertPath := path.Join(tempDir, "ca.crt")
		err = os.WriteFile(caCertPath, caCert, 0o600)
		So(err, ShouldBeNil)

		// Generate server certificate
		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate expired client certificate (NotAfter is in the past)
		expiredClientCertPath := path.Join(tempDir, "client-expired.crt")
		expiredClientKeyPath := path.Join(tempDir, "client-expired.key")
		expiredOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
			NotBefore:  time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
			NotAfter:   time.Now().Add(-24 * time.Hour),       // 1 day ago (expired)
		}
		err = tlsutils.GenerateClientCertToFile(caCert, caKey, expiredClientCertPath, expiredClientKeyPath, expiredOpts)
		So(err, ShouldBeNil)

		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with expired certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		expiredClientCert, err := tls.LoadX509KeyPair(expiredClientCertPath, expiredClientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{expiredClientCert},
			RootCAs:      caCertPool,
		})

		// Expired certificate should be rejected at TLS handshake level
		// The TLS stack will reject it before it reaches the application layer
		_, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		// Error is expected - TLS handshake fails with expired certificate
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "expired certificate")
	})
}

func TestMTLSAuthenticationWithUnknownCA(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with certificate signed by unknown CA", t, func() {
		// Generate server CA and certificate
		serverCACert, serverCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		serverCACertPath := path.Join(tempDir, "server-ca.crt")
		err = os.WriteFile(serverCACertPath, serverCACert, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(serverCACert, serverCAKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate a different CA (unknown to the server) and client certificate
		unknownCACert, unknownCAKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)

		unknownClientCertPath := path.Join(tempDir, "client-unknown-ca.crt")
		unknownClientKeyPath := path.Join(tempDir, "client-unknown-ca.key")
		clientOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
		}
		err = tlsutils.GenerateClientCertToFile(unknownCACert, unknownCAKey, unknownClientCertPath,
			unknownClientKeyPath, clientOpts)
		So(err, ShouldBeNil)

		// Set up server with server CA (doesn't know about unknown CA)
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: serverCACertPath, // Server only trusts serverCACert, not unknownCACert
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with certificate signed by unknown CA
		serverCACertPEM, err := os.ReadFile(serverCACertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(serverCACertPEM)

		unknownClientCert, err := tls.LoadX509KeyPair(unknownClientCertPath, unknownClientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{unknownClientCert},
			RootCAs:      caCertPool,
		})

		// Certificate signed by unknown CA should be rejected at TLS handshake level
		// The TLS stack will reject it before it reaches the application layer
		_, err = client.R().Get(baseURL + "/v2/test-repo/tags/list")
		// Error is expected - TLS handshake fails with unknown certificate authority
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "unknown certificate authority")
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

func TestMTLSAuthenticationWithMetaDBError(t *testing.T) {
	// Create temporary directory for certificates
	tempDir := t.TempDir()

	Convey("Test mTLS authentication with MetaDB.SetUserGroups error", t, func() {
		// Generate CA certificate
		caCert, caKey, err := tlsutils.GenerateCACert()
		So(err, ShouldBeNil)
		caCertPath := path.Join(tempDir, "ca.crt")
		err = os.WriteFile(caCertPath, caCert, 0o600)
		So(err, ShouldBeNil)

		// Generate server certificate
		serverCertPath := path.Join(tempDir, "server.crt")
		serverKeyPath := path.Join(tempDir, "server.key")
		opts := &tlsutils.CertificateOptions{
			Hostname: "localhost",
		}
		err = tlsutils.GenerateServerCertToFile(caCert, caKey, serverCertPath, serverKeyPath, opts)
		So(err, ShouldBeNil)

		// Generate valid client certificate for "testuser" user
		clientCertPath := path.Join(tempDir, "client.crt")
		clientKeyPath := path.Join(tempDir, "client.key")
		clientOpts := &tlsutils.CertificateOptions{
			CommonName: "testuser",
		}
		err = tlsutils.GenerateClientCertToFile(caCert, caKey, clientCertPath, clientKeyPath, clientOpts)
		So(err, ShouldBeNil)

		// Set up server
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetSecureBaseURL(port)

		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				"mtls-users": config.Group{
					Users: []string{"testuser"},
				},
			},
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					AnonymousPolicy: make([]string, 0),
					Policies:        make([]config.Policy, 0),
				},
				"test-repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"testuser"},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		// Set up client with valid certificate
		caCertPEM, err := os.ReadFile(caCertPath)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		So(err, ShouldBeNil)

		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		})

		// Mock MetaDB to return error on SetUserGroups
		ctlr.MetaDB = mocks.MetaDBMock{
			SetUserGroupsFn: func(ctx context.Context, groups []string) error {
				return ErrUnexpectedError
			},
		}

		// Should return 500 Internal Server Error due to MetaDB error
		resp, err := client.R().Get(baseURL + "/v2/test-repo/tags/list")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
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
