//go:build apikey
// +build apikey

package extensions_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/project-zot/mockoidc"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/extensions"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/meta/repodb"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

type (
	apiKeyResponse struct {
		repodb.APIKeyDetails
		APIKey string `json:"apiKey"`
	}
)

var ErrUnexpectedError = errors.New("unexpected err")

func TestAPIKeys(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		mockOIDCServer, err := test.MockOIDCRun()
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
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"dex": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email", "groups"},
					},
				},
			},
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{}

		defaultVal := true
		apiKeyConfig := &extconf.APIKeyConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}

		mgmtConfg := &extconf.MgmtConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}

		conf.Extensions = &extconf.ExtensionConfig{
			APIKey: apiKeyConfig,
			Mgmt:   mgmtConfg,
		}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		ctlr.Config.Storage.RootDirectory = dir

		cm := test.NewControllerManager(ctlr)

		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		payload := extensions.APIKeyPayload{
			Label:  "test",
			Scopes: []string{"test"},
		}
		reqBody, err := json.Marshal(payload)
		So(err, ShouldBeNil)

		Convey("API key retrieved with basic auth", func() {
			// call endpoint with session ( added to client after previous request)
			resp, err := resty.R().
				SetBody(reqBody).
				SetBasicAuth("test", "test").
				Post(baseURL + constants.FullAPIKeyPrefix)
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
				SetBasicAuth("test", apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// add another one
			resp, err = resty.R().
				SetBody(reqBody).
				SetBasicAuth("test", "test").
				Post(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			resp, err = resty.R().
				SetBasicAuth("test", apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("API key retrieved with openID", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "dex").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			cookies := resp.Cookies()

			// call endpoint without session
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			client.SetCookies(cookies)

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.FullAPIKeyPrefix)
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

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// trigger errors
			ctlr.RepoDB = mocks.RepoDBMock{
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

			ctlr.RepoDB = mocks.RepoDBMock{
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

			ctlr.RepoDB = mocks.RepoDBMock{
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
				Post(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})

		Convey("Login with openid and create API key", func() {
			client := resty.New()

			// mgmt should work both unauthenticated and authenticated
			resp, err := client.R().
				Get(baseURL + constants.FullMgmtPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
			// first login user
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "dex").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			client.SetCookies(resp.Cookies())

			// call endpoint with session ( added to client after previous request)
			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			var apiKeyResponse apiKeyResponse
			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

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
				Get(baseURL + constants.FullMgmtPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// invalid api keys
			resp, err = client.R().
				SetBasicAuth("invalidEmail", apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmtPrefix)
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

			authzCtxKey := localCtx.GetContextKey()

			acCtx := localCtx.AccessControlContext{
				Username: email,
			}

			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = ctlr.RepoDB.DeleteUserData(ctx)
			So(err, ShouldBeNil)

			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmtPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			client = resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// without creds should work
			resp, err = client.R().
				Get(baseURL + constants.FullMgmtPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// login again
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "dex").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			client.SetCookies(resp.Cookies())

			resp, err = client.R().
				SetBody(reqBody).
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Post(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			err = json.Unmarshal(resp.Body(), &apiKeyResponse)
			So(err, ShouldBeNil)

			// should work with session
			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Get(baseURL + constants.FullMgmtPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// should work with api key
			resp, err = client.R().
				SetBasicAuth(email, apiKeyResponse.APIKey).
				Get(baseURL + constants.FullMgmtPrefix)
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
				Delete(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				Delete(baseURL + constants.FullAPIKeyPrefix)
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
				SetBasicAuth("test", "test").
				SetQueryParam("id", apiKeyResponse.UUID).
				Delete(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// unsupported method
			resp, err = client.R().
				Put(baseURL + constants.FullAPIKeyPrefix)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
		})
	})
}

func TestAPIKeysOpenDBError(t *testing.T) {
	Convey("Test API keys - unable to create database", t, func() {
		conf := config.New()
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		mockOIDCServer, err := test.MockOIDCRun()
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
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},

			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"dex": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},
		}

		defaultVal := true
		apiKeyConfig := &extconf.APIKeyConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			APIKey: apiKeyConfig,
		}

		ctlr := api.NewController(conf)
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
