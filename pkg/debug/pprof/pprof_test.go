//go:build profile
// +build profile

package pprof_test

import (
	"net/http"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	debugConstants "zotregistry.dev/zot/pkg/debug/constants"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestProfilingAuthz(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		adminUsername, seedAdminUser := test.GenerateRandomString()
		adminPassword, seedAdminPass := test.GenerateRandomString()
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		authorizationAllRepos := test.AuthorizationAllRepos

		testCreds := test.GetCredString(adminUsername, adminPassword) +
			test.GetCredString(username, password)
		htpasswdPath := test.MakeHtpasswdFileFromString(testCreds)
		defer os.Remove(htpasswdPath)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		Convey("Test with no access control", func() {
			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated clients should have access to /v2/
			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// unauthenticated clients should have access to the profiling endpoints
			resp, err = resty.R().Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().SetQueryParam("seconds", "1").
				Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "profile")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "goroutine")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// test building the index
			resp, err = resty.R().Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Test with authenticated users and no anonymous policy", func() {
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Repositories: config.Repositories{
					authorizationAllRepos: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{username},
								Actions: []string{"read", "create"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{adminUsername},
					Actions: []string{},
				},
			}

			ctlr := api.NewController(conf)
			ctlr.Log.Info().Int64("seedAdminUser", seedAdminUser).Int64("seedAdminPass", seedAdminPass).
				Msg("random seed for admin username & password")
			ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated clients should not have access to /v2/
			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// unauthenticated clients should not have access to the profiling endpoint
			resp, err = resty.R().Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authenticated clients without permissions should not have access to the profiling endpoint
			resp, err = resty.R().SetBasicAuth(username, password).
				Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated clients with admin permissions should have access to the profiling endpoint
			resp, err = resty.R().SetBasicAuth(adminUsername, adminPassword).
				Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Test with authenticated users and anonymous policy", func() {
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Repositories: config.Repositories{
					authorizationAllRepos: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{username},
								Actions: []string{"read", "create"},
							},
						},
						DefaultPolicy:   []string{},
						AnonymousPolicy: []string{"read"},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{adminUsername},
					Actions: []string{},
				},
			}

			ctlr := api.NewController(conf)
			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// unauthenticated clients should have access to /v2/
			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// unauthenticated clients should not have access to the profiling endpoint
			resp, err = resty.R().Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			// authenticated clients without permissions should not have access to the profiling endpoint
			resp, err = resty.R().SetBasicAuth(username, password).
				Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

			// authenticated clients with admin permissions should have access to the profiling endpoint
			resp, err = resty.R().SetBasicAuth(adminUsername, adminPassword).
				Get(baseURL + constants.RoutePrefix + debugConstants.ProfilingEndpoint + "trace")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
	})
}
