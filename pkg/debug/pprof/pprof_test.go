//go:build profile
// +build profile

package pprof_test

import (
	"net/http"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	debugConstants "zotregistry.io/zot/pkg/debug/constants"
	"zotregistry.io/zot/pkg/test"
)

func TestProfilingAuthz(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		adminUsername := "admin"
		adminPassword := "admin"
		username := "test"
		password := "test"
		authorizationAllRepos := "**"

		testCreds := test.GetCredString(adminUsername, adminPassword) +
			"\n" + test.GetCredString(username, password)
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
