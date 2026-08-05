//go:build search

package client //nolint:testpackage

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/buildinfo"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestServerStatusCommand(t *testing.T) {
	Convey("ServerStatusCommand", t, func() {
		conf := config.New()
		conf.HTTP.Port = "0"
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)

		baseURL := cm.StartAndWait()
		defer cm.StopServer()

		_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"status-test","url":"%s","showspinner":false}]}`,
			baseURL))

		args := []string{"status", "--config", "status-test"}
		cmd := NewCliRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, buildinfo.ReleaseTag)
		So(actual, ShouldContainSubstring, buildinfo.BinaryType)

		// JSON
		args = []string{"status", "--config", "status-test", "--format", "json"}
		cmd = NewCliRootCmd()
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space = regexp.MustCompile(`\s+`)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, buildinfo.ReleaseTag)
		So(actual, ShouldContainSubstring, buildinfo.BinaryType)

		// YAML
		args = []string{"status", "--config", "status-test", "--format", "yaml"}
		cmd = NewCliRootCmd()
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space = regexp.MustCompile(`\s+`)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, buildinfo.ReleaseTag)
		So(actual, ShouldContainSubstring, buildinfo.BinaryType)

		// bad type
		args = []string{"status", "--config", "status-test", "--format", "badType"}
		cmd = NewCliRootCmd()
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestServerStatusCommandErrors(t *testing.T) {
	Convey("ServerStatusCommand", t, func() {
		args := []string{"status"}
		cmd := NewCliRootCmd()
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)

		// invalid URL
		err = GetServerStatus(SearchConfig{
			ServURL:       "a: ds",
			ResultWriter:  os.Stdout,
			SearchService: NewSearchService(),
		})
		So(err, ShouldNotBeNil)

		// fail Get request
		err = GetServerStatus(SearchConfig{
			ServURL:       "http://127.0.0.1:8000",
			ResultWriter:  os.Stdout,
			SearchService: NewSearchService(),
		})
		So(err, ShouldBeNil)
	})

	Convey("HTTP errors", t, func() {
		result := bytes.NewBuffer([]byte{})
		searchConfig := SearchConfig{
			SearchService: newMockService(),
			User:          "",
			OutputFormat:  "text",
			ResultWriter:  result,
		}

		Convey("v2 is Unauthorised", func() {
			server, baseURL := StartTestHTTPServer(HTTPRoutes{
				RouteHandler{
					Route: "/v2/",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusUnauthorized)
					},
					AllowedMethods: []string{http.MethodGet},
				},
			})
			defer server.Close()

			searchConfig.ServURL = baseURL
			err := GetServerStatus(searchConfig)
			So(err, ShouldBeNil)
			So(result.String(), ShouldContainSubstring, "unauthorised access, endpoint requires valid user credentials")

			// with bad user set
			searchConfig.User = "test:test"
			err = GetServerStatus(searchConfig)
			So(err, ShouldBeNil)
			So(result.String(), ShouldContainSubstring, "unauthorised access, given credentials are invalid")
		})

		Convey("v2 bad http status code", func() {
			server, baseURL := StartTestHTTPServer(HTTPRoutes{
				RouteHandler{
					Route: "/v2/",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusInternalServerError)
					},
					AllowedMethods: []string{http.MethodGet},
				},
			})
			defer server.Close()

			searchConfig.ServURL = baseURL
			err := GetServerStatus(searchConfig)
			So(err, ShouldBeNil)
			So(result.String(), ShouldContainSubstring, zerr.ErrAPINotSupported.Error())
		})

		Convey("MGMT errors", func() {
			Convey("URL not found", func() {
				server, baseURL := StartTestHTTPServer(HTTPRoutes{
					RouteHandler{
						Route: "/v2/",
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusOK)
						},
						AllowedMethods: []string{http.MethodGet},
					},
				})
				defer server.Close()

				searchConfig.ServURL = baseURL
				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, "endpoint is not available")
			})

			Convey("Unauthorized Access", func() {
				server, baseURL := StartTestHTTPServer(HTTPRoutes{
					RouteHandler{
						Route: "/v2/",
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusOK)
						},
						AllowedMethods: []string{http.MethodGet},
					},
					RouteHandler{
						Route: constants.RoutePrefix + constants.ExtMgmt,
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusUnauthorized)
						},
						AllowedMethods: []string{http.MethodGet},
					},
				})
				defer server.Close()

				searchConfig.ServURL = baseURL
				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, "unauthorised access")
			})

			Convey("Bad status code", func() {
				server, baseURL := StartTestHTTPServer(HTTPRoutes{
					RouteHandler{
						Route: "/v2/",
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusOK)
						},
						AllowedMethods: []string{http.MethodGet},
					},
					RouteHandler{
						Route: constants.RoutePrefix + constants.ExtMgmt,
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusInternalServerError)
						},
						AllowedMethods: []string{http.MethodGet},
					},
				})
				defer server.Close()

				searchConfig.ServURL = baseURL
				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, zerr.ErrAPINotSupported.Error())
			})
		})
	})
}
