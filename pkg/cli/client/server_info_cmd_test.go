//go:build search
// +build search

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

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestServerStatusCommand(t *testing.T) {
	Convey("ServerStatusCommand", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"status-test","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

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
		So(actual, ShouldContainSubstring, config.ReleaseTag)
		So(actual, ShouldContainSubstring, config.BinaryType)

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
		So(actual, ShouldContainSubstring, config.ReleaseTag)
		So(actual, ShouldContainSubstring, config.BinaryType)

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
		So(actual, ShouldContainSubstring, config.ReleaseTag)
		So(actual, ShouldContainSubstring, config.BinaryType)

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
			ServURL:      "a: ds",
			ResultWriter: os.Stdout,
		})
		So(err, ShouldNotBeNil)

		// fail Get request
		err = GetServerStatus(SearchConfig{
			ServURL:      "http://127.0.0.1:8000",
			ResultWriter: os.Stdout,
		})
		So(err, ShouldBeNil)
	})

	Convey("HTTP errors", t, func() {
		port := test.GetFreePort()
		result := bytes.NewBuffer([]byte{})
		searchConfig := SearchConfig{
			SearchService: mockService{},
			ServURL:       fmt.Sprintf("http://127.0.0.1:%v", port),
			User:          "",
			OutputFormat:  "text",
			ResultWriter:  result,
		}

		Convey("v2 is Unauthorised", func() {
			server := StartTestHTTPServer(HTTPRoutes{
				RouteHandler{
					Route: "/v2/",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusUnauthorized)
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()

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
			server := StartTestHTTPServer(HTTPRoutes{
				RouteHandler{
					Route: "/v2/",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusInternalServerError)
					},
					AllowedMethods: []string{http.MethodGet},
				},
			}, port)
			defer server.Close()

			err := GetServerStatus(searchConfig)
			So(err, ShouldBeNil)
			So(result.String(), ShouldContainSubstring, zerr.ErrAPINotSupported.Error())
		})

		Convey("MGMT errors", func() {
			Convey("URL not found", func() {
				server := StartTestHTTPServer(HTTPRoutes{
					RouteHandler{
						Route: "/v2/",
						HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
							w.WriteHeader(http.StatusOK)
						},
						AllowedMethods: []string{http.MethodGet},
					},
				}, port)
				defer server.Close()

				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, "endpoint is not available")
			})

			Convey("Unauthorized Access", func() {
				server := StartTestHTTPServer(HTTPRoutes{
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
				}, port)
				defer server.Close()

				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, "unauthorised access")
			})

			Convey("Bad status code", func() {
				server := StartTestHTTPServer(HTTPRoutes{
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
				}, port)
				defer server.Close()

				err := GetServerStatus(searchConfig)
				So(err, ShouldBeNil)
				So(result.String(), ShouldContainSubstring, zerr.ErrAPINotSupported.Error())
			})
		})
	})
}
