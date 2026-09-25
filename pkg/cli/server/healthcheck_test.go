package server_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	. "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestHealthcheck(t *testing.T) {
	oldArgs := os.Args

	defer func() { os.Args = oldArgs }()

	Convey("healthcheck succeeds against readyz", t, func() {
		var sawPath atomic.Value

		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			sawPath.Store(request.URL.Path)
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("ok"))
		}))
		defer server.Close()

		os.Args = []string{"cli_test", "healthcheck", "--url", server.URL + "/readyz"}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
		So(sawPath.Load(), ShouldEqual, "/readyz")
	})

	Convey("healthcheck ready alias works", t, func() {
		var sawPath atomic.Value

		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			sawPath.Store(request.URL.Path)
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		os.Args = []string{"cli_test", "ready", "--endpoint", "livez", "--url", server.URL}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
		So(sawPath.Load(), ShouldEqual, "/livez")
	})

	Convey("healthcheck fails on non-2xx", t, func() {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		os.Args = []string{"cli_test", "healthcheck", "--url", server.URL + "/readyz"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrHealthcheckFailed), ShouldBeTrue)
	})

	Convey("healthcheck fails when nothing is listening", t, func() {
		os.Args = []string{"cli_test", "healthcheck", "--url", "http://127.0.0.1:1/readyz", "--timeout", "100ms"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrHealthcheckFailed), ShouldBeTrue)
	})

	Convey("healthcheck rejects invalid endpoint", t, func() {
		os.Args = []string{"cli_test", "healthcheck", "--endpoint", "healthz", "--url", "http://127.0.0.1:5000"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidCLIParameter), ShouldBeTrue)
	})

	Convey("healthcheck reads address and port from config", t, func() {
		lc := net.ListenConfig{}
		listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		So(err, ShouldBeNil)

		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		So(ok, ShouldBeTrue)

		port := tcpAddr.Port

		var sawPath atomic.Value

		httpServer := &http.Server{ //nolint:gosec // test server
			Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				sawPath.Store(request.URL.Path)
				response.WriteHeader(http.StatusOK)
			}),
		}

		go func() {
			_ = httpServer.Serve(listener)
		}()

		defer func() {
			_ = httpServer.Close()
		}()

		content := fmt.Sprintf(`{
			"storage":{"rootDirectory":"/tmp/zot-healthcheck"},
			"http":{"address":"0.0.0.0","port":"%d"},
			"log":{"level":"error"}
		}`, port)
		tmpfile := MakeTempFileWithContent(t, "zot-healthcheck.json", content)

		os.Args = []string{"cli_test", "healthcheck", "--endpoint", "startupz", tmpfile}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
		So(sawPath.Load(), ShouldEqual, "/startupz")
	})

	Convey("healthcheck uses https with insecure-skip-verify", t, func() {
		var sawPath atomic.Value

		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			sawPath.Store(request.URL.Path)
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		os.Args = []string{
			"cli_test", "healthcheck",
			"--url", server.URL + "/readyz",
			"--insecure-skip-verify",
		}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
		So(sawPath.Load(), ShouldEqual, "/readyz")
	})

	Convey("healthcheck without config or --url requires a config like serve", t, func() {
		os.Args = []string{"cli_test", "healthcheck"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "accepts 1 arg")
	})

	Convey("healthcheck rejects config and --url together", t, func() {
		tmpfile := MakeTempFileWithContent(t, "zot-healthcheck-mutex.json", `{
			"storage":{"rootDirectory":"/tmp/zot-healthcheck"},
			"http":{"address":"127.0.0.1","port":"8080"},
			"log":{"level":"error"}
		}`)

		os.Args = []string{
			"cli_test", "healthcheck", tmpfile,
			"--url", "http://127.0.0.1:8080/readyz",
		}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "accepts 0 arg")
	})

	Convey("healthcheck fails when config file cannot be loaded", t, func() {
		os.Args = []string{"cli_test", "healthcheck", "/nonexistent/zot-healthcheck-config.json"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("healthcheck rejects invalid --url", t, func() {
		os.Args = []string{"cli_test", "healthcheck", "--url", "://bad"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidCLIParameter), ShouldBeTrue)
	})

	Convey("healthcheck treats non-positive timeout as default", t, func() {
		var sawPath atomic.Value

		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			sawPath.Store(request.URL.Path)
			response.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		os.Args = []string{"cli_test", "healthcheck", "--url", server.URL + "/readyz", "--timeout", "0"}
		So(cli.NewServerRootCmd().Execute(), ShouldBeNil)
		So(sawPath.Load(), ShouldEqual, "/readyz")
	})

	Convey("healthcheck does not follow redirects to a 2xx page", t, func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ok", func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/readyz", func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, "/ok", http.StatusFound)
		})

		server := httptest.NewServer(mux)
		defer server.Close()

		os.Args = []string{"cli_test", "healthcheck", "--url", server.URL + "/readyz"}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrHealthcheckFailed), ShouldBeTrue)
		So(err.Error(), ShouldContainSubstring, "returned status 302")
	})

	Convey("healthcheck redacts URL userinfo in failure errors", t, func() {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		// httptest.Server.URL is http://127.0.0.1:<port>; inject userinfo before the host.
		rawURL := "http://probe-user:s3cret@" + server.URL[len("http://"):] + "/readyz"
		os.Args = []string{"cli_test", "healthcheck", "--url", rawURL}
		err := cli.NewServerRootCmd().Execute()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrHealthcheckFailed), ShouldBeTrue)
		So(err.Error(), ShouldContainSubstring, "probe-user:xxxxx@")
		So(err.Error(), ShouldNotContainSubstring, "s3cret")
	})
}
