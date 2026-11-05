//go:build !windows

package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	. "zotregistry.dev/zot/v2/pkg/test/common"
)

// writeServeConfig writes a minimal config; httpOptions are added to its http section.
func writeServeConfig(t *testing.T, port string, httpOptions ...string) string {
	t.Helper()

	extra := ""
	if len(httpOptions) > 0 {
		extra = ", " + strings.Join(httpOptions, ", ")
	}

	cfgPath := path.Join(t.TempDir(), "config.json")
	content := fmt.Sprintf(`{"distSpecVersion": "1.1.1", "storage": {"rootDirectory": %q},
		"http": {"address": "127.0.0.1", "port": %q%s}, "log": {"level": "error", "output": %q}}`,
		t.TempDir(), port, extra, path.Join(t.TempDir(), "zot.log"))

	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return cfgPath
}

const serveStartFailureChildEnv = "ZOT_TEST_SERVE_START_FAILURE_CONFIG"

func runServe(cfgPath string) <-chan error {
	served := make(chan error, 1)

	go func() {
		cmd := cli.NewServerRootCmd()
		cmd.SetArgs([]string{"serve", cfgPath})
		served <- cmd.Execute()
	}()

	return served
}

func TestServeReportsStartFailure(t *testing.T) {
	// The controller starts its background tasks before it binds the port, and they are left
	// running when serve fails, as the process exits then; so serve runs in a separate process,
	// which exits like cmd/zot does.
	if cfgPath := os.Getenv(serveStartFailureChildEnv); cfgPath != "" {
		cmd := cli.NewServerRootCmd()
		cmd.SetArgs([]string{"serve", cfgPath})

		if err := cmd.Execute(); err != nil {
			os.Exit(1)
		}

		os.Exit(0)
	}

	Convey("serve exits with a non-zero code when the controller can't start", t, func() {
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only listener
		So(err, ShouldBeNil)

		defer listener.Close()

		_, port, err := net.SplitHostPort(listener.Addr().String())
		So(err, ShouldBeNil)

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		//nolint:gosec // G204: test-only, re-runs this test binary
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServeReportsStartFailure$")

		cmd.Env = append(os.Environ(), serveStartFailureChildEnv+"="+writeServeConfig(t, port))

		output, err := cmd.CombinedOutput()
		So(ctx.Err(), ShouldBeNil)

		exitErr, ok := errors.AsType[*exec.ExitError](err)
		So(ok, ShouldBeTrue)
		So(exitErr.ExitCode(), ShouldEqual, 1)
		// the error is reported, but it is not a command line error, so no usage is printed
		So(string(output), ShouldContainSubstring, "address already in use")
		So(string(output), ShouldNotContainSubstring, "Usage:")
	})
}

func TestServeDrainsRequestsOnSIGTERM(t *testing.T) {
	Convey("SIGTERM lets in-flight requests finish before serve returns", t, func() {
		port := GetFreePort()
		baseURL := "http://127.0.0.1:" + port

		defer signal.Reset()

		// no shutdown timeout, so the test can't pass by closing the request
		served := runServe(writeServeConfig(t, port, `"shutdownTimeout": "0"`))
		So(waitForServer(baseURL+"/v2/", served), ShouldBeTrue)

		blob, body, conn := startBlobDownload(baseURL, port)

		defer conn.Close()

		// the client stops reading while the server is still writing the blob
		So(syscall.Kill(os.Getpid(), syscall.SIGTERM), ShouldBeNil)

		select {
		case err := <-served:
			t.Fatalf("serve returned while a request was in flight: %v", err)
		case <-time.After(time.Second):
		}

		received, err := io.ReadAll(body)
		So(err, ShouldBeNil)
		So(bytes.Equal(received, blob), ShouldBeTrue)

		select {
		case err := <-served:
			So(err, ShouldBeNil)
		case <-time.After(30 * time.Second):
			t.Fatal("serve did not return after the request finished")
		}
	})
}

func TestServeShutdownTimeout(t *testing.T) {
	Convey("SIGTERM closes requests still running after http.shutdownTimeout", t, func() {
		port := GetFreePort()
		baseURL := "http://127.0.0.1:" + port

		defer signal.Reset()

		served := runServe(writeServeConfig(t, port, `"shutdownTimeout": "1s"`))
		So(waitForServer(baseURL+"/v2/", served), ShouldBeTrue)

		_, _, conn := startBlobDownload(baseURL, port)

		defer conn.Close()

		// the client never reads the rest of the blob, so the request can't finish
		signaled := time.Now()
		So(syscall.Kill(os.Getpid(), syscall.SIGTERM), ShouldBeNil)

		select {
		case err := <-served:
			So(err, ShouldBeNil)
			So(time.Since(signaled), ShouldBeGreaterThanOrEqualTo, time.Second)
		case <-time.After(15 * time.Second):
			t.Fatal("serve did not return after the shutdown timeout")
		}
	})
}

// startBlobDownload uploads a blob larger than the socket buffers, then starts downloading it and
// reads only the response headers, so the server is still writing the blob when this returns.
// It returns the blob, the response body, and the connection, which closes the body.
func startBlobDownload(baseURL, port string) ([]byte, io.Reader, net.Conn) {
	blob := make([]byte, 32*1024*1024)
	_, err := rand.Read(blob)
	So(err, ShouldBeNil)

	digest := godigest.FromBytes(blob)
	So(uploadBlob(baseURL, "repo", digest, blob), ShouldBeNil)

	// a scrape enables metrics, so the in-flight request sends one when it finishes
	So(scrapeMetrics(baseURL), ShouldBeNil)

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", "127.0.0.1:"+port)
	So(err, ShouldBeNil)

	_, err = fmt.Fprintf(conn, "GET /v2/repo/blobs/%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", digest)
	So(err, ShouldBeNil)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil) //nolint:bodyclose // closed with conn
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)

	return blob, resp.Body, conn
}

func waitForServer(url string, served <-chan error) bool {
	for range 100 {
		select {
		case <-served:
			return false
		default:
		}

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()

			return true
		}

		time.Sleep(100 * time.Millisecond)
	}

	return false
}

func scrapeMetrics(baseURL string) error {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/metrics", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return err
}

func uploadBlob(baseURL, repo string, digest godigest.Digest, blob []byte) error {
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v2/"+repo+"/blobs/uploads/", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	resp.Body.Close()

	location := resp.Header.Get("Location")

	req, _ = http.NewRequestWithContext(ctx, http.MethodPut,
		baseURL+location+"?digest="+digest.String(), bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("upload status %d", resp.StatusCode) //nolint:err113 // test helper
	}

	return nil
}
