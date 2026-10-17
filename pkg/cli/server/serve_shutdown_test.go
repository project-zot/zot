//go:build !windows

package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	. "zotregistry.dev/zot/v2/pkg/test/common"
)

func writeServeConfig(t *testing.T, port string) string {
	t.Helper()

	cfgPath := path.Join(t.TempDir(), "config.json")
	content := fmt.Sprintf(`{"distSpecVersion": "1.1.1", "storage": {"rootDirectory": %q},
		"http": {"address": "127.0.0.1", "port": %q}, "log": {"level": "error", "output": %q}}`,
		t.TempDir(), port, path.Join(t.TempDir(), "zot.log"))

	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return cfgPath
}

func runServe(cfgPath string, output io.Writer) <-chan error {
	served := make(chan error, 1)

	go func() {
		cmd := cli.NewServerRootCmd()
		cmd.SetArgs([]string{"serve", cfgPath})
		cmd.SetOut(output)
		cmd.SetErr(output)
		served <- cmd.Execute()
	}()

	return served
}

func TestServeReportsStartFailure(t *testing.T) {
	Convey("serve fails when the controller can't start", t, func() {
		listener, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only listener
		So(err, ShouldBeNil)

		defer listener.Close()

		_, port, err := net.SplitHostPort(listener.Addr().String())
		So(err, ShouldBeNil)

		defer signal.Reset()

		output := &bytes.Buffer{}

		select {
		case err := <-runServe(writeServeConfig(t, port), output):
			So(err, ShouldNotBeNil)
			// the error is reported, but it is not a command line error, so no usage is printed
			So(output.String(), ShouldContainSubstring, "address already in use")
			So(output.String(), ShouldNotContainSubstring, "Usage:")
		case <-time.After(30 * time.Second):
			t.Fatal("serve did not return")
		}
	})
}

func TestServeDrainsRequestsOnSIGTERM(t *testing.T) {
	Convey("SIGTERM lets in-flight requests finish before serve returns", t, func() {
		port := GetFreePort()
		baseURL := "http://127.0.0.1:" + port

		defer signal.Reset()

		served := runServe(writeServeConfig(t, port), io.Discard)
		So(waitForServer(baseURL+"/v2/", served), ShouldBeTrue)

		// a blob larger than the socket buffers, so the server is still writing it while the client waits
		blob := make([]byte, 32*1024*1024)
		_, err := rand.Read(blob)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes(blob)
		So(uploadBlob(baseURL, "repo", digest, blob), ShouldBeNil)

		conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", "127.0.0.1:"+port)
		So(err, ShouldBeNil)

		defer conn.Close()

		_, err = fmt.Fprintf(conn, "GET /v2/repo/blobs/%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", digest)
		So(err, ShouldBeNil)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil) //nolint:bodyclose // closed with conn
		So(err, ShouldBeNil)
		So(resp.StatusCode, ShouldEqual, http.StatusOK)

		// the client stops reading while the server is still writing the blob
		So(syscall.Kill(os.Getpid(), syscall.SIGTERM), ShouldBeNil)

		select {
		case err := <-served:
			t.Fatalf("serve returned while a request was in flight: %v", err)
		case <-time.After(time.Second):
		}

		body, err := io.ReadAll(resp.Body)
		So(err, ShouldBeNil)
		So(bytes.Equal(body, blob), ShouldBeTrue)

		select {
		case err := <-served:
			So(err, ShouldBeNil)
		case <-time.After(30 * time.Second):
			t.Fatal("serve did not return after the request finished")
		}
	})
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
