package api_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/ktls"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
)

// TestKTLSBlobGet runs blob GETs against a controller with http.tls.offload set.
// Without the tls kernel module every connection must fall back to userspace
// TLS; with it (or ZOT_KTLS_REQUIRE=1) HTTP/1.1 TLS 1.3 connections must be
// offloaded. Either way bodies, ranges, h2 and the plain-HTTP 400 must match
// what ServeTLS gives.
func TestKTLSBlobGet(t *testing.T) {
	Convey("blob GETs with kernel TLS offload requested", t, func() {
		_, serverCertPath, serverKeyPath, _, _, caCertPEM := setupTestCerts(t)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer resty.SetTLSClientConfig(nil)

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.HTTP.TLS = &config.TLSConfig{Cert: serverCertPath, Key: serverKeyPath, Offload: true}
		conf.Log.Level = "debug"
		conf.Log.Output = logPath

		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)
		secureBaseURL := cm.StartAndWait()

		defer cm.StopServer()

		const layerSize = 8<<20 + 4321

		img := CreateImageWith().RandomLayers(1, layerSize).DefaultConfig().Build()
		So(UploadImage(img, secureBaseURL, "ktls", "latest"), ShouldBeNil)

		layer := img.Layers[0]
		blobURL := fmt.Sprintf("%s/v2/ktls/blobs/%s", secureBaseURL, godigest.FromBytes(layer))

		newClient := func(forceH2 bool) *http.Client {
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: forceH2,
			}
			t.Cleanup(transport.CloseIdleConnections)

			return &http.Client{Transport: transport, Timeout: time.Minute}
		}

		// get returns the response fields the checks need; the body is already
		// read and closed.
		type getResult struct {
			status     int
			proto      string
			tlsVersion uint16
		}

		get := func(client *http.Client, rangeHeader string) (getResult, []byte) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, blobURL, nil)
			So(err, ShouldBeNil)

			if rangeHeader != "" {
				req.Header.Set("Range", rangeHeader)
			}

			resp, err := client.Do(req)
			So(err, ShouldBeNil)

			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)

			res := getResult{status: resp.StatusCode, proto: resp.Proto}
			if resp.TLS != nil {
				res.tlsVersion = resp.TLS.Version
			}

			return res, body
		}

		Convey("HTTP/1.1 whole blob and range", func() {
			client := newClient(false)

			resp, body := get(client, "")
			So(resp.status, ShouldEqual, http.StatusOK)
			So(resp.proto, ShouldEqual, "HTTP/1.1")
			So(resp.tlsVersion, ShouldEqual, tls.VersionTLS13)
			So(bytes.Equal(body, layer), ShouldBeTrue)

			const rangeStart, rangeEnd = 1<<20 + 3, 6<<20 + 11

			resp, body = get(client, "bytes="+strconv.Itoa(rangeStart)+"-"+strconv.Itoa(rangeEnd))
			So(resp.status, ShouldEqual, http.StatusPartialContent)
			So(bytes.Equal(body, layer[rangeStart:rangeEnd+1]), ShouldBeTrue)

			logs, err := os.ReadFile(logPath)
			So(err, ShouldBeNil)

			switch {
			case ktls.Available():
				So(string(logs), ShouldContainSubstring, "kernel TLS offload active")
			case os.Getenv("ZOT_KTLS_REQUIRE") == "1":
				t.Fatal("ZOT_KTLS_REQUIRE=1 but kTLS is unavailable (is the tls module loaded?)")
			default:
				So(string(logs), ShouldContainSubstring, "kernel TLS offload requested but unavailable")
				So(string(logs), ShouldNotContainSubstring, "kernel TLS offload active")
			}
		})

		Convey("h2 is still served", func() {
			resp, body := get(newClient(true), "")
			So(resp.status, ShouldEqual, http.StatusOK)
			So(resp.proto, ShouldEqual, "HTTP/2.0")
			So(bytes.Equal(body, layer), ShouldBeTrue)
		})

		Convey("plain HTTP to the HTTPS port gets 400", func() {
			baseURL := strings.Replace(secureBaseURL, "https://", "http://", 1)

			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})
	})
}
