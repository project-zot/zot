package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
)

func TestProxyHTTPRequestStreamsBodyAndResponse(t *testing.T) {
	Convey("proxyHTTPRequest forwards request body/headers and returns streamed response", t, func() {
		requestPayload := strings.Repeat("payload-", 1024)
		responsePayload := strings.Repeat("response-", 2048)

		type backendResult struct {
			body     string
			hopCount string
			err      error
		}

		resultCh := make(chan backendResult, 1)

		backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			body, err := io.ReadAll(request.Body)
			resultCh <- backendResult{
				body:     string(body),
				hopCount: request.Header.Get(constants.ScaleOutHopCountHeader),
				err:      err,
			}

			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, responsePayload)
		}))
		defer backend.Close()

		backendURL, err := url.Parse(backend.URL)
		So(err, ShouldBeNil)

		conf := config.New()
		conf.Cluster = &config.ClusterConfig{Members: []string{backendURL.Host}, HashKey: "loremipsumdolors"}

		ctrlr := &Controller{Config: conf}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
			"http://example.com/v2/repo/manifests/latest", strings.NewReader(requestPayload))
		So(err, ShouldBeNil)

		resp, err := proxyHTTPRequest(context.Background(), req, backendURL.Host, ctrlr)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		So(err, ShouldBeNil)

		result := <-resultCh
		So(result.err, ShouldBeNil)

		remainingReqBody, err := io.ReadAll(req.Body)
		So(err, ShouldBeNil)

		So(resp.StatusCode, ShouldEqual, http.StatusCreated)
		So(string(respBody), ShouldEqual, responsePayload)
		So(result.body, ShouldEqual, requestPayload)
		So(result.hopCount, ShouldEqual, "1")
		So(len(remainingReqBody), ShouldEqual, 0)
	})
}

func TestProxyHTTPRequestPreservesExplicitEmptyBody(t *testing.T) {
	Convey("proxyHTTPRequest preserves explicit zero-length request bodies", t, func() {
		resultCh := make(chan *http.Request, 1)

		backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resultCh <- request
			response.WriteHeader(http.StatusNoContent)
		}))
		defer backend.Close()

		backendURL, err := url.Parse(backend.URL)
		So(err, ShouldBeNil)

		conf := config.New()
		conf.Cluster = &config.ClusterConfig{Members: []string{backendURL.Host}, HashKey: "loremipsumdolors"}

		ctrlr := &Controller{Config: conf}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://example.com/v2/repo/manifests/latest", http.NoBody)
		So(err, ShouldBeNil)
		So(req.ContentLength, ShouldEqual, 0)

		resp, err := proxyHTTPRequest(context.Background(), req, backendURL.Host, ctrlr)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		defer resp.Body.Close()

		backendReq := <-resultCh

		So(resp.StatusCode, ShouldEqual, http.StatusNoContent)
		So(backendReq.ContentLength, ShouldEqual, 0)
		So(backendReq.Body, ShouldEqual, http.NoBody)
		So(backendReq.TransferEncoding, ShouldBeEmpty)
	})
}
