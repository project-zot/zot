package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cluster"
	zlog "zotregistry.dev/zot/v2/pkg/log"
)

func TestClusterProxyRejectsAlreadyProxiedRequest(t *testing.T) {
	Convey("ClusterProxy rejects an already-proxied request without calling the handler", t, func() {
		conf := config.New()
		conf.Cluster = &config.ClusterConfig{
			Members: []string{"127.0.0.1:9000", "127.0.0.1:9001"},
			HashKey: "loremipsumdolors",
			Proxy: &config.ClusterRequestProxyConfig{
				LocalMemberClusterSocketIndex: 0,
			},
		}

		name := ""
		for _, candidate := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			targetMemberIndex, _ := cluster.ComputeTargetMember(conf.Cluster.HashKey, conf.Cluster.Members, candidate)
			if targetMemberIndex != conf.Cluster.Proxy.LocalMemberClusterSocketIndex {
				name = candidate

				break
			}
		}
		So(name, ShouldNotBeEmpty)

		handlerCalled := false
		ctrlr := &Controller{Config: conf, Log: zlog.NewTestLogger()}
		handler := ClusterProxy(ctrlr)(func(response http.ResponseWriter, request *http.Request) {
			handlerCalled = true
			response.WriteHeader(http.StatusOK)
		})

		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v2/"+name+"/tags/list", nil)
		request = mux.SetURLVars(request, map[string]string{"name": name})
		request.Header.Set(constants.ScaleOutHopCountHeader, "1")
		response := httptest.NewRecorder()

		handler(response, request)

		So(response.Code, ShouldEqual, http.StatusLoopDetected)
		So(handlerCalled, ShouldBeFalse)
	})
}

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
