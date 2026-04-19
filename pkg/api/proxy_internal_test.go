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

		var gotBody string
		var gotHopCount string

		backend := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			body, err := io.ReadAll(request.Body)
			So(err, ShouldBeNil)

			gotBody = string(body)
			gotHopCount = request.Header.Get(constants.ScaleOutHopCountHeader)

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
			"http://example.com/v2/repo/manifests/latest", io.NopCloser(strings.NewReader(requestPayload)))
		So(err, ShouldBeNil)

		resp, err := proxyHTTPRequest(context.Background(), req, backendURL.Host, ctrlr)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		So(err, ShouldBeNil)

		remainingReqBody, err := io.ReadAll(req.Body)
		So(err, ShouldBeNil)

		So(resp.StatusCode, ShouldEqual, http.StatusCreated)
		So(string(respBody), ShouldEqual, responsePayload)
		So(gotBody, ShouldEqual, requestPayload)
		So(gotHopCount, ShouldEqual, "1")
		So(len(remainingReqBody), ShouldEqual, 0)
	})
}
