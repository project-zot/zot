//go:build mgmt
// +build mgmt

package extensions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
)

func TestMgmtErrors(t *testing.T) {
	Convey("Trigger mgmt errors", t, func() {
		config := config.New()
		mgmtHandler := mgmtHandler{
			config: config,
			log:    log.NewLogger("debug", ""),
		}

		request, err := http.NewRequestWithContext(context.Background(),
			http.MethodGet,
			"",
			nil)
		So(err, ShouldBeNil)

		response := httptest.NewRecorder()

		Convey("Trigger mgmt missing port error", func() {
			request.RemoteAddr = "100.100.100.100"
			mgmtHandler.getAuthInfo(response, request)
			resp := response.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("Trigger mgmt non local request error", func() {
			request.RemoteAddr = "100.100.100.100:9999"
			mgmtHandler.getAuthInfo(response, request)
			resp := response.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Trigger mgmt invalid ip error", func() {
			request.RemoteAddr = "invalidip:9999"
			mgmtHandler.getAuthInfo(response, request)
			resp := response.Result()
			defer resp.Body.Close()
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})
	})
}
