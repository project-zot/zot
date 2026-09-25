package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/stretchr/testify/assert"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestMarkReadyNotifiesSystemd(t *testing.T) {
	logger := log.NewLogger("debug", "")
	ctlr := &Controller{
		Healthz: common.NewHealthzServer(config.New(), logger),
		Log:     logger,
	}

	var gotState string
	var gotUnsetEnvironment bool

	ctlr.sdNotify = func(unsetEnvironment bool, state string) (bool, error) {
		gotUnsetEnvironment = unsetEnvironment
		gotState = state

		return true, nil
	}

	ctlr.markReady()

	assert.False(t, gotUnsetEnvironment, "expected systemd notify environment to remain set")
	assert.Equal(t, daemon.SdNotifyReady, gotState)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	ctlr.Healthz.Handler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
}

func TestNotifySystemdStopping(t *testing.T) {
	logger := log.NewLogger("debug", "")
	ctlr := &Controller{Log: logger}

	var gotState string

	ctlr.sdNotify = func(_ bool, state string) (bool, error) {
		gotState = state

		return true, nil
	}

	ctlr.notifySystemdStopping()

	assert.Equal(t, daemon.SdNotifyStopping, gotState)
}

func TestNotifySystemdLogsOnError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.NewLoggerWithWriter("debug", &logBuf)
	ctlr := &Controller{Log: logger}

	ctlr.sdNotify = func(_ bool, _ string) (bool, error) {
		return false, errors.New("notify failed")
	}

	assert.NotPanics(t, func() {
		ctlr.notifySystemd(daemon.SdNotifyReady)
	})

	logged := logBuf.String()
	assert.Contains(t, logged, "failed to notify systemd")
	assert.Contains(t, logged, "notify failed")
	assert.Contains(t, logged, daemon.SdNotifyReady)
}
