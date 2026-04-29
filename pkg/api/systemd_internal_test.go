//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-systemd/v22/daemon"

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

	originalNotify := systemdNotify
	t.Cleanup(func() {
		systemdNotify = originalNotify
	})

	var gotState string
	var gotUnsetEnvironment bool
	systemdNotify = func(unsetEnvironment bool, state string) (bool, error) {
		gotUnsetEnvironment = unsetEnvironment
		gotState = state

		return true, nil
	}

	ctlr.markReady()

	if gotUnsetEnvironment {
		t.Fatal("expected systemd notify environment to remain set")
	}

	if gotState != daemon.SdNotifyReady {
		t.Fatalf("expected systemd ready notification, got %q", gotState)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	ctlr.Healthz.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected readyz to return 200, got %d", response.Code)
	}
}
