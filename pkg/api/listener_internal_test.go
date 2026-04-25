//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui

package api

import (
	"net"
	"strings"
	"testing"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestCreateListenerUsesSystemdActivation(t *testing.T) {
	activatedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create activated listener: %v", err)
	}

	originalActivationListeners := systemdActivationListeners
	t.Cleanup(func() {
		systemdActivationListeners = originalActivationListeners
	})

	systemdActivationListeners = func() ([]net.Listener, error) {
		return []net.Listener{activatedListener}, nil
	}

	conf := config.New()
	conf.HTTP.Port = "1"
	ctlr := &Controller{
		Config: conf,
		Log:    log.NewLogger("debug", ""),
	}

	listener, addr, err := ctlr.createListener("127.0.0.1:1", conf.GetHTTPPort())
	if err != nil {
		t.Fatalf("unexpected create listener error: %v", err)
	}
	defer listener.Close()

	wantPort := activatedListener.Addr().(*net.TCPAddr).Port
	if ctlr.GetPort() != wantPort {
		t.Fatalf("expected chosen port %d, got %d", wantPort, ctlr.GetPort())
	}

	if addr != activatedListener.Addr().String() {
		t.Fatalf("expected server address %q, got %q", activatedListener.Addr().String(), addr)
	}
}

func TestCreateListenerRejectsMultipleSystemdActivationListeners(t *testing.T) {
	firstListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create first listener: %v", err)
	}
	defer firstListener.Close()

	secondListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create second listener: %v", err)
	}
	defer secondListener.Close()

	originalActivationListeners := systemdActivationListeners
	t.Cleanup(func() {
		systemdActivationListeners = originalActivationListeners
	})

	systemdActivationListeners = func() ([]net.Listener, error) {
		return []net.Listener{firstListener, secondListener}, nil
	}

	conf := config.New()
	ctlr := &Controller{
		Config: conf,
		Log:    log.NewLogger("debug", ""),
	}

	_, _, err = ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
	if err == nil {
		t.Fatal("expected multiple systemd listeners to fail")
	}

	if !strings.Contains(err.Error(), "expected exactly one systemd socket activation listener") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateListenerFallsBackToConfiguredAddress(t *testing.T) {
	originalActivationListeners := systemdActivationListeners
	t.Cleanup(func() {
		systemdActivationListeners = originalActivationListeners
	})

	systemdActivationListeners = func() ([]net.Listener, error) {
		return nil, nil
	}

	conf := config.New()
	conf.HTTP.Port = "0"
	ctlr := &Controller{
		Config: conf,
		Log:    log.NewLogger("debug", ""),
	}

	listener, addr, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
	if err != nil {
		t.Fatalf("unexpected create listener error: %v", err)
	}
	defer listener.Close()

	if ctlr.GetPort() <= 0 {
		t.Fatalf("expected chosen port to be set, got %d", ctlr.GetPort())
	}

	if addr != "127.0.0.1:0" {
		t.Fatalf("expected configured server address, got %q", addr)
	}
}
