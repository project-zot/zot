package common

import (
	"errors"
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

var errNotReady = errors.New("not ready yet")

type Healthz struct {
	log     log.Logger
	ready   bool
	started bool
	Handler *healthz.Handler
}

func NewHealthzServer(appConfig *config.Config, logger log.Logger) *Healthz {
	var health Healthz
	health.ready = false
	health.started = false
	health.log = logger
	health.Handler = &healthz.Handler{Checks: map[string]healthz.Checker{
		"livez":    health.livez,
		"readyz":   health.readyz,
		"startupz": health.startupz,
	}}

	return &health
}

func (h *Healthz) livez(req *http.Request) error {
	return nil
}

func (h *Healthz) readyz(req *http.Request) error {
	if h.ready {
		return nil
	}

	return errNotReady
}

func (h *Healthz) startupz(req *http.Request) error {
	if h.started {
		return nil
	}

	return errNotReady
}

func (h *Healthz) Ready() {
	h.ready = true
	h.log.Debug().Msg("ready")
}

func (h *Healthz) Started() {
	h.started = true
	h.log.Debug().Msg("started")
}
