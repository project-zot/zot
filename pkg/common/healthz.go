package common

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log"
)

var errNotReady = errors.New("not ready yet")

type Healthz struct {
	Endpoint string
	Log      log.Logger
	ready    bool
}

func NewHealthzServer(appConfig *config.Config, logger log.Logger) *Healthz {
	var healthz Healthz
	healthz.ready = false
	healthz.Log = logger

	if appConfig.HTTP.HealthPort == "" {
		logger.Info().Msg("health port is not configured, not starting healthz server")

		return &healthz
	}
	healthz.Endpoint = fmt.Sprintf("%s:%s", appConfig.HTTP.Address, appConfig.HTTP.HealthPort)

	go healthz.Run()

	return &healthz
}

func (h *Healthz) livez(req *http.Request) error {
	return nil
}

func (h *Healthz) readyz(req *http.Request) error {
	return nil
}

func (h *Healthz) startupz(req *http.Request) error {
	if h.ready {
		return nil
	}

	return errNotReady
}

func (h *Healthz) Ready() {
	h.ready = true
	h.Log.Debug().Msg("startup completed")
}

func (h *Healthz) Run() {
	handler := &healthz.Handler{Checks: map[string]healthz.Checker{
		"livez":    h.livez,
		"readyz":   h.readyz,
		"startupz": h.startupz,
	}}

	server := &http.Server{
		Addr:         h.Endpoint,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		h.Log.Error().Err(err).Msg("failed to start healthz server")
	}
}
