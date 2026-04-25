//go:build !metrics

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
)

func TestMetricsHandlerForwardsAuthorizationToZot(t *testing.T) {
	const authHeader = "Basic b2JzZXJ2YWJpbGl0eTpwYXNzd29yZA=="

	receivedAuth := make(chan string, 1)
	zotServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth <- r.Header.Get(authorization)

		if r.Header.Get(authorization) != authHeader {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(&monitoring.MetricsInfo{
			Gauges: []*monitoring.GaugeValue{
				{Name: "zot.scheduler.workers.total", Value: 7},
			},
		})
	}))
	defer zotServer.Close()

	config := DefaultConfig()
	setTestServerAddress(t, config, zotServer.URL)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set(authorization, authHeader)

	recorder := httptest.NewRecorder()
	metricsHandler(NewController(config)).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}

	if got := <-receivedAuth; got != authHeader {
		t.Fatalf("expected Authorization header %q, got %q", authHeader, got)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "zot_up 1") {
		t.Fatalf("expected successful zot scrape in body:\n%s", body)
	}

	if !strings.Contains(body, "zot_scheduler_workers_total 7") {
		t.Fatalf("expected zot metrics in body:\n%s", body)
	}
}

func setTestServerAddress(t *testing.T, config *Config, rawURL string) {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	host, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("failed to split test server host/port: %v", err)
	}

	config.Server.Protocol = parsedURL.Scheme
	config.Server.Host = host
	config.Server.Port = port
}
