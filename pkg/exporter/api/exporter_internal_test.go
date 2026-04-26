//go:build !metrics

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
)

func TestMetricsHandlerForwardsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	const authorizationHeader = "Basic b2JzZXJ2YWJpbGl0eTpwYXNzd29yZA=="

	var forwardedAuthorization atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authorizationHeader {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`))

			return
		}

		forwardedAuthorization.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Counters":[],"Gauges":[],"Summaries":[],"Histograms":[]}`))
	}))
	defer server.Close()

	controller := NewController(DefaultConfig())
	collector := GetCollector(controller)
	collector.Client = monitoring.NewMetricsClient(
		&monitoring.MetricsConfig{Address: server.URL, HTTPClient: server.Client()},
		controller.Log,
	)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", authorizationHeader)
	response := httptest.NewRecorder()

	newMetricsHandler(collector).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from exporter, got %d with body: %s", response.Code, response.Body.String())
	}

	if !forwardedAuthorization.Load() {
		t.Fatal("expected exporter to forward Authorization header to zot metrics endpoint")
	}

	if !strings.Contains(response.Body.String(), "zot_up 1") {
		t.Fatalf("expected successful zot scrape in exporter metrics, got body: %s", response.Body.String())
	}
}

func TestMetricsHandlerReportsZotDownWithoutAuthorizationHeader(t *testing.T) {
	t.Parallel()

	const authorizationHeader = "Basic b2JzZXJ2YWJpbGl0eTpwYXNzd29yZA=="

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authorizationHeader {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`))

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Counters":[],"Gauges":[],"Summaries":[],"Histograms":[]}`))
	}))
	defer server.Close()

	controller := NewController(DefaultConfig())
	collector := GetCollector(controller)
	collector.Client = monitoring.NewMetricsClient(
		&monitoring.MetricsConfig{Address: server.URL, HTTPClient: server.Client()},
		controller.Log,
	)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()

	newMetricsHandler(collector).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from exporter, got %d with body: %s", response.Code, response.Body.String())
	}

	if !strings.Contains(response.Body.String(), "zot_up 0") {
		t.Fatalf("expected failed zot scrape in exporter metrics, got body: %s", response.Body.String())
	}
}
