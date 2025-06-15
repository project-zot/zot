package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPQueryEndpoint(t *testing.T) {
	handler := NewMCPServer()
	req := httptest.NewRequest(http.MethodPost, "/mcp/query", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 200 or 400, got %d", rec.Code)
	}
}

func TestMCPPlaygroundEndpoint(t *testing.T) {
	handler := NewMCPServer()
	req := httptest.NewRequest(http.MethodGet, "/mcp/playground", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("expected Content-Type header to be set")
	}
}
