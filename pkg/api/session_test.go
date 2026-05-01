package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zotapi "zotregistry.dev/zot/v2/pkg/api"
	monitoring "zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

func TestSessionAuditLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method      string
		status      int
		setUsername string
		wantAudit   bool
		wantSubject string
	}{
		{
			name:        "mutating POST 200 anonymous",
			method:      http.MethodPost,
			status:      http.StatusOK,
			wantAudit:   true,
			wantSubject: "anonymous",
		},
		{
			name:        "mutating PUT 201 authenticated",
			method:      http.MethodPut,
			status:      http.StatusCreated,
			setUsername: "alice",
			wantAudit:   true,
			wantSubject: "alice",
		},
		{
			name:        "mutating PATCH 202 anonymous",
			method:      http.MethodPatch,
			status:      http.StatusAccepted,
			wantAudit:   true,
			wantSubject: "anonymous",
		},
		{
			name:        "mutating DELETE 200 anonymous",
			method:      http.MethodDelete,
			status:      http.StatusOK,
			wantAudit:   true,
			wantSubject: "anonymous",
		},
		{
			name:      "GET 200 skipped",
			method:    http.MethodGet,
			status:    http.StatusOK,
			wantAudit: false,
		},
		{
			name:        "POST 401 skipped",
			method:      http.MethodPost,
			status:      http.StatusUnauthorized,
			wantAudit:   false,
			wantSubject: "",
		},
		{
			name:        "POST 403 skipped even with username",
			method:      http.MethodPost,
			status:      http.StatusForbidden,
			setUsername: "bob",
			wantAudit:   false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			auditPath := filepath.Join(t.TempDir(), "audit.log")
			audit := log.NewAuditLogger("info", auditPath)

			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if testCase.setUsername != "" {
					uac := reqCtx.NewUserAccessControl()
					uac.SetUsername(testCase.setUsername)
					uac.SaveOnRequest(r)
				}

				w.WriteHeader(testCase.status)
			})

			wrapped := zotapi.SessionAuditLogger(audit)(inner)

			req := httptest.NewRequest(testCase.method, "/v2/repo/test/uploads", http.NoBody)
			req.RemoteAddr = "127.0.0.1:12345"

			recorder := httptest.NewRecorder()
			wrapped.ServeHTTP(recorder, req)

			data, err := os.ReadFile(auditPath)
			require.NoError(t, err)

			if !testCase.wantAudit {
				assert.Empty(t, strings.TrimSpace(string(data)))

				return
			}

			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			require.Len(t, lines, 1)

			var payload map[string]any
			require.NoError(t, json.Unmarshal(lines[0], &payload))

			statusVal, ok := payload["status"].(float64)
			require.True(t, ok, "JSON status should decode as float64")

			assert.Equal(t, "HTTP API Audit", payload["message"])
			assert.Equal(t, testCase.wantSubject, payload["subject"])
			assert.Equal(t, testCase.method, payload["action"])
			assert.InDelta(t, float64(testCase.status), statusVal, 0)
			assert.Equal(t, "session", payload["component"])
			assert.Equal(t, "127.0.0.1:12345", payload["clientIP"])
			assert.Equal(t, "/v2/repo/test/uploads", payload["object"])
		})
	}
}

func TestSessionAuditLogger_rawQueryAppendedToObject(t *testing.T) {
	t.Parallel()

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit := log.NewAuditLogger("info", auditPath)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	wrapped := zotapi.SessionAuditLogger(audit)(inner)

	req := httptest.NewRequest(http.MethodPost, "/v2/a/b", http.NoBody)
	req.URL.RawQuery = "digest=sha256:abc"

	recorder := httptest.NewRecorder()
	wrapped.ServeHTTP(recorder, req)

	data, err := os.ReadFile(auditPath)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(data), &payload))

	assert.Equal(t, "/v2/a/b?digest=sha256:abc", payload["object"])
}

func TestSessionLogger_redactsAuthorizationAndLogsUsernameFromContext(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	ctlr := &zotapi.Controller{
		Log:     log.NewLoggerWithWriter("info", &buf),
		Metrics: monitoring.NewMetricsServer(false, log.NewTestLogger()),
	}
	t.Cleanup(ctlr.Metrics.Stop)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uac := reqCtx.NewUserAccessControl()
		uac.SetUsername("alice")
		uac.SaveOnRequest(r)

		w.WriteHeader(http.StatusOK)

		_, _ = w.Write([]byte("ok"))
	})

	wrapped := zotapi.SessionLogger(ctlr)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", http.NoBody)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.RemoteAddr = "10.0.0.1:4444"

	recorder := httptest.NewRecorder()
	wrapped.ServeHTTP(recorder, req)

	out := buf.String()

	assert.Contains(t, out, `"message":"HTTP API"`)
	assert.Contains(t, out, `"username":"alice"`)
	assert.Contains(t, out, `"Authorization":["******"]`)
	assert.NotContains(t, out, "super-secret-token")
}

func TestSessionLogger_omitsUsernameWhenAnonymous(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	ctlr := &zotapi.Controller{
		Log:     log.NewLoggerWithWriter("info", &buf),
		Metrics: monitoring.NewMetricsServer(false, log.NewTestLogger()),
	}
	t.Cleanup(ctlr.Metrics.Stop)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	wrapped := zotapi.SessionLogger(ctlr)(inner)

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", http.NoBody)

	recorder := httptest.NewRecorder()
	wrapped.ServeHTTP(recorder, req)

	out := buf.String()

	assert.Contains(t, out, `"message":"HTTP API"`)
	assert.NotContains(t, out, `"username"`)
}
