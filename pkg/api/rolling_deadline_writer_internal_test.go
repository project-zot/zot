package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"zotregistry.dev/zot/v2/pkg/log"
)

// TestSetWriteDeadlineThroughStatusWriter verifies that http.ResponseController
// can reach the underlying connection's SetWriteDeadline through the
// statusWriter middleware wrapper (via Unwrap). Without this, the rolling
// write deadline for blob downloads silently degrades to the server's
// absolute WriteTimeout and multi-GB transfers get cut off mid-stream.
func TestSetWriteDeadlineThroughStatusWriter(t *testing.T) {
	deadlineErr := make(chan error, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		ctrl := http.NewResponseController(sw)
		deadlineErr <- ctrl.SetWriteDeadline(time.Now().Add(time.Minute))
		_, _ = sw.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if err := <-deadlineErr; err != nil {
		t.Fatalf("SetWriteDeadline through statusWriter failed: %v", err)
	}
}

// TestRollingDeadlineWriterPassthrough verifies that the rolling deadline
// writer forwards writes and supports flushing over a real connection.
func TestRollingDeadlineWriterPassthrough(t *testing.T) {
	wrapped := make(chan bool, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		rdw := newRollingDeadlineWriter(sw, time.Minute, log.NewTestLogger())

		// The deadline probe must succeed so the wrapper is actually used.
		_, isWrapped := rdw.(*rollingDeadlineWriter)
		wrapped <- isWrapped

		if _, err := rdw.Write([]byte("hello")); err != nil {
			t.Errorf("write failed: %v", err)
		}

		if flusher, ok := rdw.(http.Flusher); ok {
			flusher.Flush()
		} else {
			t.Error("rolling deadline writer does not implement http.Flusher")
		}
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(body) != "hello" {
		t.Fatalf("unexpected body: %q", string(body))
	}

	if !<-wrapped {
		t.Fatal("rolling deadline writer fell back to plain writer: deadline probe failed")
	}
}
