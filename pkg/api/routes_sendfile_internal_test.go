package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

type fileObservingListener struct {
	net.Listener

	sawFile *atomic.Bool
}

func (l fileObservingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return fileObservingConn{Conn: conn, sawFile: l.sawFile}, nil
}

type fileObservingConn struct {
	net.Conn

	sawFile *atomic.Bool
}

func (c fileObservingConn) ReadFrom(source io.Reader) (int64, error) {
	// net.TCPConn.ReadFrom recognizes syscall.Conn inside one LimitedReader.
	if limited, ok := source.(*io.LimitedReader); ok {
		if _, ok := limited.R.(syscall.Conn); ok {
			c.sawFile.Store(true)
		}
	}

	return io.Copy(c.Conn, source)
}

func TestBlobFileReachesTCPReadFrom(t *testing.T) {
	t.Parallel()

	content := strings.Repeat("0123456789", 4096)

	for _, test := range []struct {
		name        string
		rangeHeader string
		content     string
		wantBody    string
		wantRange   string
		wantStatus  int
		wantFile    bool
		tls         bool
	}{
		{name: "whole blob", content: content, wantBody: content, wantStatus: 200, wantFile: true},
		{
			name: "range", content: content, rangeHeader: "bytes=1234-12345", wantBody: content[1234:12346],
			wantRange: "bytes 1234-12345/40960", wantStatus: 206, wantFile: true,
		},
		{
			name: "small range", content: content, rangeHeader: "bytes=7-9", wantBody: content[7:10],
			wantRange: "bytes 7-9/40960", wantStatus: 206,
		},
		{name: "empty blob", wantStatus: 200},
		{name: "TLS whole blob", content: content, wantBody: content, wantStatus: 200, tls: true},
		{
			name: "TLS range", content: content, rangeHeader: "bytes=1234-12345", wantBody: content[1234:12346],
			wantRange: "bytes 1234-12345/40960", wantStatus: 206, tls: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			logger := log.NewTestLogger()
			metrics := monitoring.NewNopMetricServer()
			store := imagestore.NewImageStore(t.TempDir(), "", false, false, logger, metrics, nil,
				local.New(false), nil, nil, nil)
			digest := godigest.FromString(test.content)
			blobPath := store.BlobPath("repo", digest)
			require.NoError(t, os.MkdirAll(filepath.Dir(blobPath), 0o700))
			require.NoError(t, os.WriteFile(blobPath, []byte(test.content), 0o600))

			var logs bytes.Buffer
			controller := &Controller{
				Config: config.New(), Log: log.NewLoggerWithWriter("info", &logs), Metrics: metrics,
				StoreController: storage.StoreController{DefaultStore: store},
			}
			routes := &RouteHandler{c: controller}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				routes.GetBlob(w, mux.SetURLVars(r, map[string]string{"name": "repo", "digest": digest.String()}))
			})
			// Audit logging adds a second statusWriter. Both must preserve ReadFrom.
			logged := SessionLogger(controller)(SessionAuditLogger(&logger)(handler))
			done := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				logged.ServeHTTP(w, r)
			}))

			var sawFile atomic.Bool
			server.Listener = fileObservingListener{Listener: server.Listener, sawFile: &sawFile}
			if test.tls {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			if test.rangeHeader != "" {
				request.Header.Set("Range", test.rangeHeader)
			}
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, err := client.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, test.wantBody, string(body))
			assert.Equal(t, test.wantStatus, response.StatusCode)
			assert.Equal(t, strconv.Itoa(len(test.wantBody)), response.Header.Get("Content-Length"))
			assert.Equal(t, test.wantRange, response.Header.Get("Content-Range"))
			assert.Equal(t, digest.String(), response.Header.Get("Docker-Content-Digest"))
			assert.Equal(t, "application/octet-stream", response.Header.Get("Content-Type"))
			assert.Equal(t, test.wantFile, sawFile.Load())

			<-done // The session logger runs after the handler returns.

			var entry struct {
				StatusCode int `json:"statusCode"`
				BodySize   int `json:"bodySize"`
			}
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry))
			assert.Equal(t, test.wantStatus, entry.StatusCode)
			assert.Equal(t, len(test.wantBody), entry.BodySize)
		})
	}
}
