package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusWriterRejectedCopyStatus(t *testing.T) {
	t.Parallel()

	done := make(chan *statusWriter, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writer := &statusWriter{ResponseWriter: &statusWriter{ResponseWriter: w}}
		writer.Header().Set("Content-Length", "1")
		// Hide WriterTo so io.Copy uses ReadFrom when the writer provides it.
		count, err := io.Copy(writer, struct{ io.Reader }{strings.NewReader("body")})
		assert.Zero(t, count)
		assert.ErrorIs(t, err, http.ErrContentLength)
		done <- writer
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Empty(t, body)

	writer := <-done
	assert.Equal(t, response.StatusCode, writer.status)
	assert.Zero(t, writer.length)
	inner, ok := writer.ResponseWriter.(*statusWriter)
	require.True(t, ok)
	assert.Equal(t, response.StatusCode, inner.status)
	assert.Zero(t, inner.length)
}
