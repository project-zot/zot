//go:build sync

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatusWriterUnwrap: http.ResponseController reaches the wrapped writer's Flush through
// statusWriter, which has no Flush of its own.
func TestStatusWriterUnwrap(t *testing.T) {
	t.Parallel()

	inner := httptest.NewRecorder()
	writer := &statusWriter{ResponseWriter: inner}

	require.Same(t, inner, writer.Unwrap())

	require.NoError(t, http.NewResponseController(writer).Flush())
	assert.True(t, inner.Flushed)
}
