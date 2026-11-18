package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type readFromRecorder struct {
	*httptest.ResponseRecorder

	source io.Reader
	count  int64
	err    error
}

func (r *readFromRecorder) ReadFrom(source io.Reader) (int64, error) {
	r.source = source

	return r.count, r.err
}

func TestStatusWriterReadFrom(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		status     int
		count      int64
		err        error
		wantStatus int
	}{
		{name: "implicit 200", count: 4, wantStatus: http.StatusOK},
		{name: "partial copy", count: 4, err: io.ErrClosedPipe, wantStatus: http.StatusOK},
		{name: "empty"},
		{name: "error before bytes", err: io.ErrClosedPipe},
		{name: "explicit 206", status: http.StatusPartialContent, count: 4, wantStatus: http.StatusPartialContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inner := &readFromRecorder{ResponseRecorder: httptest.NewRecorder(), count: test.count, err: test.err}
			writer := &statusWriter{ResponseWriter: inner}
			if test.status != 0 {
				writer.WriteHeader(test.status)
			}

			source := strings.NewReader("body")
			count, err := writer.ReadFrom(source)
			assert.Equal(t, test.count, count)
			require.ErrorIs(t, err, test.err)
			assert.Same(t, source, inner.source)
			assert.Equal(t, int(test.count), writer.length)
			assert.Equal(t, test.wantStatus, writer.status)
			if test.wantStatus == 0 {
				// No bytes reached the response. The handler can still send an error or 204.
				writer.WriteHeader(http.StatusNoContent)
				assert.Equal(t, http.StatusNoContent, inner.Code)
			}
		})
	}
}

func TestStatusWriterReadFromFallback(t *testing.T) {
	t.Parallel()

	inner := httptest.NewRecorder()
	writer := &statusWriter{ResponseWriter: inner}
	writer.WriteHeader(http.StatusPartialContent)

	count, err := writer.ReadFrom(strings.NewReader("body"))
	require.NoError(t, err)
	assert.Equal(t, int64(4), count)
	assert.Equal(t, 4, writer.length)
	assert.Equal(t, http.StatusPartialContent, writer.status)
	assert.Equal(t, "body", inner.Body.String())
}
