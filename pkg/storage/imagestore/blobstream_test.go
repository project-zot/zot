//nolint:testpackage // Tests exercise the unexported newBlobStream/blobStream directly.
package imagestore

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errInjectedStreamClose = errors.New("injected close failure") //nolint:gochecknoglobals

type closeCountingReadCloser struct {
	io.Reader

	closeErr error
	closed   int
}

func (c *closeCountingReadCloser) Close() error {
	c.closed++

	return c.closeErr
}

func TestNewBlobStream(t *testing.T) {
	Convey("newBlobStream", t, func() {
		Convey("negative from is rejected", func() {
			_, err := newBlobStream(io.NopCloser(bytes.NewReader(nil)), -1, 4)
			So(err, ShouldNotBeNil)
		})

		Convey("to before from is rejected", func() {
			_, err := newBlobStream(io.NopCloser(bytes.NewReader(nil)), 5, 4)
			So(err, ShouldNotBeNil)
		})

		Convey("Read is limited to the requested range and Close delegates to the source", func() {
			underlying := &closeCountingReadCloser{Reader: bytes.NewReader([]byte("0123456789"))}

			stream, err := newBlobStream(underlying, 0, 4)
			So(err, ShouldBeNil)

			buf, err := io.ReadAll(stream)
			So(err, ShouldBeNil)

			// to-from+1 = 5 bytes, even though the underlying reader has 10.
			So(string(buf), ShouldEqual, "01234")

			So(stream.Close(), ShouldBeNil)
			So(underlying.closed, ShouldEqual, 1)
		})

		Convey("Close propagates the underlying error", func() {
			underlying := &closeCountingReadCloser{Reader: bytes.NewReader(nil), closeErr: errInjectedStreamClose}

			stream, err := newBlobStream(underlying, 0, 0)
			So(err, ShouldBeNil)

			err = stream.Close()
			So(errors.Is(err, errInjectedStreamClose), ShouldBeTrue)
		})
	})
}

func TestBlobStreamWriteTo(t *testing.T) {
	t.Parallel()

	underlying := &closeCountingReadCloser{Reader: strings.NewReader("0123456789")}
	stream, err := newBlobStream(underlying, 0, 4)
	require.NoError(t, err)
	defer stream.Close()

	// Read and WriteTo must share the same limit, even if a caller uses both.
	first := make([]byte, 2)
	_, err = io.ReadFull(stream, first)
	require.NoError(t, err)

	var body strings.Builder
	count, err := io.Copy(&body, stream)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
	assert.Equal(t, "234", body.String())
	assert.Zero(t, underlying.closed)

	remainder, err := io.ReadAll(underlying)
	require.NoError(t, err)
	assert.Equal(t, "56789", string(remainder))
}
