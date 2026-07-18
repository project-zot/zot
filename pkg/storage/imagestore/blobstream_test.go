//nolint:testpackage // Tests exercise the unexported newBlobStream/blobStream directly.
package imagestore

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

var errInjectedStreamClose = errors.New("injected close failure")

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
	t.Run("negative from is rejected", func(t *testing.T) {
		if _, err := newBlobStream(io.NopCloser(bytes.NewReader(nil)), -1, 4); err == nil {
			t.Fatal("expected an error for negative from")
		}
	})

	t.Run("to before from is rejected", func(t *testing.T) {
		if _, err := newBlobStream(io.NopCloser(bytes.NewReader(nil)), 5, 4); err == nil {
			t.Fatal("expected an error for to < from")
		}
	})

	t.Run("Read is limited to the requested range and Close delegates to the source", func(t *testing.T) {
		underlying := &closeCountingReadCloser{Reader: bytes.NewReader([]byte("0123456789"))}

		stream, err := newBlobStream(underlying, 0, 4)
		if err != nil {
			t.Fatalf("newBlobStream: %v", err)
		}

		buf, err := io.ReadAll(stream)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}

		// to-from+1 = 5 bytes, even though the underlying reader has 10.
		if string(buf) != "01234" {
			t.Fatalf("expected \"01234\", got %q", buf)
		}

		if err := stream.Close(); !errors.Is(err, nil) {
			t.Fatalf("expected nil error, got %v", err)
		}

		if underlying.closed != 1 {
			t.Fatalf("expected Close to delegate to the underlying reader once, got %d", underlying.closed)
		}
	})

	t.Run("Close propagates the underlying error", func(t *testing.T) {
		underlying := &closeCountingReadCloser{Reader: bytes.NewReader(nil), closeErr: errInjectedStreamClose}

		stream, err := newBlobStream(underlying, 0, 0)
		if err != nil {
			t.Fatalf("newBlobStream: %v", err)
		}

		if err := stream.Close(); !errors.Is(err, errInjectedStreamClose) {
			t.Fatalf("expected injected close error, got %v", err)
		}
	})
}
