package errclass

import (
	"errors"
	"io"
)

// WrapReadCloser returns a ReadCloser that runs format on Read / Close errors.
// io.EOF is returned unchanged (normal end-of-stream). If format is nil, errors
// are returned as-is.
func WrapReadCloser(inner io.ReadCloser, format func(error) error) io.ReadCloser {
	if inner == nil {
		return nil
	}

	return &readCloser{inner: inner, format: format}
}

type readCloser struct {
	inner  io.ReadCloser
	format func(error) error
}

func (r *readCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}

	return n, r.classify(err)
}

func (r *readCloser) Close() error {
	return r.classify(r.inner.Close())
}

func (r *readCloser) classify(err error) error {
	if err == nil {
		return nil
	}

	if r.format != nil {
		return r.format(err)
	}

	return err
}
