package errclass

import (
	"context"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
)

// WrapFileWriter returns a FileWriter that runs format on Write / Close / Cancel /
// Commit errors. Size is passed through unchanged. If format is nil, errors are
// returned as-is (useful in tests).
//
// format (typically a driver formatErr) is responsible for leaving FileWriter
// lifecycle errors unclassified — see IsWriterLifecycleError.
func WrapFileWriter(inner storagedriver.FileWriter, format func(error) error) storagedriver.FileWriter {
	if inner == nil {
		return nil
	}

	return &fileWriter{inner: inner, format: format}
}

type fileWriter struct {
	inner  storagedriver.FileWriter
	format func(error) error
}

func (w *fileWriter) Write(p []byte) (int, error) {
	n, err := w.inner.Write(p)

	return n, w.classify(err)
}

func (w *fileWriter) Size() int64 {
	return w.inner.Size()
}

func (w *fileWriter) Close() error {
	return w.classify(w.inner.Close())
}

func (w *fileWriter) Cancel(ctx context.Context) error {
	return w.classify(w.inner.Cancel(ctx))
}

func (w *fileWriter) Commit(ctx context.Context) error {
	return w.classify(w.inner.Commit(ctx))
}

func (w *fileWriter) classify(err error) error {
	if err == nil {
		return nil
	}

	if w.format != nil {
		return w.format(err)
	}

	return err
}
