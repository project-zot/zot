package mocks

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
)

type StorageDriverMock struct {
	NameFn        func() string
	GetContentFn  func(ctx context.Context, path string) ([]byte, error)
	PutContentFn  func(ctx context.Context, path string, content []byte) error
	ReaderFn      func(ctx context.Context, path string, offset int64) (io.ReadCloser, error)
	WriterFn      func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error)
	StatFn        func(ctx context.Context, path string) (driver.FileInfo, error)
	ListFn        func(ctx context.Context, path string) ([]string, error)
	MoveFn        func(ctx context.Context, sourcePath, destPath string) error
	DeleteFn      func(ctx context.Context, path string) error
	WalkFn        func(ctx context.Context, path string, f driver.WalkFn, options ...func(*driver.WalkOptions)) error
	RedirectURLFn func(r *http.Request, path string) (string, error)
}

//nolint:gochecknoglobals
var (
	fileWriterSize = 12
	fileInfoSize   = 10
)

func (s *StorageDriverMock) Name() string {
	if s != nil && s.NameFn != nil {
		return s.NameFn()
	}

	return ""
}

func (s *StorageDriverMock) GetContent(ctx context.Context, path string) ([]byte, error) {
	if s != nil && s.GetContentFn != nil {
		return s.GetContentFn(ctx, path)
	}

	return []byte{}, nil
}

func (s *StorageDriverMock) PutContent(ctx context.Context, path string, content []byte) error {
	if s != nil && s.PutContentFn != nil {
		return s.PutContentFn(ctx, path, content)
	}

	return nil
}

func (s *StorageDriverMock) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	if s != nil && s.ReaderFn != nil {
		return s.ReaderFn(ctx, path, offset)
	}

	return io.NopCloser(strings.NewReader("")), nil
}

func (s *StorageDriverMock) Writer(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
	if s != nil && s.WriterFn != nil {
		return s.WriterFn(ctx, path, isAppend)
	}

	return &FileWriterMock{}, nil
}

func (s *StorageDriverMock) Stat(ctx context.Context, path string) (driver.FileInfo, error) {
	if s != nil && s.StatFn != nil {
		return s.StatFn(ctx, path)
	}

	return &FileInfoMock{}, nil
}

func (s *StorageDriverMock) List(ctx context.Context, path string) ([]string, error) {
	if s != nil && s.ListFn != nil {
		return s.ListFn(ctx, path)
	}

	return []string{"a"}, nil
}

func (s *StorageDriverMock) Move(ctx context.Context, sourcePath, destPath string) error {
	if s != nil && s.MoveFn != nil {
		return s.MoveFn(ctx, sourcePath, destPath)
	}

	return nil
}

func (s *StorageDriverMock) Delete(ctx context.Context, path string) error {
	if s != nil && s.DeleteFn != nil {
		return s.DeleteFn(ctx, path)
	}

	return nil
}

func (s *StorageDriverMock) RedirectURL(r *http.Request, path string) (string, error) {
	if s != nil && s.RedirectURLFn != nil {
		return s.RedirectURLFn(r, path)
	}

	return "", nil
}

func (s *StorageDriverMock) URLFor(ctx context.Context, path string, options map[string]any) (string, error) {
	return "", nil
}

func (s *StorageDriverMock) Walk(ctx context.Context, path string, f driver.WalkFn,
	options ...func(*driver.WalkOptions),
) error {
	if s != nil && s.WalkFn != nil {
		return s.WalkFn(ctx, path, f, options...)
	}

	return nil
}

type FileInfoMock struct {
	IsDirFn func() bool
	SizeFn  func() int64
	PathFn  func() string
}

func (f *FileInfoMock) Path() string {
	if f != nil && f.PathFn != nil {
		return f.PathFn()
	}

	return ""
}

func (f *FileInfoMock) Size() int64 {
	if f != nil && f.SizeFn != nil {
		return f.SizeFn()
	}

	return int64(fileInfoSize)
}

func (f *FileInfoMock) ModTime() time.Time {
	return time.Now()
}

func (f *FileInfoMock) IsDir() bool {
	if f != nil && f.IsDirFn != nil {
		return f.IsDirFn()
	}

	return true
}

type FileWriterMock struct {
	WriteFn  func([]byte) (int, error)
	CancelFn func() error
	CommitFn func() error
	CloseFn  func() error
}

func (f *FileWriterMock) Size() int64 {
	return int64(fileWriterSize)
}

func (f *FileWriterMock) Cancel(_ context.Context) error {
	if f != nil && f.CancelFn != nil {
		return f.CancelFn()
	}

	return nil
}

func (f *FileWriterMock) Commit(_ context.Context) error {
	if f != nil && f.CommitFn != nil {
		return f.CommitFn()
	}

	return nil
}

func (f *FileWriterMock) Write(p []byte) (int, error) {
	if f != nil && f.WriteFn != nil {
		return f.WriteFn(p)
	}

	return 10, nil
}

func (f *FileWriterMock) Close() error {
	if f != nil && f.CloseFn != nil {
		return f.CloseFn()
	}

	return nil
}
