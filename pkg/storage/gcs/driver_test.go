package gcs_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errTest = errors.New("error")

type fileInfoMock struct {
	isDir   bool
	size    int64
	modTime time.Time
	path    string
}

func (f *fileInfoMock) Path() string       { return f.path }
func (f *fileInfoMock) Size() int64        { return f.size }
func (f *fileInfoMock) ModTime() time.Time { return f.modTime }
func (f *fileInfoMock) IsDir() bool        { return f.isDir }

func TestDriver(t *testing.T) {
	Convey("GCS Driver", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		gcsDriver := gcs.New(storeMock)

		Convey("Name", func() {
			So(gcsDriver.Name(), ShouldEqual, "gcs")
		})

		Convey("EnsureDir", func() {
			err := gcsDriver.EnsureDir("/test")
			So(err, ShouldBeNil)
		})

		Convey("DirExists", func() {
			Convey("True", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
					}, nil
				}
				So(gcsDriver.DirExists("/test"), ShouldBeTrue)
			})

			Convey("False - Not a dir", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{
						IsDirFn: func() bool { return false },
					}, nil
				}
				So(gcsDriver.DirExists("/test"), ShouldBeFalse)
			})

			Convey("False - Error", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return nil, errTest
				}
				So(gcsDriver.DirExists("/test"), ShouldBeFalse)
			})
		})

		Convey("Reader", func() {
			Convey("Success", func() {
				storeMock.ReaderFn = func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("")), nil
				}
				r, err := gcsDriver.Reader("/test", 0)
				So(err, ShouldBeNil)
				So(r, ShouldNotBeNil)
			})

			Convey("InvalidOffsetError", func() {
				storeMock.ReaderFn = func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return nil, driver.InvalidOffsetError{Path: path, Offset: offset}
				}
				_, err := gcsDriver.Reader("/test", 100)
				So(err, ShouldNotBeNil)

				var invalidOffset driver.InvalidOffsetError
				So(errors.As(err, &invalidOffset), ShouldBeTrue)
				So(invalidOffset.DriverName, ShouldEqual, "gcs")
			})
		})

		Convey("ReadFile", func() {
			Convey("Success", func() {
				storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
					return []byte("content"), nil
				}
				content, err := gcsDriver.ReadFile("/test")
				So(err, ShouldBeNil)
				So(string(content), ShouldEqual, "content")
			})

			Convey("PathNotFoundError with empty Path gets path set", func() {
				storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
					return nil, driver.PathNotFoundError{Path: ""} // Path empty so driver sets it
				}
				_, err := gcsDriver.ReadFile("/requested/path")
				So(err, ShouldNotBeNil)

				var pathErr driver.PathNotFoundError
				So(errors.As(err, &pathErr), ShouldBeTrue)
				So(pathErr.DriverName, ShouldEqual, "gcs")
				So(pathErr.Path, ShouldEqual, "/requested/path")
			})

			Convey("GCS not-found string becomes PathNotFoundError", func() {
				for _, msg := range []string{"object doesn't exist", "Error 404", "does not exist"} {
					errMsg := msg
					storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
						//nolint:err113 // test needs variable not-found message
						return nil, fmt.Errorf("%s", errMsg)
					}
					_, err := gcsDriver.ReadFile("/key")
					So(err, ShouldNotBeNil)

					var pathErr driver.PathNotFoundError
					So(errors.As(err, &pathErr), ShouldBeTrue)
					So(pathErr.Path, ShouldEqual, "/key")
				}
			})

			Convey("Generic error becomes storagedriver.Error", func() {
				storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
					return nil, errTest
				}
				_, err := gcsDriver.ReadFile("/test")
				So(err, ShouldNotBeNil)

				var storageErr driver.Error
				So(errors.As(err, &storageErr), ShouldBeTrue)
				So(storageErr.DriverName, ShouldEqual, "gcs")
				So(storageErr.Detail, ShouldEqual, errTest)
			})
		})

		Convey("Delete", func() {
			Convey("Success", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return nil
				}
				err := gcsDriver.Delete("/test")
				So(err, ShouldBeNil)
			})

			Convey("PathNotFoundError is idempotent (return nil)", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return driver.PathNotFoundError{Path: path}
				}
				err := gcsDriver.Delete("/nonexistent")
				So(err, ShouldBeNil)
			})

			Convey("Other error is returned", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return errTest
				}
				err := gcsDriver.Delete("/test")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, errTest), ShouldBeFalse) // wrapped in storagedriver.Error
			})
		})

		Convey("Stat", func() {
			Convey("Success", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{}, nil
				}
				fi, err := gcsDriver.Stat("/test")
				So(err, ShouldBeNil)
				So(fi, ShouldNotBeNil)
			})

			Convey("InvalidPathError", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return nil, driver.InvalidPathError{Path: path}
				}
				_, err := gcsDriver.Stat("/bad")
				So(err, ShouldNotBeNil)

				var invalidPath driver.InvalidPathError
				So(errors.As(err, &invalidPath), ShouldBeTrue)
				So(invalidPath.DriverName, ShouldEqual, "gcs")
			})
		})

		Convey("Writer", func() {
			Convey("Success", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, nil
				}
				w, err := gcsDriver.Writer("/test", false)
				So(err, ShouldBeNil)
				So(w, ShouldNotBeNil)
			})

			Convey("Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errTest
				}
				_, err := gcsDriver.Writer("/test", false)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("WriteFile", func() {
			Convey("Success", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(p []byte) (int, error) {
							return len(p), nil
						},
						CommitFn: func() error {
							return nil
						},
						CloseFn: func() error {
							return nil
						},
					}, nil
				}
				n, err := gcsDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldBeNil)
				So(n, ShouldEqual, 7)
			})

			Convey("Writer Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errTest
				}
				_, err := gcsDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldNotBeNil)
			})

			Convey("Write Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(p []byte) (int, error) {
							return 0, errTest
						},
						CloseFn: func() error { return nil },
					}, nil
				}
				_, err := gcsDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldNotBeNil)
			})

			Convey("Commit Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(p []byte) (int, error) {
							return len(p), nil
						},
						CommitFn: func() error {
							return errTest
						},
						CloseFn: func() error { return nil },
					}, nil
				}
				_, err := gcsDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Walk", func() {
			storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
				return nil
			}
			err := gcsDriver.Walk("/test", nil)
			So(err, ShouldBeNil)
		})

		Convey("List", func() {
			Convey("Success", func() {
				storeMock.ListFn = func(ctx context.Context, path string) ([]string, error) {
					return []string{"a"}, nil
				}
				l, err := gcsDriver.List("/test")
				So(err, ShouldBeNil)
				So(l, ShouldResemble, []string{"a"})
			})

			Convey("Error", func() {
				storeMock.ListFn = func(ctx context.Context, path string) ([]string, error) {
					return nil, errTest
				}
				_, err := gcsDriver.List("/test")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Move", func() {
			storeMock.MoveFn = func(ctx context.Context, sourcePath, destPath string) error {
				return nil
			}
			err := gcsDriver.Move("/src", "/dst")
			So(err, ShouldBeNil)
		})

		Convey("SameFile", func() {
			Convey("True", func() {
				now := time.Now()
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &fileInfoMock{
						isDir:   false,
						size:    10,
						modTime: now,
						path:    "/canonical/path",
					}, nil
				}
				So(gcsDriver.SameFile("/path1", "/path2"), ShouldBeTrue)
			})

			Convey("False - Different ModTime", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					modTime := time.Now()
					if path == "/path2" {
						modTime = modTime.Add(1 * time.Hour)
					}

					return &fileInfoMock{
						isDir:   false,
						size:    10,
						modTime: modTime,
						path:    path,
					}, nil
				}
				So(gcsDriver.SameFile("/path1", "/path2"), ShouldBeFalse)
			})
		})

		Convey("Link", func() {
			storeMock.PutContentFn = func(ctx context.Context, path string, content []byte) error {
				return nil
			}
			err := gcsDriver.Link("/src", "/dst")
			So(err, ShouldBeNil)
		})
	})
}

func TestNewImageStore(t *testing.T) {
	Convey("NewImageStore", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := gcs.NewImageStore("/tmp", "/tmp", true, true, log, metrics, nil, storeMock, nil, nil, nil)
		So(imgStore, ShouldNotBeNil)
	})
}
