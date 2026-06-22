package azure_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
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
	Convey("Azure Driver", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		azureDriver := azure.New(storeMock)

		Convey("Name", func() {
			So(azureDriver.Name(), ShouldEqual, "azure")
		})

		Convey("EnsureDir", func() {
			err := azureDriver.EnsureDir("/test")
			So(err, ShouldBeNil)
		})

		Convey("DirExists", func() {
			Convey("True", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
					}, nil
				}
				So(azureDriver.DirExists("/test"), ShouldBeTrue)
			})

			Convey("False - Not a dir", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{
						IsDirFn: func() bool { return false },
					}, nil
				}
				So(azureDriver.DirExists("/test"), ShouldBeFalse)
			})

			Convey("False - Error", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return nil, errTest
				}
				So(azureDriver.DirExists("/test"), ShouldBeFalse)
			})
		})

		Convey("Reader", func() {
			Convey("Success", func() {
				storeMock.ReaderFn = func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("")), nil
				}
				r, err := azureDriver.Reader("/test", 0)
				So(err, ShouldBeNil)
				So(r, ShouldNotBeNil)
			})

			Convey("InvalidOffsetError", func() {
				storeMock.ReaderFn = func(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
					return nil, driver.InvalidOffsetError{Path: path, Offset: offset}
				}
				_, err := azureDriver.Reader("/test", 100)
				So(err, ShouldNotBeNil)

				var invalidOffset driver.InvalidOffsetError
				So(errors.As(err, &invalidOffset), ShouldBeTrue)
				So(invalidOffset.DriverName, ShouldEqual, "azure")
			})
		})

		Convey("ReadFile", func() {
			Convey("Success", func() {
				storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
					return []byte("content"), nil
				}
				content, err := azureDriver.ReadFile("/test")
				So(err, ShouldBeNil)
				So(string(content), ShouldEqual, "content")
			})

			Convey("PathNotFoundError with empty Path gets path set", func() {
				storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
					return nil, driver.PathNotFoundError{Path: ""} // Path empty so driver sets it
				}
				_, err := azureDriver.ReadFile("/requested/path")
				So(err, ShouldNotBeNil)

				var pathErr driver.PathNotFoundError
				So(errors.As(err, &pathErr), ShouldBeTrue)
				So(pathErr.DriverName, ShouldEqual, "azure")
				So(pathErr.Path, ShouldEqual, "/requested/path")
			})

			Convey("Azure not-found string becomes PathNotFoundError", func() {
				for _, msg := range []string{"BlobNotFound", "ResourceNotFound", "Error 404", "does not exist"} {
					errMsg := msg
					storeMock.GetContentFn = func(ctx context.Context, path string) ([]byte, error) {
						//nolint:err113 // test needs variable not-found message
						return nil, fmt.Errorf("%s", errMsg)
					}
					_, err := azureDriver.ReadFile("/key")
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
				_, err := azureDriver.ReadFile("/test")
				So(err, ShouldNotBeNil)

				var storageErr driver.Error
				So(errors.As(err, &storageErr), ShouldBeTrue)
				So(storageErr.DriverName, ShouldEqual, "azure")
				So(storageErr.Detail, ShouldEqual, errTest)
			})
		})

		Convey("Delete", func() {
			Convey("Success", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return nil
				}
				err := azureDriver.Delete("/test")
				So(err, ShouldBeNil)
			})

			Convey("PathNotFoundError is idempotent (return nil)", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return driver.PathNotFoundError{Path: path}
				}
				err := azureDriver.Delete("/nonexistent")
				So(err, ShouldBeNil)
			})

			Convey("Other error is returned", func() {
				storeMock.DeleteFn = func(ctx context.Context, path string) error {
					return errTest
				}
				err := azureDriver.Delete("/test")
				So(err, ShouldNotBeNil)
				So(errors.Is(err, errTest), ShouldBeFalse) // wrapped in storagedriver.Error
			})
		})

		Convey("Stat", func() {
			Convey("Success", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return &mocks.FileInfoMock{}, nil
				}
				fi, err := azureDriver.Stat("/test")
				So(err, ShouldBeNil)
				So(fi, ShouldNotBeNil)
			})

			Convey("InvalidPathError", func() {
				storeMock.StatFn = func(ctx context.Context, path string) (driver.FileInfo, error) {
					return nil, driver.InvalidPathError{Path: path}
				}
				_, err := azureDriver.Stat("/bad")
				So(err, ShouldNotBeNil)

				var invalidPath driver.InvalidPathError
				So(errors.As(err, &invalidPath), ShouldBeTrue)
				So(invalidPath.DriverName, ShouldEqual, "azure")
			})
		})

		Convey("Writer", func() {
			Convey("Success", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{}, nil
				}
				w, err := azureDriver.Writer("/test", false)
				So(err, ShouldBeNil)
				So(w, ShouldNotBeNil)
			})

			Convey("Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errTest
				}
				_, err := azureDriver.Writer("/test", false)
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
				n, err := azureDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldBeNil)
				So(n, ShouldEqual, 7)
			})

			Convey("Writer Error", func() {
				storeMock.WriterFn = func(ctx context.Context, path string, isAppend bool) (driver.FileWriter, error) {
					return nil, errTest
				}
				_, err := azureDriver.WriteFile("/test", []byte("content"))
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
				_, err := azureDriver.WriteFile("/test", []byte("content"))
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
				_, err := azureDriver.WriteFile("/test", []byte("content"))
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Walk", func() {
			Convey("Success", func() {
				storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
					return nil
				}
				err := azureDriver.Walk("/test", nil)
				So(err, ShouldBeNil)
			})

			Convey("Direct io.EOF is returned as io.EOF", func() {
				storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
					return io.EOF
				}
				err := azureDriver.Walk("/test", nil)
				So(errors.Is(err, io.EOF), ShouldBeTrue)
			})

			Convey("io.EOF wrapped in storagedriver.Error is returned as io.EOF", func() {
				storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
					return driver.Error{
						DriverName: "azure",
						Detail:     io.EOF,
					}
				}
				err := azureDriver.Walk("/test", nil)
				So(errors.Is(err, io.EOF), ShouldBeTrue)
			})

			Convey("Non-EOF error is formatted normally", func() {
				storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
					return errTest
				}
				err := azureDriver.Walk("/test", nil)
				So(err, ShouldNotBeNil)
				So(errors.Is(err, io.EOF), ShouldBeFalse)

				var storageErr driver.Error
				So(errors.As(err, &storageErr), ShouldBeTrue)
			})
		})

		Convey("List", func() {
			Convey("Success", func() {
				storeMock.ListFn = func(ctx context.Context, path string) ([]string, error) {
					return []string{"a"}, nil
				}
				l, err := azureDriver.List("/test")
				So(err, ShouldBeNil)
				So(l, ShouldResemble, []string{"a"})
			})

			Convey("Error", func() {
				storeMock.ListFn = func(ctx context.Context, path string) ([]string, error) {
					return nil, errTest
				}
				_, err := azureDriver.List("/test")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("Move", func() {
			storeMock.MoveFn = func(ctx context.Context, sourcePath, destPath string) error {
				return nil
			}
			err := azureDriver.Move("/src", "/dst")
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
				So(azureDriver.SameFile("/path1", "/path2"), ShouldBeTrue)
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
				So(azureDriver.SameFile("/path1", "/path2"), ShouldBeFalse)
			})
		})

		Convey("Link", func() {
			storeMock.PutContentFn = func(ctx context.Context, path string, content []byte) error {
				return nil
			}
			err := azureDriver.Link("/src", "/dst")
			So(err, ShouldBeNil)
		})

		Convey("RedirectURL", func() {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://localhost/v2/repo/blobs/sha256:abc", nil)

			Convey("Success", func() {
				storeMock.RedirectURLFn = func(r *http.Request, path string) (string, error) {
					So(r, ShouldEqual, req)
					So(path, ShouldEqual, "/blob/path")

					return "https://example.com/signed", nil
				}

				url, err := azureDriver.RedirectURL(req, "/blob/path")
				So(err, ShouldBeNil)
				So(url, ShouldEqual, "https://example.com/signed")
			})

			Convey("Error", func() {
				storeMock.RedirectURLFn = func(_ *http.Request, _ string) (string, error) {
					return "", errTest
				}

				url, err := azureDriver.RedirectURL(req, "/blob/path")
				So(url, ShouldEqual, "")
				So(err, ShouldNotBeNil)

				var storageErr driver.Error
				So(errors.As(err, &storageErr), ShouldBeTrue)
				So(storageErr.DriverName, ShouldEqual, "azure")
			})
		})
	})
}

func TestNewImageStore(t *testing.T) {
	Convey("NewImageStore", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := azure.NewImageStore("/tmp", "/tmp", true, true, log, metrics, nil, storeMock, nil, nil, nil)
		So(imgStore, ShouldNotBeNil)
	})
}
