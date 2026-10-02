package gcs_test

// Zot GCS wrapper formatErr / Mark* mapping (not upstream SDK surfaces).
// See pkg/storage/errclass/driver-error-matrix.md.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	gcsstorage "cloud.google.com/go/storage"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/api/googleapi"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestFormatErrClassification(t *testing.T) {
	Convey("GCS formatErr classification", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		gcsDriver := gcs.New(storeMock)

		type outcome int

		const (
			pathNotFound outcome = iota
			driverError
		)

		cases := []struct {
			name string
			msg  string
			want outcome
			note string
		}{
			{
				name: "object doesn't exist",
				msg:  "storage: object doesn't exist",
				want: pathNotFound,
				note: "Missing — string fallback for untyped GCS miss",
			},
			{
				name: "Error 404",
				msg:  "googleapi: Error 404: Not Found",
				want: pathNotFound,
				note: "Missing — 404 string fallback",
			},
			{
				name: "timeout containing does not exist",
				msg:  "RequestTimeout: object does not exist yet",
				want: driverError,
				note: "Transient — bare does-not-exist text is not Missing",
			},
			{
				name: "resource does not exist",
				msg:  "resource does not exist",
				want: driverError,
				note: "Transient — bare does-not-exist text is not Missing",
			},
			{
				name: "context deadline",
				msg:  "context deadline exceeded",
				want: driverError,
				note: "Transient",
			},
			{
				name: "connection reset",
				msg:  "read: connection reset by peer",
				want: driverError,
				note: "Transient",
			},
			{
				name: "503 Service Unavailable",
				msg:  "googleapi: Error 503: Service Unavailable",
				want: driverError,
				note: "Transient",
			},
			{
				name: "429 Too Many Requests",
				msg:  "googleapi: Error 429: Too Many Requests",
				want: driverError,
				note: "Transient",
			},
		}

		for _, testCase := range cases {
			Convey(testCase.name+": "+testCase.note, func() {
				storeMock.GetContentFn = func(_ context.Context, _ string) ([]byte, error) {
					//nolint:err113 // mapping needs exact message text
					return nil, fmt.Errorf("%s", testCase.msg)
				}

				_, err := gcsDriver.ReadFile("/blobs/sha256/abc")
				So(err, ShouldNotBeNil)

				var pnf storagedriver.PathNotFoundError

				var derr storagedriver.Error

				switch testCase.want {
				case pathNotFound:
					So(errors.As(err, &pnf), ShouldBeTrue)
					So(pnf.DriverName, ShouldEqual, "gcs")
					So(pnf.Path, ShouldEqual, "/blobs/sha256/abc")
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
				case driverError:
					So(errors.As(err, &pnf), ShouldBeFalse)
					So(errors.As(err, &derr), ShouldBeTrue)
					So(derr.DriverName, ShouldEqual, "gcs")
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
				}
			})
		}

		Convey("googleapi typed 404 → ErrStorageMissing", func() {
			cause := &googleapi.Error{Code: http.StatusNotFound, Message: "Not Found"}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := gcsDriver.Stat("/missing")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("context.Canceled → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, context.Canceled
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, context.Canceled), ShouldBeTrue)
		})

		Convey("googleapi typed 429 → ErrStorageTransient", func() {
			cause := &googleapi.Error{Code: http.StatusTooManyRequests, Message: "rate limit"}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("googleapi typed 503 → ErrStorageTransient", func() {
			cause := &googleapi.Error{Code: http.StatusServiceUnavailable, Message: "unavailable"}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("net.Error Timeout → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, timeoutNetError{}
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("InvalidPathError → ErrStoragePermanent + DriverName", func() {
			storeMock.StatFn = func(_ context.Context, path string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.InvalidPathError{Path: path}
			}
			_, err := gcsDriver.Stat("/bad")
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidPathError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(inv.DriverName, ShouldEqual, "gcs")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("googleapi 401 → ErrStoragePermanent", func() {
			cause := &googleapi.Error{Code: http.StatusUnauthorized, Message: "Unauthorized"}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("%v-erased googleapi 403 (distribution Move) → Permanent", func() {
			// Upstream gcs.Move: fmt.Errorf("move %q to %q: %v", src, dst, err)
			typed := &googleapi.Error{Code: http.StatusForbidden, Message: "Forbidden"}
			//nolint:err113,errorlint // simulate distribution %v erase
			erased := fmt.Errorf("move %q to %q: %v", "/src", "/dst", typed)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, erased
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)

			var gerr *googleapi.Error
			So(errors.As(err, &gerr), ShouldBeFalse)
		})

		Convey("googleapi 403 inside Error.Detail → ErrStoragePermanent", func() {
			cause := &googleapi.Error{Code: http.StatusForbidden, Message: "Forbidden"}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.Error{
					DriverName: "gcs",
					Detail:     cause,
				}
			}
			_, err := gcsDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("ErrObjectNotExist inside storagedriver.Error.Detail → Missing", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.Error{
					DriverName: "gcs",
					Detail:     gcsstorage.ErrObjectNotExist,
				}
			}
			_, err := gcsDriver.Stat("/missing")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("InvalidOffsetError → ErrStoragePermanent + DriverName", func() {
			storeMock.ReaderFn = func(_ context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, storagedriver.InvalidOffsetError{Path: path, Offset: offset}
			}
			_, err := gcsDriver.Reader("/blob", 99)
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidOffsetError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(inv.DriverName, ShouldEqual, "gcs")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("ErrUnsupportedMethod → ErrStoragePermanent", func() {
			storeMock.RedirectURLFn = func(_ *http.Request, _ string) (string, error) {
				return "", storagedriver.ErrUnsupportedMethod{DriverName: "gcs"}
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example/", nil)
			So(err, ShouldBeNil)
			_, err = gcsDriver.RedirectURL(req, "/blob")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("non-PathNotFound List mid-walk → ErrStorageTransient", func() {
			storeMock.NameFn = func() string { return "gcs" }
			storeMock.ListFn = func(_ context.Context, p string) ([]string, error) {
				if p == "/repo" {
					return []string{"/repo/child"}, nil
				}
				//nolint:err113 // mapping
				return nil, errors.New("connection reset by peer")
			}
			storeMock.StatFn = func(_ context.Context, p string) (storagedriver.FileInfo, error) {
				return &fileInfoMock{isDir: true, path: p}, nil
			}
			storeMock.WalkFn = func(ctx context.Context, path string, f storagedriver.WalkFn,
				options ...func(*storagedriver.WalkOptions),
			) error {
				return storagedriver.WalkFallback(ctx, storeMock, path, f, options...)
			}

			err := gcsDriver.Walk("/repo", func(_ storagedriver.FileInfo) error {
				return nil
			})
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		})

		Convey("Writer Commit failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CommitFn: func() error {
						return &googleapi.Error{Code: http.StatusForbidden, Message: "denied"}
					},
				}, nil
			}
			fw, err := gcsDriver.Writer("/key", false)
			So(err, ShouldBeNil)
			err = fw.Commit(context.Background())
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("WriteFile Write failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					WriteFn: func(_ []byte) (int, error) {
						return 0, errors.New("connection reset by peer") //nolint:err113 // mapping
					},
				}, nil
			}
			_, err := gcsDriver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("WriteFile Close failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CloseFn: func() error {
						return errors.New("connection reset by peer") //nolint:err113 // mapping
					},
				}, nil
			}
			_, err := gcsDriver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})
	})
}

func TestDeleteIdempotentPathNotFound(t *testing.T) {
	Convey("GCS Delete PathNotFound → nil (idempotent wrapper)", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		gcsDriver := gcs.New(storeMock)

		storeMock.DeleteFn = func(_ context.Context, path string) error {
			return storagedriver.PathNotFoundError{Path: path}
		}
		So(gcsDriver.Delete("/already-gone"), ShouldBeNil)
	})
}

func TestWalkEOFPeeled(t *testing.T) {
	Convey("GCS Walk peels io.EOF before formatErr", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		gcsDriver := gcs.New(storeMock)

		storeMock.WalkFn = func(_ context.Context, _ string, _ storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			return storagedriver.Error{DriverName: "gcs", Detail: io.EOF}
		}

		err := gcsDriver.Walk("/repo", func(_ storagedriver.FileInfo) error { return nil })
		So(errors.Is(err, io.EOF), ShouldBeTrue)

		var derr storagedriver.Error
		So(errors.As(err, &derr), ShouldBeFalse)
	})
}

func TestWalkCallbackErrorNotTransient(t *testing.T) {
	Convey("GCS WalkFn application error → unchanged (not Transient)", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		gcsDriver := gcs.New(storeMock)
		boom := errors.New("filter boom") //nolint:err113 // test

		storeMock.WalkFn = func(_ context.Context, _ string, f storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			err := f(nil)

			return storagedriver.Error{DriverName: "gcs", Detail: err}
		}

		err := gcsDriver.Walk("/repo", func(_ storagedriver.FileInfo) error { return boom })
		So(err, ShouldEqual, boom)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
	})
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }
