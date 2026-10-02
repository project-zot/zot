package s3_test

// Zot S3 wrapper formatErr / Mark* mapping (not S3MOCK upstream surfaces).
// See pkg/storage/errclass/driver-error-matrix.md and upstream_driver_errors_test.go.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestFormatErrClassification(t *testing.T) {
	Convey("S3 formatErr classification", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		s3Driver := s3.New(storeMock)

		Convey("PathNotFound → ErrStorageMissing", func() {
			storeMock.StatFn = func(_ context.Context, path string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.PathNotFoundError{Path: path}
			}
			_, err := s3Driver.Stat("/missing")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("NoSuchKey awserr → ErrStorageMissing", func() {
			cause := awserr.New("NoSuchKey", "not found", nil)
			storeMock.GetContentFn = func(_ context.Context, _ string) ([]byte, error) {
				return nil, cause
			}
			_, err := s3Driver.ReadFile("/key")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)

			var awsErr awserr.Error
			So(errors.As(err, &awsErr), ShouldBeTrue)
			So(awsErr.Code(), ShouldEqual, "NoSuchKey")
		})

		Convey("NoSuchKey inside storagedriver.Error.Detail → ErrStorageMissing", func() {
			cause := awserr.New("NoSuchKey", "not found", nil)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.Error{
					DriverName: "s3",
					Detail:     cause,
				}
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("SlowDown awserr → ErrStorageTransient", func() {
			cause := awserr.New("SlowDown", "throttle", nil)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("AccessDenied awserr → ErrStoragePermanent", func() {
			cause := awserr.New("AccessDenied", "denied", nil)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("NoSuchBucket awserr → ErrStoragePermanent (not Missing)", func() {
			cause := awserr.New("NoSuchBucket", "bucket gone", nil)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("generic error → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, errors.New("something odd") //nolint:err113 // test
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("InvalidPathError → ErrStoragePermanent", func() {
			storeMock.StatFn = func(_ context.Context, path string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.InvalidPathError{Path: path}
			}
			_, err := s3Driver.Stat("/bad")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("ErrUnsupportedMethod → ErrStoragePermanent", func() {
			storeMock.RedirectURLFn = func(_ *http.Request, _ string) (string, error) {
				return "", storagedriver.ErrUnsupportedMethod{DriverName: "s3"}
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example/", nil)
			So(err, ShouldBeNil)
			_, err = s3Driver.RedirectURL(req, "/blob")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)

			var unsupported storagedriver.ErrUnsupportedMethod
			So(errors.As(err, &unsupported), ShouldBeTrue)
		})

		Convey("InvalidOffsetError → ErrStoragePermanent", func() {
			storeMock.ReaderFn = func(_ context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, storagedriver.InvalidOffsetError{Path: path, Offset: offset}
			}
			_, err := s3Driver.Reader("/blob", 99)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("context.DeadlineExceeded → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, context.DeadlineExceeded
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, context.DeadlineExceeded), ShouldBeTrue)
		})

		Convey("net.Error Timeout → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, timeoutNetError{}
			}
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("WriteFile Write failure → classified via formatErr", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					WriteFn: func(_ []byte) (int, error) {
						return 0, awserr.New("SlowDown", "throttle", nil)
					},
				}, nil
			}
			_, err := s3Driver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("WriteFile Commit failure → classified via formatErr", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CommitFn: func() error {
						return awserr.New("AccessDenied", "denied", nil)
					},
				}, nil
			}
			_, err := s3Driver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("WriteFile Close failure → classified via formatErr", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CloseFn: func() error {
						return awserr.New("SlowDown", "throttle", nil)
					},
				}, nil
			}
			_, err := s3Driver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Writer Commit failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CommitFn: func() error {
						return awserr.New("AccessDenied", "denied", nil)
					},
				}, nil
			}
			fw, err := s3Driver.Writer("/key", false)
			So(err, ShouldBeNil)
			err = fw.Commit(context.Background())
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("Writer Close failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CloseFn: func() error {
						return awserr.New("SlowDown", "throttle", nil)
					},
				}, nil
			}
			fw, err := s3Driver.Writer("/key", false)
			So(err, ShouldBeNil)
			err = fw.Close()
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Writer already committed is not Transient", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CommitFn: func() error {
						return errors.New("already committed") //nolint:err113 // distribution
					},
				}, nil
			}
			fw, err := s3Driver.Writer("/key", false)
			So(err, ShouldBeNil)
			err = fw.Commit(context.Background())
			So(err.Error(), ShouldEqual, "already committed")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("Reader Read failure → classified via WrapReadCloser", func() {
			storeMock.ReaderFn = func(_ context.Context, _ string, _ int64) (io.ReadCloser, error) {
				return &errReadCloser{
					readErr: awserr.New("SlowDown", "throttle", nil),
				}, nil
			}
			reader, err := s3Driver.Reader("/key", 0)
			So(err, ShouldBeNil)
			_, err = reader.Read([]byte{0})
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Reader Close failure → classified via WrapReadCloser", func() {
			storeMock.ReaderFn = func(_ context.Context, _ string, _ int64) (io.ReadCloser, error) {
				return &errReadCloser{
					closeErr: awserr.New("RequestTimeout", "timeout", nil),
				}, nil
			}
			reader, err := s3Driver.Reader("/key", 0)
			So(err, ShouldBeNil)
			err = reader.Close()
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Error.Detail holding Errors (partial Delete) → Transient, no panic", func() {
			cause := storagedriver.Error{
				DriverName: "s3",
				Detail: storagedriver.Errors{Errs: []error{
					errors.New("one"), //nolint:err113 // mapping
					errors.New("two"), //nolint:err113 // mapping
				}},
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			So(func() {
				_, _ = s3Driver.Stat("/key")
			}, ShouldNotPanic)
			_, err := s3Driver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		})
	})
}

func TestWalkEOFPeeled(t *testing.T) {
	Convey("S3 Walk peels io.EOF before formatErr", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		s3Driver := s3.New(storeMock)

		storeMock.WalkFn = func(_ context.Context, _ string, _ storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			return storagedriver.Error{DriverName: "s3", Detail: io.EOF}
		}

		err := s3Driver.Walk("/repo", func(_ storagedriver.FileInfo) error { return nil })
		So(errors.Is(err, io.EOF), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)

		var derr storagedriver.Error
		So(errors.As(err, &derr), ShouldBeFalse)
	})
}

func TestWalkCallbackErrorNotTransient(t *testing.T) {
	Convey("S3 WalkFn application error → unchanged (not Transient)", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		s3Driver := s3.New(storeMock)
		boom := errors.New("filter boom") //nolint:err113 // test

		storeMock.WalkFn = func(_ context.Context, _ string, f storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			err := f(nil)
			// Simulate distribution Base wrapping the callback error.
			return storagedriver.Error{DriverName: "s3", Detail: err}
		}

		err := s3Driver.Walk("/repo", func(_ storagedriver.FileInfo) error { return boom })
		So(err, ShouldEqual, boom)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
	})
}

type errReadCloser struct {
	readErr  error
	closeErr error
}

func (e *errReadCloser) Read(_ []byte) (int, error) {
	if e.readErr != nil {
		return 0, e.readErr
	}

	return 0, io.EOF
}

func (e *errReadCloser) Close() error {
	return e.closeErr
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }
