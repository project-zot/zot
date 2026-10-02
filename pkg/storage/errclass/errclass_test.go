package errclass_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestWrap(t *testing.T) {
	Convey("Wrap", t, func() {
		Convey("nil outer → nil", func() {
			So(errclass.Wrap(nil, errors.New("x")), ShouldBeNil) //nolint:err113 // test
		})

		Convey("nil inner → outer", func() {
			So(errclass.Wrap(zerr.ErrStorageMissing, nil), ShouldEqual, zerr.ErrStorageMissing)
		})

		Convey("distinct inner → both Is", func() {
			inner := errors.New("sdk") //nolint:err113 // test
			wrapped := errclass.Wrap(zerr.ErrStorageMissing, inner)
			So(errors.Is(wrapped, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(wrapped, inner), ShouldBeTrue)
		})

		Convey("inner already wraps outer → return inner", func() {
			inner := fmt.Errorf("outer: %w", zerr.ErrStorageMissing)
			wrapped := errclass.Wrap(zerr.ErrStorageMissing, inner)
			So(wrapped, ShouldEqual, inner)
			So(errors.Is(wrapped, zerr.ErrStorageMissing), ShouldBeTrue)
			So(wrapped.Error(), ShouldContainSubstring, "outer")
		})

		Convey("Error.Detail holding Errors does not panic", func() {
			// S3 DeleteObjects partial failure shape; errors.Is can panic on ==
			// when both sides are Error{Detail: Errors{…}} (uncomparable).
			multi := storagedriver.Errors{Errs: []error{
				errors.New("one"), //nolint:err113 // test
				errors.New("two"), //nolint:err113 // test
			}}
			original := storagedriver.Error{DriverName: "s3", Detail: multi}
			duplicate := storagedriver.Error{DriverName: "s3", Detail: multi}

			So(func() {
				_ = errclass.Wrap(duplicate, original)
			}, ShouldNotPanic)

			wrapped := errclass.Wrap(duplicate, original)
			So(errors.As(wrapped, new(storagedriver.Error)), ShouldBeTrue)
			So(errors.Is(errclass.MarkTransient(wrapped), zerr.ErrStorageTransient), ShouldBeTrue)
		})
	})
}

func TestMarkHelpers(t *testing.T) {
	Convey("MarkMissing / MarkTransient / MarkPermanent", t, func() {
		Convey("nil → nil", func() {
			So(errclass.MarkMissing(nil), ShouldBeNil)
			So(errclass.MarkTransient(nil), ShouldBeNil)
			So(errclass.MarkPermanent(nil), ShouldBeNil)
		})

		Convey("already classified → return same error", func() {
			missing := errclass.MarkMissing(errors.New("gone")) //nolint:err113 // test
			So(errclass.MarkMissing(missing), ShouldEqual, missing)

			transient := errclass.MarkTransient(errors.New("blip")) //nolint:err113 // test
			So(errclass.MarkTransient(transient), ShouldEqual, transient)

			permanent := errclass.MarkPermanent(errors.New("denied")) //nolint:err113 // test
			So(errclass.MarkPermanent(permanent), ShouldEqual, permanent)
		})

		Convey("cross-class re-mark → keep original class only", func() {
			permanent := errclass.MarkPermanent(errors.New("denied")) //nolint:err113 // test
			remarked := errclass.MarkTransient(permanent)
			So(remarked, ShouldEqual, permanent)
			So(errors.Is(remarked, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(remarked, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(remarked, zerr.ErrStorageMissing), ShouldBeFalse)

			missing := errclass.MarkMissing(errors.New("gone")) //nolint:err113 // test
			So(errclass.MarkPermanent(missing), ShouldEqual, missing)
			So(errors.Is(missing, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(missing, zerr.ErrStoragePermanent), ShouldBeFalse)

			transient := errclass.MarkTransient(errors.New("blip")) //nolint:err113 // test
			So(errclass.MarkMissing(transient), ShouldEqual, transient)
			So(errors.Is(transient, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(transient, zerr.ErrStorageMissing), ShouldBeFalse)
		})

		Convey("fresh wrap → sentinel Is", func() {
			underlying := errors.New("underlying") //nolint:err113 // test
			So(errors.Is(errclass.MarkMissing(underlying), zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(errclass.MarkTransient(underlying), zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(errclass.MarkPermanent(underlying), zerr.ErrStoragePermanent), ShouldBeTrue)
		})
	})
}

func TestWrapFileWriter(t *testing.T) {
	Convey("WrapFileWriter classifies method errors", t, func() {
		boom := errors.New("sdk boom") //nolint:err113 // test

		Convey("nil inner → nil", func() {
			So(errclass.WrapFileWriter(nil, errclass.MarkTransient), ShouldBeNil)
		})

		Convey("Write / Commit / Close / Cancel go through format", func() {
			inner := &mocks.FileWriterMock{
				WriteFn: func(_ []byte) (int, error) {
					return 0, boom
				},
				CommitFn: func() error { return boom },
				CloseFn:  func() error { return boom },
				CancelFn: func() error { return boom },
			}
			writer := errclass.WrapFileWriter(inner, errclass.MarkTransient)

			_, err := writer.Write([]byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, boom), ShouldBeTrue)

			So(errors.Is(writer.Commit(context.Background()), zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(writer.Close(), zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(writer.Cancel(context.Background()), zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("nil format leaves errors unclassified", func() {
			inner := &mocks.FileWriterMock{
				CommitFn: func() error { return boom },
			}
			writer := errclass.WrapFileWriter(inner, nil)
			err := writer.Commit(context.Background())
			So(err, ShouldEqual, boom)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("success paths stay nil", func() {
			writer := errclass.WrapFileWriter(&mocks.FileWriterMock{}, errclass.MarkTransient)
			_, err := writer.Write([]byte("x"))
			So(err, ShouldBeNil)
			So(writer.Commit(context.Background()), ShouldBeNil)
			So(writer.Close(), ShouldBeNil)
			So(writer.Size(), ShouldBeGreaterThan, 0)
		})
	})
}

func TestIsWriterLifecycleError(t *testing.T) {
	Convey("IsWriterLifecycleError", t, func() {
		Convey("distribution strings", func() {
			So(errclass.IsWriterLifecycleError(errors.New("already closed")), ShouldBeTrue)    //nolint:err113 // distribution
			So(errclass.IsWriterLifecycleError(errors.New("already committed")), ShouldBeTrue) //nolint:err113 // distribution
			So(errclass.IsWriterLifecycleError(errors.New("already cancelled")), ShouldBeTrue) //nolint:err113 // distribution
		})

		Convey("zot ErrFileAlready* sentinels", func() {
			So(errclass.IsWriterLifecycleError(zerr.ErrFileAlreadyClosed), ShouldBeTrue)
			So(errclass.IsWriterLifecycleError(zerr.ErrFileAlreadyCommitted), ShouldBeTrue)
			So(errclass.IsWriterLifecycleError(zerr.ErrFileAlreadyCancelled), ShouldBeTrue)
		})

		Convey("storage I/O is not lifecycle", func() {
			So(errclass.IsWriterLifecycleError(errors.New("SlowDown")), ShouldBeFalse) //nolint:err113 // test
			So(errclass.IsWriterLifecycleError(nil), ShouldBeFalse)
		})
	})
}

func TestWrapReadCloser(t *testing.T) {
	Convey("WrapReadCloser classifies Read/Close errors", t, func() {
		boom := errors.New("sdk boom") //nolint:err113 // test

		Convey("nil inner → nil", func() {
			So(errclass.WrapReadCloser(nil, errclass.MarkTransient), ShouldBeNil)
		})

		Convey("Read failure is classified", func() {
			reader := errclass.WrapReadCloser(&errReadCloser{readErr: boom}, errclass.MarkTransient)
			_, err := reader.Read([]byte{0})
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, boom), ShouldBeTrue)
		})

		Convey("io.EOF is not classified", func() {
			reader := errclass.WrapReadCloser(&errReadCloser{readErr: io.EOF}, errclass.MarkTransient)
			_, err := reader.Read([]byte{0})
			So(err, ShouldEqual, io.EOF)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("Close failure is classified", func() {
			reader := errclass.WrapReadCloser(&errReadCloser{closeErr: boom}, errclass.MarkTransient)
			err := reader.Close()
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, boom), ShouldBeTrue)
		})

		Convey("nil format leaves errors unclassified", func() {
			reader := errclass.WrapReadCloser(&errReadCloser{closeErr: boom}, nil)
			err := reader.Close()
			So(err, ShouldEqual, boom)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})
	})
}

func TestPredicates(t *testing.T) {
	Convey("IsStorageObjectMissing / IsBlobUnavailable", t, func() {
		Convey("nil → false", func() {
			So(errclass.IsStorageObjectMissing(nil), ShouldBeFalse)
			So(errclass.IsBlobUnavailable(nil), ShouldBeFalse)
		})

		Convey("ErrStorageMissing → storage missing + unavailable", func() {
			err := errclass.MarkMissing(errors.New("gone")) //nolint:err113 // test
			So(errclass.IsStorageObjectMissing(err), ShouldBeTrue)
			So(errclass.IsBlobUnavailable(err), ShouldBeTrue)
		})

		Convey("bare PathNotFound is not Missing until driver formatErr MarkMissing", func() {
			err := storagedriver.PathNotFoundError{Path: "/x"}
			So(errclass.IsStorageObjectMissing(err), ShouldBeFalse)
			So(errclass.IsBlobUnavailable(err), ShouldBeFalse)
		})

		Convey("ErrCacheMiss → unavailable, not storage missing", func() {
			So(errors.Is(zerr.ErrCacheMiss, zerr.ErrCacheMiss), ShouldBeTrue)
			So(errclass.IsStorageObjectMissing(zerr.ErrCacheMiss), ShouldBeFalse)
			So(errclass.IsBlobUnavailable(zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("ErrBlobNotFound → unavailable only", func() {
			So(errclass.IsBlobUnavailable(zerr.ErrBlobNotFound), ShouldBeTrue)
			So(errclass.IsStorageObjectMissing(zerr.ErrBlobNotFound), ShouldBeFalse)
		})

		Convey("Wrapped BlobNotFound + CacheMiss matches both HTTP and cache", func() {
			err := errclass.Wrap(zerr.ErrBlobNotFound, zerr.ErrCacheMiss)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
			So(errclass.IsStorageObjectMissing(err), ShouldBeFalse)
			So(errclass.IsBlobUnavailable(err), ShouldBeTrue)
		})

		Convey("Transient is not unavailable", func() {
			err := errclass.MarkTransient(errors.New("blip")) //nolint:err113 // test
			So(errclass.IsBlobUnavailable(err), ShouldBeFalse)
			So(errclass.IsStorageObjectMissing(err), ShouldBeFalse)
		})
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
