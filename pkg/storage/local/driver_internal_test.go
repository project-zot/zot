package local

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
)

func TestFormatErr(t *testing.T) {
	Convey("Test formatErr error handling", t, func() {
		driver := New(true)

		Convey("Test formatErr with nil error", func() {
			err := driver.formatErr(nil)
			So(err, ShouldBeNil)
		})

		Convey("Test formatErr with PathNotFoundError", func() {
			pathErr := storagedriver.PathNotFoundError{Path: "/test"}
			formatted := driver.formatErr(pathErr)
			So(formatted, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError
			So(errors.As(formatted, &pathNotFoundErr), ShouldBeTrue)
			So(pathNotFoundErr.DriverName, ShouldEqual, "local")
			So(errors.Is(formatted, zerr.ErrStorageMissing), ShouldBeTrue)
			// Stamped PathNotFound must not be stacked with the unstamped original.
			So(formatted.Error(), ShouldEqual,
				"storage object or path is missing: local: Path not found: /test")
		})

		Convey("Test formatErr with InvalidPathError", func() {
			invalidErr := storagedriver.InvalidPathError{Path: "/test"}
			formatted := driver.formatErr(invalidErr)
			So(formatted, ShouldNotBeNil)

			var invalidPathErr storagedriver.InvalidPathError
			So(errors.As(formatted, &invalidPathErr), ShouldBeTrue)
			So(invalidPathErr.DriverName, ShouldEqual, "local")
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(formatted.Error(), ShouldEqual,
				"storage backend returned a permanent error: local: invalid path: /test")
		})

		Convey("Test formatErr with InvalidOffsetError", func() {
			offsetErr := storagedriver.InvalidOffsetError{Path: "/test", Offset: 100}
			formatted := driver.formatErr(offsetErr)
			So(formatted, ShouldNotBeNil)

			var invalidOffsetErr storagedriver.InvalidOffsetError
			So(errors.As(formatted, &invalidOffsetErr), ShouldBeTrue)
			So(invalidOffsetErr.DriverName, ShouldEqual, "local")
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(formatted.Error(), ShouldEqual,
				"storage backend returned a permanent error: local: invalid offset: 100 for path: /test")
		})

		Convey("Test formatErr with generic error", func() {
			genericErr := errors.New("generic error")
			formatted := driver.formatErr(genericErr)
			So(formatted, ShouldNotBeNil)

			var storageErr storagedriver.Error
			So(errors.As(formatted, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
			So(storageErr.Detail, ShouldEqual, genericErr)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageMissing), ShouldBeFalse)
			So(errors.Is(formatted, genericErr), ShouldBeTrue)
		})

		Convey("Test formatErr with permission error → ErrStoragePermanent", func() {
			formatted := driver.formatErr(os.ErrPermission)
			So(formatted, ShouldNotBeNil)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageMissing), ShouldBeFalse)
			So(errors.Is(formatted, os.ErrPermission), ShouldBeTrue)
		})

		Convey("Test formatErr with EINVAL → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.EINVAL)
			So(formatted, ShouldNotBeNil)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EINVAL), ShouldBeTrue)
		})

		Convey("Test formatErr with os.ErrInvalid → ErrStoragePermanent", func() {
			formatted := driver.formatErr(os.ErrInvalid)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, os.ErrInvalid), ShouldBeTrue)
		})

		Convey("Test formatErr with ENOTDIR → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.ENOTDIR)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.ENOTDIR), ShouldBeTrue)
		})

		Convey("Test formatErr with EISDIR → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.EISDIR)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EISDIR), ShouldBeTrue)
		})

		Convey("Test formatErr with ENAMETOOLONG → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.ENAMETOOLONG)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.ENAMETOOLONG), ShouldBeTrue)
		})

		Convey("Test formatErr with ENOSPC → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.ENOSPC)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.ENOSPC), ShouldBeTrue)
		})

		Convey("Test formatErr with EDQUOT → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.EDQUOT)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EDQUOT), ShouldBeTrue)
		})

		Convey("Test formatErr with EROFS → ErrStoragePermanent", func() {
			formatted := driver.formatErr(syscall.EROFS)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EROFS), ShouldBeTrue)
		})

		Convey("Test formatErr with PathError (any errno) → ErrStoragePermanent", func() {
			pathErr := &os.PathError{Op: "write", Path: "/tmp/x", Err: syscall.ENOSPC}
			formatted := driver.formatErr(pathErr)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, pathErr), ShouldBeTrue)
			So(errors.Is(formatted, syscall.ENOSPC), ShouldBeTrue)
		})

		Convey("Test formatErr with EAGAIN → ErrStorageTransient", func() {
			formatted := driver.formatErr(syscall.EAGAIN)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EAGAIN), ShouldBeTrue)
		})

		Convey("Test formatErr with EIO → ErrStorageTransient", func() {
			formatted := driver.formatErr(syscall.EIO)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeFalse)
			So(errors.Is(formatted, syscall.EIO), ShouldBeTrue)
		})

		Convey("Test formatErr with raw ENOENT → ErrStorageMissing", func() {
			formatted := driver.formatErr(os.ErrNotExist)
			So(errors.Is(formatted, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, os.ErrNotExist), ShouldBeTrue)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(formatted, &pnf), ShouldBeFalse)

			var derr storagedriver.Error
			So(errors.As(formatted, &derr), ShouldBeTrue)
			So(derr.DriverName, ShouldEqual, "local")
			So(errors.Is(derr.Detail, os.ErrNotExist), ShouldBeTrue)
		})

		Convey("Test formatErr with %w-wrapped ENOENT → ErrStorageMissing", func() {
			// os.IsNotExist does not traverse arbitrary wrappers; errors.Is does.
			wrapped := fmt.Errorf("stat: %w", os.ErrNotExist)
			formatted := driver.formatErr(wrapped)
			So(errors.Is(formatted, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, os.ErrNotExist), ShouldBeTrue)
			So(os.IsNotExist(wrapped), ShouldBeFalse)
		})

		Convey("Test formatErr peels Error.Detail for permission → Permanent", func() {
			wrapped := storagedriver.Error{
				DriverName: "local",
				Detail:     os.ErrPermission,
			}
			formatted := driver.formatErr(wrapped)
			So(errors.Is(formatted, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(formatted, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(formatted, os.ErrPermission), ShouldBeTrue)
		})
	})
}

func TestOpenReaderSeekPaths(t *testing.T) {
	Convey("openReader Seek / undershoot Close paths", t, func() {
		driver := New(true)
		closeBoom := errors.New("close failed") //nolint:err113 // test

		Convey("seekPos < offset + Close nil → InvalidOffset Permanent", func() {
			file := &mockReadSeekCloser{seekPos: 0}
			_, err := driver.openReader(file, "/blob", 10)
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidOffsetError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(inv.Path, ShouldEqual, "/blob")
			So(inv.Offset, ShouldEqual, int64(10))
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(err.Error(), ShouldEqual,
				"storage backend returned a permanent error: local: invalid offset: 10 for path: /blob")
			So(file.closeCalled, ShouldBeTrue)
		})

		Convey("seekPos < offset + Close error → Join InvalidOffset and Close", func() {
			file := &mockReadSeekCloser{seekPos: 0, closeErr: closeBoom}
			_, err := driver.openReader(file, "/blob", 10)
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidOffsetError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(errors.Is(err, closeBoom), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(strings.Count(err.Error(), "invalid offset"), ShouldEqual, 1)
		})

		Convey("Seek error + Close error → Join both", func() {
			seekBoom := errors.New("seek failed") //nolint:err113 // test
			file := &mockReadSeekCloser{seekErr: seekBoom, closeErr: closeBoom}
			_, err := driver.openReader(file, "/blob", 0)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, seekBoom), ShouldBeTrue)
			So(errors.Is(err, closeBoom), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("successful Seek returns the file", func() {
			file := &mockReadSeekCloser{seekPos: 5}
			got, err := driver.openReader(file, "/blob", 5)
			So(err, ShouldBeNil)
			So(got, ShouldEqual, file)
			So(file.closeCalled, ShouldBeFalse)
		})
	})
}

type mockReadSeekCloser struct {
	seekPos     int64
	seekErr     error
	closeErr    error
	closeCalled bool
}

func (m *mockReadSeekCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockReadSeekCloser) Close() error {
	m.closeCalled = true

	return m.closeErr
}

func (m *mockReadSeekCloser) Seek(_ int64, _ int) (int64, error) {
	return m.seekPos, m.seekErr
}

// failCloseFile fails Close with a fixed error; other ops use the real file.
type failCloseFile struct {
	*os.File
	closeErr error
}

func (f *failCloseFile) Close() error {
	_ = f.File.Close()

	return f.closeErr
}

func TestFileWriterClassifiesOSErrors(t *testing.T) {
	Convey("fileWriter routes OS errors through formatErr", t, func() {
		driver := New(true)
		dir := t.TempDir()

		Convey("Close classifies Close failure as Permanent (EINVAL)", func() {
			realFile, err := os.CreateTemp(dir, "fw-close-*")
			So(err, ShouldBeNil)

			fw := newFileWriter(&failCloseFile{File: realFile, closeErr: syscall.EINVAL}, 0, false, driver.formatErr)
			err = fw.Close()
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(err, syscall.EINVAL), ShouldBeTrue)
		})

		Convey("Cancel classifies Remove failure as Permanent (EINVAL)", func() {
			realFile, err := os.CreateTemp(dir, "fw-cancel-*")
			So(err, ShouldBeNil)
			// Close the underlying FD so Remove can succeed on the path; then
			// point Name() at an invalid path by wrapping after rename...
			// Simpler: use a file whose Name() is NUL (invalid for Remove).
			name := realFile.Name()
			So(realFile.Close(), ShouldBeNil)
			So(os.Remove(name), ShouldBeNil)

			fw := newFileWriter(&namedFile{name: string([]byte{0x00})}, 0, false, driver.formatErr)
			err = fw.Cancel(t.Context())
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, syscall.EINVAL), ShouldBeTrue)
		})

		Convey("ErrFileAlreadyClosed is not stamped Transient", func() {
			realFile, err := os.CreateTemp(dir, "fw-already-*")
			So(err, ShouldBeNil)

			fw := newFileWriter(realFile, 0, false, driver.formatErr)
			So(fw.Close(), ShouldBeNil)
			err = fw.Close()
			So(err, ShouldEqual, zerr.ErrFileAlreadyClosed)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})
	})
}

// namedFile only implements Name for Cancel Remove tests.
type namedFile struct {
	name string
}

func (n *namedFile) Write(_ []byte) (int, error) { return 0, nil }
func (n *namedFile) Close() error                { return nil }
func (n *namedFile) Sync() error                 { return nil }
func (n *namedFile) Name() string                { return n.name }
