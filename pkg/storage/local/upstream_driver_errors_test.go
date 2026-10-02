package local_test

// Characterization of local driver Stat/List/Walk/Delete surfaces (real FS).
// formatErr / Mark* mapping lives in driver_internal_test.go (package local).
// See pkg/storage/errclass/driver-error-matrix.md.

import (
	"errors"
	"io"
	"os"
	"path"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

func TestUpstreamDriverErrors(t *testing.T) {
	Convey("Local driver upstream error surfaces", t, func() {
		driver := local.New(true)
		root := t.TempDir()

		Convey("Stat missing object → PathNotFound", func() {
			_, err := driver.Stat(path.Join(root, "no-such-blob"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("Stat existing file → nil, not IsDir", func() {
			file := path.Join(root, "existing.txt")
			So(os.WriteFile(file, []byte("x"), 0o600), ShouldBeNil)

			fi, err := driver.Stat(file)
			So(err, ShouldBeNil)
			So(fi.IsDir(), ShouldBeFalse)
		})

		Convey("Stat existing empty directory → nil, IsDir", func() {
			dir := path.Join(root, "emptydir")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)

			fi, err := driver.Stat(dir)
			So(err, ShouldBeNil)
			So(fi.IsDir(), ShouldBeTrue)
		})

		Convey("List empty existing directory → [], nil (contrast object-storage empty List → PathNotFound)", func() {
			dir := path.Join(root, "empty-list")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)

			keys, err := driver.List(dir)
			So(err, ShouldBeNil)
			So(keys, ShouldResemble, []string{})
		})

		Convey("List directory with entries → paths, nil", func() {
			dir := path.Join(root, "with-entries")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "a"), []byte("1"), 0o600), ShouldBeNil)
			So(os.Mkdir(path.Join(dir, "b"), 0o755), ShouldBeNil)

			keys, err := driver.List(dir)
			So(err, ShouldBeNil)
			So(keys, ShouldContain, path.Join(dir, "a"))
			So(keys, ShouldContain, path.Join(dir, "b"))
		})

		Convey("List missing directory → PathNotFound", func() {
			_, err := driver.List(path.Join(root, "missing-dir"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("List permission denied → driver.Error, not PathNotFound", func() {
			// Root can still read mode 000 dirs; same guard as local_test.go.
			if os.Geteuid() == 0 {
				return
			}

			dir := path.Join(root, "noperm-list")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.Chmod(dir, 0o000), ShouldBeNil)
			defer func() { _ = os.Chmod(dir, 0o755) }()

			_, err := driver.List(dir)
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeFalse)

			var derr storagedriver.Error
			So(errors.As(err, &derr), ShouldBeTrue)
			So(derr.DriverName, ShouldEqual, "local")
		})

		Convey("Walk missing start path → PathNotFound from List", func() {
			err := driver.Walk(path.Join(root, "missing-walk"), func(_ storagedriver.FileInfo) error {
				return nil
			})
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("Walk real empty directory → nil (no callbacks)", func() {
			dir := path.Join(root, "empty-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)

			called := false
			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				called = true

				return nil
			})
			So(err, ShouldBeNil)
			So(called, ShouldBeFalse)
		})

		Convey("Walk mid-walk child vanished → skip PathNotFound on Stat, continue", func() {
			dir := path.Join(root, "vanish-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			// Lexicographic order: visit a-keep first, delete z-gone before it is Stat'd.
			So(os.Mkdir(path.Join(dir, "a-keep"), 0o755), ShouldBeNil)
			So(os.Mkdir(path.Join(dir, "z-gone"), 0o755), ShouldBeNil)

			seen := []string{}
			err := driver.Walk(dir, func(fi storagedriver.FileInfo) error {
				seen = append(seen, fi.Path())
				_ = os.RemoveAll(path.Join(dir, "z-gone"))

				return nil
			})
			So(err, ShouldBeNil)
			So(seen, ShouldContain, path.Join(dir, "a-keep"))
			So(seen, ShouldNotContain, path.Join(dir, "z-gone"))
		})

		Convey("WalkFn io.EOF → bare io.EOF (stop signal, not Transient)", func() {
			dir := path.Join(root, "eof-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "f"), []byte("x"), 0o600), ShouldBeNil)

			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				return io.EOF
			})
			So(err, ShouldNotBeNil)
			So(errors.Is(err, io.EOF), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeFalse)

			var derr storagedriver.Error
			So(errors.As(err, &derr), ShouldBeFalse)
		})

		Convey("WalkFn Detail-wrapped io.EOF → bare io.EOF", func() {
			dir := path.Join(root, "eof-detail-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "f"), []byte("x"), 0o600), ShouldBeNil)

			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				return storagedriver.Error{DriverName: "local", Detail: io.EOF}
			})
			So(errors.Is(err, io.EOF), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("WalkFn ErrSkipDir on file → nil", func() {
			dir := path.Join(root, "skip-file-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "f"), []byte("x"), 0o600), ShouldBeNil)

			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				return storagedriver.ErrSkipDir
			})
			So(err, ShouldBeNil)
		})

		Convey("WalkFn ErrSkipDir on file stops sibling iteration", func() {
			dir := path.Join(root, "skip-file-siblings")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			// Lexicographic: a-file before z-sibling
			So(os.WriteFile(path.Join(dir, "a-file"), []byte("x"), 0o600), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "z-sibling"), []byte("y"), 0o600), ShouldBeNil)

			var seen []string
			err := driver.Walk(dir, func(fi storagedriver.FileInfo) error {
				seen = append(seen, fi.Path())
				if fi.Path() == path.Join(dir, "a-file") {
					return storagedriver.ErrSkipDir
				}

				return nil
			})
			So(err, ShouldBeNil)
			So(seen, ShouldContain, path.Join(dir, "a-file"))
			So(seen, ShouldNotContain, path.Join(dir, "z-sibling"))
		})

		Convey("WalkFn ErrFilledBuffer → nil (stop signal, not Transient)", func() {
			dir := path.Join(root, "filled-buffer-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "f"), []byte("x"), 0o600), ShouldBeNil)

			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				return storagedriver.ErrFilledBuffer
			})
			So(err, ShouldBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("WalkFn ErrFilledBuffer in nested dir stops parent siblings", func() {
			dir := path.Join(root, "filled-nested")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			// Lexicographic order: a-subdir before z-sibling
			sub := path.Join(dir, "a-subdir")
			So(os.Mkdir(sub, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(sub, "inner"), []byte("x"), 0o600), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "z-sibling"), []byte("y"), 0o600), ShouldBeNil)

			var seen []string
			err := driver.Walk(dir, func(fi storagedriver.FileInfo) error {
				seen = append(seen, fi.Path())
				if fi.Path() == path.Join(sub, "inner") {
					return storagedriver.ErrFilledBuffer
				}

				return nil
			})
			So(err, ShouldBeNil)
			So(seen, ShouldContain, path.Join(dir, "a-subdir"))
			So(seen, ShouldContain, path.Join(sub, "inner"))
			So(seen, ShouldNotContain, path.Join(dir, "z-sibling"))
		})

		Convey("WalkFn generic error → unchanged (not Transient)", func() {
			dir := path.Join(root, "err-walk")
			So(os.Mkdir(dir, 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, "f"), []byte("x"), 0o600), ShouldBeNil)

			boom := errors.New("walk boom") //nolint:err113 // test
			err := driver.Walk(dir, func(_ storagedriver.FileInfo) error {
				return boom
			})
			So(err, ShouldEqual, boom)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(err, io.EOF), ShouldBeFalse)
		})

		Convey("Delete missing → PathNotFound (not idempotent)", func() {
			err := driver.Delete(path.Join(root, "no-delete-target"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("Reader missing → PathNotFound", func() {
			_, err := driver.Reader(path.Join(root, "no-reader"), 0)
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})
	})
}
