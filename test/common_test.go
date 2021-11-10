// +build extended

package test_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	. "github.com/anuvu/zot/test"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir, err := ioutil.TempDir("", "copy-files-test")
		if err != nil {
			panic(err)
		}

		err = CopyFiles("data", dir)
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(dir)
		err = CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir, err := ioutil.TempDir("", "copy-files-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		err = os.Chmod(dir, 0300)
		So(err, ShouldBeNil)

		err = CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir, err := ioutil.TempDir("", "copy-files-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		sdir := "subdir"
		err = os.Mkdir(path.Join(dir, sdir), 0300)
		So(err, ShouldBeNil)

		err = CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir, err := ioutil.TempDir("", "copy-files-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		filePath := path.Join(dir, "file.txt")
		err = ioutil.WriteFile(filePath, []byte("some dummy file content"), 0644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0300)
		So(err, ShouldBeNil)

		err = CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
}
