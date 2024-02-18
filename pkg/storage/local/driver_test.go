package local_test

import (
	"os"
	"path"
	"strings"
	"testing"

	storagedriver "github.com/docker/distribution/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/local"
)

func TestStorageDriver(t *testing.T) {
	driver := local.New(true)

	Convey("Test DirExists", t, func() {
		rootDir := t.TempDir()

		// Folder exists
		result := driver.DirExists(rootDir)
		So(result, ShouldBeTrue)

		// Folder name triggering ENAMETOOLONG
		result = driver.DirExists(path.Join(rootDir, strings.Repeat("1234567890", 1000)))
		So(result, ShouldBeFalse)

		// Folder which does not exist
		result = driver.DirExists(path.Join(rootDir, "someName"))
		So(result, ShouldBeFalse)

		// Path is actually a file
		fileName := "testFile"
		_, err := os.Create(path.Join(rootDir, fileName))
		So(err, ShouldBeNil)
		result = driver.DirExists(path.Join(rootDir, fileName))
		So(result, ShouldBeFalse)

		// Folder name triggering ENOTDIR a one of the parents is not a folder
		result = driver.DirExists(path.Join(rootDir, fileName, "someName"))
		So(result, ShouldBeFalse)

		// New folder created by driver
		repoName := "testRepo"
		err = driver.EnsureDir(path.Join(rootDir, repoName))
		So(err, ShouldBeNil)

		result = driver.DirExists(path.Join(rootDir, repoName))
		So(result, ShouldBeTrue)

		// Folder without permissions
		err = os.Chmod(path.Join(rootDir, repoName), 0o000)
		So(err, ShouldBeNil)
		defer os.Chmod(path.Join(rootDir, repoName), storageConstants.DefaultDirPerms) //nolint:errcheck

		result = driver.DirExists(path.Join(rootDir, repoName))
		So(result, ShouldBeTrue)
	})

	Convey("Test Walk", t, func() {
		Convey("Test all folders are walked and files are identified correctly", func() {
			rootDir := t.TempDir()
			err := driver.EnsureDir(path.Join(rootDir, "d1", "d11"))
			So(err, ShouldBeNil)
			err = driver.EnsureDir(path.Join(rootDir, "d1", "d12"))
			So(err, ShouldBeNil)
			err = driver.EnsureDir(path.Join(rootDir, "d2"))
			So(err, ShouldBeNil)
			_, err = os.Create(path.Join(rootDir, "d1", "d11", "f111"))
			So(err, ShouldBeNil)
			_, err = os.Create(path.Join(rootDir, "d2", "f21"))
			So(err, ShouldBeNil)

			fileList := []string{}
			folderList := []string{}

			err = driver.Walk(rootDir, func(fileInfo storagedriver.FileInfo) error {
				if fileInfo.IsDir() {
					folderList = append(folderList, fileInfo.Path())
				} else {
					fileList = append(fileList, fileInfo.Path())
				}

				return nil
			})
			So(err, ShouldBeNil)

			So(len(fileList), ShouldEqual, 2)
			So(fileList, ShouldContain, path.Join(rootDir, "d1", "d11", "f111"))
			So(fileList, ShouldContain, path.Join(rootDir, "d2", "f21"))
			So(len(folderList), ShouldEqual, 4)
			So(folderList, ShouldContain, path.Join(rootDir, "d1"))
			So(folderList, ShouldContain, path.Join(rootDir, "d1", "d11"))
			So(folderList, ShouldContain, path.Join(rootDir, "d1", "d12"))
			So(folderList, ShouldContain, path.Join(rootDir, "d2"))
		})

		Convey("Test deleting folders while walking raises doesn't raise errors", func() {
			rootDir := t.TempDir()
			err := driver.EnsureDir(path.Join(rootDir, "d1"))
			So(err, ShouldBeNil)
			err = driver.EnsureDir(path.Join(rootDir, "d2"))
			So(err, ShouldBeNil)

			// List/Sort d1 and d2, delete d2 while d1 is walked
			// While d2 is walked the PathNotFoundError should be ignored
			err = driver.Walk(rootDir, func(fileInfo storagedriver.FileInfo) error {
				return driver.Delete(path.Join(rootDir, "d2"))
			})
			So(err, ShouldBeNil)
		})
	})
}
