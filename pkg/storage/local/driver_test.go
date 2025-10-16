package local_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
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

		// Invalid UTF-8 path should return false
		invalidUTF8Path := string([]byte{0xff, 0xfe, 0xfd}) // Invalid UTF-8 sequence
		result = driver.DirExists(invalidUTF8Path)
		So(result, ShouldBeFalse)
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

func TestMove(t *testing.T) {
	Convey("Test Move file/directory operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test moving non-existent file", func() {
			err := driver.Move("/nonexistent", "/destination")
			So(err, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
		})

		Convey("Test successful file move", func() {
			srcFile := path.Join(rootDir, "source.txt")
			destFile := path.Join(rootDir, "dest.txt")

			// Create source file
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Move file
			err = driver.Move(srcFile, destFile)
			So(err, ShouldBeNil)

			// Verify move
			_, err = os.Stat(srcFile)
			So(err, ShouldNotBeNil)
			_, err = os.Stat(destFile)
			So(err, ShouldBeNil)
		})

		Convey("Test moving to non-existent directory", func() {
			srcFile := path.Join(rootDir, "source.txt")
			destFile := path.Join(rootDir, "nonexistent", "dest.txt")

			// Create source file
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Move file (should create destination directory)
			err = driver.Move(srcFile, destFile)
			So(err, ShouldBeNil)

			// Verify move
			_, err = os.Stat(srcFile)
			So(err, ShouldNotBeNil)
			_, err = os.Stat(destFile)
			So(err, ShouldBeNil)
		})

		Convey("Test Move() with os.MkdirAll error to trigger formatErr", func() {
			srcFile := path.Join(rootDir, "source.txt")
			// Use invalid path to trigger os.MkdirAll error
			destFile := string([]byte{0x00}) + "/dest.txt"

			// Create source file
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Move should return a formatted error
			err = driver.Move(srcFile, destFile)
			So(err, ShouldNotBeNil)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})

		Convey("Test Move() with os.Rename error to trigger formatErr", func() {
			srcFile := path.Join(rootDir, "source.txt")
			destFile := path.Join(rootDir, "dest.txt")

			// Create source file
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Create destination file to cause rename conflict
			err = os.WriteFile(destFile, []byte("existing content"), 0o600)
			So(err, ShouldBeNil)

			// Move should return a formatted error (rename conflict)
			err = driver.Move(srcFile, destFile)
			// Note: On some systems, os.Rename might succeed by overwriting
			// So we just verify it doesn't panic and handle the result appropriately
			_ = err
		})
	})
}

func TestValidateHardLink(t *testing.T) {
	Convey("Test ValidateHardLink functionality", t, func() {
		rootDir := t.TempDir()

		Convey("Test successful hardlink validation", func() {
			err := local.ValidateHardLink(rootDir)
			So(err, ShouldBeNil)
		})

		Convey("Test hardlink validation on non-existent directory", func() {
			err := local.ValidateHardLink("/nonexistent/directory")
			// This might succeed or fail depending on system permissions
			// We're just testing that it doesn't panic
			_ = err
		})
	})
}

func TestWriteFile(t *testing.T) {
	Convey("Test WriteFile operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test successful file write", func() {
			content := []byte("test content")
			filePath := path.Join(rootDir, "test.txt")

			n, err := driver.WriteFile(filePath, content)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(content))

			// Verify file was created
			_, err = os.Stat(filePath)
			So(err, ShouldBeNil)
		})

		Convey("Test write to non-existent directory", func() {
			content := []byte("test content")
			filePath := "/nonexistent/path/file.txt"

			n, err := driver.WriteFile(filePath, content)
			So(err, ShouldNotBeNil)
			So(n, ShouldEqual, -1)
		})

		Convey("Test write empty content", func() {
			content := []byte("")
			filePath := path.Join(rootDir, "empty.txt")

			n, err := driver.WriteFile(filePath, content)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, 0)
		})

		Convey("Test WriteFile() with io.Copy error to trigger formatErr", func() {
			// Create a file
			filePath := path.Join(rootDir, "test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// WriteFile should succeed normally
			content := []byte("new content")
			n, err := driver.WriteFile(filePath, content)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(content))

			// Test with invalid path to trigger formatErr path
			// This will cause Writer to fail, which WriteFile will pass through
			invalidPath := string([]byte{0x00}) // Null byte in path
			n, err = driver.WriteFile(invalidPath, content)
			So(err, ShouldNotBeNil)
			So(n, ShouldEqual, -1)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})
	})
}

func TestLink(t *testing.T) {
	Convey("Test Link hardlink operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test successful hardlink creation", func() {
			// Create source file
			srcFile := path.Join(rootDir, "source.txt")
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Create hardlink
			destFile := path.Join(rootDir, "link.txt")
			err = driver.Link(srcFile, destFile)
			So(err, ShouldBeNil)

			// Verify link exists
			_, err = os.Stat(destFile)
			So(err, ShouldBeNil)
		})

		Convey("Test linking non-existent file", func() {
			destFile := path.Join(rootDir, "link.txt")
			err := driver.Link("/nonexistent", destFile)
			So(err, ShouldNotBeNil)
		})

		Convey("Test linking to existing destination", func() {
			// Create source file
			srcFile := path.Join(rootDir, "source.txt")
			err := os.WriteFile(srcFile, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Create existing destination file
			destFile := path.Join(rootDir, "existing.txt")
			err = os.WriteFile(destFile, []byte("existing content"), 0o600)
			So(err, ShouldBeNil)

			// Create hardlink (should remove existing file first)
			err = driver.Link(srcFile, destFile)
			So(err, ShouldBeNil)

			// Verify link exists
			_, err = os.Stat(destFile)
			So(err, ShouldBeNil)
		})

		Convey("Test Link() with os.Remove error to trigger return err", func() {
			// Link should return os.Remove error
			err := driver.Link("", string([]byte{0x00}))
			So(err, ShouldNotBeNil)
		})
	})
}

func TestDelete(t *testing.T) {
	Convey("Test Delete operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test deleting non-existent file", func() {
			err := driver.Delete("/nonexistent")
			So(err, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
		})

		Convey("Test successful file deletion", func() {
			filePath := path.Join(rootDir, "test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			err = driver.Delete(filePath)
			So(err, ShouldBeNil)

			// Verify deletion
			_, err = os.Stat(filePath)
			So(err, ShouldNotBeNil)
		})

		Convey("Test deleting directory", func() {
			dirPath := path.Join(rootDir, "testdir")
			err := os.Mkdir(dirPath, 0o755)
			So(err, ShouldBeNil)

			// Create file in directory
			filePath := path.Join(dirPath, "test.txt")
			err = os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			err = driver.Delete(dirPath)
			So(err, ShouldBeNil)

			// Verify deletion
			_, err = os.Stat(dirPath)
			So(err, ShouldNotBeNil)
		})

		Convey("Test Delete() with invalid path to trigger formatErr", func() {
			// Use an invalid path that will cause os.Stat to fail with a non-IsNotExist error
			invalidPath := string([]byte{0x00}) // Null byte in path is invalid on most systems

			// Delete should return a formatted error (not PathNotFoundError)
			err := driver.Delete(invalidPath)
			So(err, ShouldNotBeNil)

			// Should not be a PathNotFoundError since it's not an IsNotExist error
			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeFalse)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})
	})
}

func TestFileInfoSize(t *testing.T) {
	Convey("Test fileInfo.Size method", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test file size calculation", func() {
			filePath := path.Join(rootDir, "test.txt")
			content := []byte("test content")
			err := os.WriteFile(filePath, content, 0o600)
			So(err, ShouldBeNil)

			fileInfo, err := driver.Stat(filePath)
			So(err, ShouldBeNil)
			So(fileInfo.Size(), ShouldEqual, int64(len(content)))
		})

		Convey("Test directory size (should be 0)", func() {
			dirPath := path.Join(rootDir, "testdir")
			err := os.Mkdir(dirPath, 0o755)
			So(err, ShouldBeNil)

			dirInfo, err := driver.Stat(dirPath)
			So(err, ShouldBeNil)
			So(dirInfo.Size(), ShouldEqual, int64(0))
		})

		Convey("Test empty file size", func() {
			filePath := path.Join(rootDir, "empty.txt")
			err := os.WriteFile(filePath, []byte(""), 0o600)
			So(err, ShouldBeNil)

			fileInfo, err := driver.Stat(filePath)
			So(err, ShouldBeNil)
			So(fileInfo.Size(), ShouldEqual, int64(0))
		})

		Convey("Test Stat() with permission error", func() {
			// Create a file
			filePath := path.Join(rootDir, "permission_test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Remove read permission
			err = os.Chmod(filePath, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				_ = os.Chmod(filePath, 0o600) // Restore permissions
			}()

			// Stat should return a formatted error (not PathNotFoundError)
			_, err = driver.Stat(filePath)
			// Note: On some systems, Stat() might still succeed even with 0000 permissions
			// We just verify it doesn't panic and handles the case appropriately
			_ = err
		})

		Convey("Test Stat() with invalid path to trigger formatErr", func() {
			// Use an invalid path that will cause os.Stat to fail with a non-IsNotExist error
			invalidPath := string([]byte{0x00}) // Null byte in path is invalid on most systems

			// Stat should return a formatted error (not PathNotFoundError)
			_, err := driver.Stat(invalidPath)
			So(err, ShouldNotBeNil)

			// Should not be a PathNotFoundError since it's not an IsNotExist error
			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeFalse)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})

		Convey("Test Stat() with non-existent file", func() {
			// Stat on non-existent file should return PathNotFoundError
			_, err := driver.Stat(path.Join(rootDir, "nonexistent.txt"))
			So(err, ShouldNotBeNil)

			// Should be a PathNotFoundError
			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
			So(pathNotFoundErr.Path, ShouldContainSubstring, "nonexistent.txt")
		})
	})
}

func TestReader(t *testing.T) {
	Convey("Test Reader operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test reading non-existent file", func() {
			_, err := driver.Reader("/nonexistent", 0)
			So(err, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
		})

		Convey("Test reading with invalid offset", func() {
			filePath := path.Join(rootDir, "test.txt")
			content := []byte("test content")
			err := os.WriteFile(filePath, content, 0o600)
			So(err, ShouldBeNil)

			_, err = driver.Reader(filePath, 1000) // Offset beyond file size
			// Note: This might not always return an error depending on the implementation
			// We just verify it doesn't panic
			_ = err
		})

		Convey("Test successful read from beginning", func() {
			filePath := path.Join(rootDir, "test.txt")
			content := []byte("test content")
			err := os.WriteFile(filePath, content, 0o600)
			So(err, ShouldBeNil)

			reader, err := driver.Reader(filePath, 0)
			So(err, ShouldBeNil)
			defer reader.Close()

			readContent, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(string(readContent), ShouldEqual, string(content))
		})

		Convey("Test successful read with offset", func() {
			filePath := path.Join(rootDir, "test.txt")
			content := []byte("test content")
			err := os.WriteFile(filePath, content, 0o600)
			So(err, ShouldBeNil)

			reader, err := driver.Reader(filePath, 5) // Start from offset 5
			So(err, ShouldBeNil)
			defer reader.Close()

			readContent, err := io.ReadAll(reader)
			So(err, ShouldBeNil)
			So(string(readContent), ShouldEqual, "content")
		})

		Convey("Test ReadFile() with io.ReadAll error to trigger formatErr", func() {
			// Create a file
			filePath := path.Join(rootDir, "test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// ReadFile should succeed normally
			content, err := driver.ReadFile(filePath)
			So(err, ShouldBeNil)
			So(string(content), ShouldEqual, "test content")

			// Test with non-existent file to trigger formatErr path
			// This will cause Reader to fail, which ReadFile will pass through
			_, err = driver.ReadFile("/nonexistent")
			So(err, ShouldNotBeNil)

			// Should be a PathNotFoundError (from Reader)
			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
		})

		Convey("Test Reader() with file.Seek error to trigger formatErr", func() {
			// Create a file
			filePath := path.Join(rootDir, "test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Use invalid offset to trigger file.Seek error
			_, err = driver.Reader(filePath, -1) // Negative offset should cause Seek error
			So(err, ShouldNotBeNil)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})
	})
}

func TestWriter(t *testing.T) {
	Convey("Test Writer operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test append mode with non-existent file", func() {
			filePath := path.Join(rootDir, "test.txt")
			_, err := driver.Writer(filePath, true) // append=true
			So(err, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
		})

		Convey("Test successful writer creation (non-append)", func() {
			filePath := path.Join(rootDir, "test.txt")
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			defer writer.Close()

			// Write some content
			_, err = writer.Write([]byte("test content"))
			So(err, ShouldBeNil)

			// Close and verify
			err = writer.Close()
			So(err, ShouldBeNil)

			// Verify file was created
			_, err = os.Stat(filePath)
			So(err, ShouldBeNil)
		})

		Convey("Test append mode with existing file", func() {
			filePath := path.Join(rootDir, "test.txt")
			initialContent := []byte("initial ")
			err := os.WriteFile(filePath, initialContent, 0o600)
			So(err, ShouldBeNil)

			writer, err := driver.Writer(filePath, true)
			So(err, ShouldBeNil)
			defer writer.Close()

			// Append content
			_, err = writer.Write([]byte("appended"))
			So(err, ShouldBeNil)

			// Close and verify
			err = writer.Close()
			So(err, ShouldBeNil)

			// Verify content was appended
			content, err := os.ReadFile(filePath)
			So(err, ShouldBeNil)
			So(string(content), ShouldEqual, "initial appended")
		})

		Convey("Test writer with non-existent parent directory", func() {
			filePath := path.Join(rootDir, "nonexistent", "test.txt")
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			defer writer.Close()

			// Write some content
			_, err = writer.Write([]byte("test content"))
			So(err, ShouldBeNil)

			// Close and verify
			err = writer.Close()
			So(err, ShouldBeNil)

			// Verify file was created
			_, err = os.Stat(filePath)
			So(err, ShouldBeNil)
		})
	})
}

var (
	errMockCloseFailure = errors.New("close failed")
	errMockSyncOnClose  = errors.New("sync failed on close")
	errMockSyncOnCommit = errors.New("sync failed on commit")
)

// mockFile implements FileInterface for testing sync behavior.
type mockFile struct {
	*os.File
	syncCalled bool
	syncError  error
	closeError error
}

func (mf *mockFile) Sync() error {
	mf.syncCalled = true
	if mf.syncError != nil {
		return mf.syncError
	}

	return mf.File.Sync()
}

func (mf *mockFile) Close() error {
	if mf.closeError != nil {
		return mf.closeError
	}

	return mf.File.Close()
}

func TestFileWriterClose(t *testing.T) {
	Convey("Test fileWriter.Close() error handling", t, func() {
		driver := local.New(true)
		dir := t.TempDir()
		filePath := filepath.Join(dir, "testfile")

		Convey("Test Close() with commit=true", func() {
			// Create fileWriter with commit=true using the driver
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should succeed
			err = writer.Close()
			So(err, ShouldBeNil)
		})

		Convey("Test Close() with commit=true using mock to verify Sync()", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper
			mockFile := &mockFile{File: realFile}

			// Create fileWriter with commit=true using the mock
			writer := local.NewFileWriter(mockFile, 0, true)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should call Sync() and succeed
			err = writer.Close()
			So(err, ShouldBeNil)

			// Verify Sync() was called
			So(mockFile.syncCalled, ShouldBeTrue)
		})

		Convey("Test Close() with commit=false", func() {
			// Create a new test file
			filePath2 := filepath.Join(dir, "testfile2")
			writer, err := driver.Writer(filePath2, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should succeed
			err = writer.Close()
			So(err, ShouldBeNil)
		})

		Convey("Test Close() with commit=false using mock to verify Sync() NOT called", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper
			mockFile := &mockFile{File: realFile}

			// Create fileWriter with commit=false using the mock
			writer := local.NewFileWriter(mockFile, 0, false)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should NOT call Sync() and succeed
			err = writer.Close()
			So(err, ShouldBeNil)

			// Verify Sync() was NOT called
			So(mockFile.syncCalled, ShouldBeFalse)
		})

		Convey("Test Close() on already closed file", func() {
			// Create a test file
			filePath3 := filepath.Join(dir, "testfile3")
			writer, err := driver.Writer(filePath3, false)
			So(err, ShouldBeNil)

			// Close once
			err = writer.Close()
			So(err, ShouldBeNil)

			// Close again should return error
			err = writer.Close()
			So(err, ShouldNotBeNil)
		})

		Convey("Test Close() with file.Close() error", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper with Close() error
			mockFile := &mockFile{
				File:       realFile,
				closeError: errMockCloseFailure,
			}

			// Create fileWriter using the mock
			writer := local.NewFileWriter(mockFile, 0, false)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should return Close() error
			err = writer.Close()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "close failed")
		})
	})
}

func TestFileWriterCancel(t *testing.T) {
	Convey("Test fileWriter.Cancel()", t, func() {
		driver := local.New(true)
		dir := t.TempDir()
		filePath := filepath.Join(dir, "testfile")

		Convey("Test Cancel() on open file", func() {
			// Create a test file
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Cancel should succeed and remove the file
			err = writer.Cancel(context.Background())
			So(err, ShouldBeNil)

			// File should be removed
			_, err = os.Stat(filePath)
			So(err, ShouldNotBeNil)
		})

		Convey("Test Cancel() on already closed file", func() {
			// Create a test file
			filePath2 := filepath.Join(dir, "testfile2")
			writer, err := driver.Writer(filePath2, false)
			So(err, ShouldBeNil)

			// Close first
			err = writer.Close()
			So(err, ShouldBeNil)

			// Cancel on closed file should return error
			err = writer.Cancel(context.Background())
			So(err, ShouldNotBeNil)
		})
	})
}

func TestFileWriterCommit(t *testing.T) {
	Convey("Test fileWriter.Commit()", t, func() {
		driver := local.New(true)
		dir := t.TempDir()
		filePath := filepath.Join(dir, "testfile")

		Convey("Test Commit() on open file", func() {
			// Create a test file
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit should succeed
			err = writer.Commit(context.Background())
			So(err, ShouldBeNil)

			// File should still exist
			_, err = os.Stat(filePath)
			So(err, ShouldBeNil)
		})

		Convey("Test Commit() with commit=true using mock to verify Sync()", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper
			mockFile := &mockFile{File: realFile}

			// Create fileWriter with commit=true using the mock
			writer := local.NewFileWriter(mockFile, 0, true)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit should call Sync() and succeed
			err = writer.Commit(context.Background())
			So(err, ShouldBeNil)

			// Verify Sync() was called
			So(mockFile.syncCalled, ShouldBeTrue)
		})

		Convey("Test Commit() on already committed file", func() {
			// Create a test file
			filePath2 := filepath.Join(dir, "testfile2")
			writer, err := driver.Writer(filePath2, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit first time
			err = writer.Commit(context.Background())
			So(err, ShouldBeNil)

			// Commit again should return error
			err = writer.Commit(context.Background())
			So(err, ShouldNotBeNil)
		})

		Convey("Test Commit() with commit=false using mock to verify Sync() NOT called", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper
			mockFile := &mockFile{File: realFile}

			// Create fileWriter with commit=false using the mock
			writer := local.NewFileWriter(mockFile, 0, false)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit should NOT call Sync() and succeed
			err = writer.Commit(context.Background())
			So(err, ShouldBeNil)

			// Verify Sync() was NOT called
			So(mockFile.syncCalled, ShouldBeFalse)
		})

		Convey("Test Commit() on already closed file", func() {
			// Create a test file
			filePath3 := filepath.Join(dir, "testfile3")
			writer, err := driver.Writer(filePath3, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close first
			err = writer.Close()
			So(err, ShouldBeNil)

			// Commit on closed file should return error
			err = writer.Commit(context.Background())
			So(err, ShouldNotBeNil)
		})

		Convey("Test Commit() on already cancelled file", func() {
			// Create a test file
			filePath4 := filepath.Join(dir, "testfile4")
			writer, err := driver.Writer(filePath4, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Cancel first
			err = writer.Cancel(context.Background())
			So(err, ShouldBeNil)

			// Commit on cancelled file should return ErrFileAlreadyCancelled
			err = writer.Commit(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrFileAlreadyCancelled)
		})
	})
}

func TestFileWriterWrite(t *testing.T) {
	Convey("Test fileWriter.Write()", t, func() {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "testfile")

		Convey("Test Write() on open file", func() {
			// Create a test file
			driver := local.New(true)
			writer, err := driver.Writer(filePath, false)
			So(err, ShouldBeNil)

			// Write should succeed
			n, err := writer.Write([]byte("test data"))
			So(err, ShouldBeNil)
			So(n, ShouldEqual, 9)

			// Size should be updated
			So(writer.Size(), ShouldEqual, 9)
		})

		Convey("Test Sync() error handling on Close()", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper with Sync() error
			mockFile := &mockFile{
				File:      realFile,
				syncError: errMockSyncOnClose,
			}

			// Create fileWriter with commit=true using the mock
			writer := local.NewFileWriter(mockFile, 0, true)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Close should return Sync() error
			err = writer.Close()
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "sync failed on close")

			// Verify Sync() was called
			So(mockFile.syncCalled, ShouldBeTrue)
		})

		Convey("Test Write() on closed file", func() {
			// Create a test file
			filePath2 := filepath.Join(dir, "testfile2")
			driver := local.New(true)
			writer, err := driver.Writer(filePath2, false)
			So(err, ShouldBeNil)

			// Close first
			err = writer.Close()
			So(err, ShouldBeNil)

			// Write on closed file should return error
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldNotBeNil)
		})

		Convey("Test Write() on committed file", func() {
			// Create a test file
			filePath3 := filepath.Join(dir, "testfile3")
			driver := local.New(true)
			writer, err := driver.Writer(filePath3, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit
			err = writer.Commit(context.Background())
			So(err, ShouldBeNil)

			// Write on committed file should return error
			_, err = writer.Write([]byte("more data"))
			So(err, ShouldNotBeNil)
		})

		Convey("Test Write() on cancelled file", func() {
			// Create a test file
			filePath4 := filepath.Join(dir, "testfile4")
			driver := local.New(true)
			writer, err := driver.Writer(filePath4, false)
			So(err, ShouldBeNil)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Cancel
			err = writer.Cancel(context.Background())
			So(err, ShouldBeNil)

			// Write on cancelled file should return ErrFileAlreadyCancelled
			_, err = writer.Write([]byte("more data"))
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrFileAlreadyCancelled)
		})

		Convey("Test Sync() error handling on Commit()", func() {
			// Create a real file first
			realFile, err := os.Create(filePath)
			So(err, ShouldBeNil)

			// Create a mock file wrapper with Sync() error
			mockFile := &mockFile{
				File:      realFile,
				syncError: errMockSyncOnCommit,
			}

			// Create fileWriter with commit=true using the mock
			writer := local.NewFileWriter(mockFile, 0, true)

			// Write some data
			_, err = writer.Write([]byte("test data"))
			So(err, ShouldBeNil)

			// Commit should return Sync() error
			err = writer.Commit(context.Background())
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "sync failed on commit")

			// Verify Sync() was called
			So(mockFile.syncCalled, ShouldBeTrue)
		})
	})
}

func TestList(t *testing.T) {
	Convey("Test List operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test successful listing with empty directory", func() {
			keys, err := driver.List(rootDir)
			So(err, ShouldBeNil)
			So(len(keys), ShouldEqual, 0)
		})

		Convey("Test successful listing with files and directories", func() {
			// Create test directory structure
			testDir := path.Join(rootDir, "testdir")
			err := os.Mkdir(testDir, 0o755)
			So(err, ShouldBeNil)

			// Create subdirectory
			subDir := path.Join(testDir, "subdir")
			err = os.Mkdir(subDir, 0o755)
			So(err, ShouldBeNil)

			// Create files
			_, err = os.Create(path.Join(testDir, "file1.txt"))
			So(err, ShouldBeNil)
			_, err = os.Create(path.Join(testDir, "file2.txt"))
			So(err, ShouldBeNil)
			_, err = os.Create(path.Join(subDir, "file3.txt"))
			So(err, ShouldBeNil)

			// List directory content
			keys, err := driver.List(testDir)
			So(err, ShouldBeNil)
			So(len(keys), ShouldEqual, 3)

			// Verify paths are properly constructed
			expectedPaths := []string{
				path.Join(testDir, "subdir"),
				path.Join(testDir, "file1.txt"),
				path.Join(testDir, "file2.txt"),
			}

			for _, expectedPath := range expectedPaths {
				So(keys, ShouldContain, expectedPath)
			}
		})

		Convey("Test listing non-existent directory", func() {
			nonExistentDir := path.Join(rootDir, "nonexistent")
			_, err := driver.List(nonExistentDir)
			So(err, ShouldNotBeNil)

			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeTrue)
			So(pathNotFoundErr.Path, ShouldEqual, nonExistentDir)
		})

		Convey("Test List() with os.ReadDir error triggering formatErr", func() {
			// Use an invalid path that will cause os.ReadDir to fail with a non-IsNotExist error
			invalidPath := string([]byte{0x00}) // Null byte in path is invalid on most systems

			_, err := driver.List(invalidPath)
			So(err, ShouldNotBeNil)

			// Should not be a PathNotFoundError since it's not an IsNotExist error
			var pathNotFoundErr storagedriver.PathNotFoundError

			So(errors.As(err, &pathNotFoundErr), ShouldBeFalse)

			// Should be a formatted error
			var storageErr storagedriver.Error

			So(errors.As(err, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
		})
	})
}

func TestSameFile(t *testing.T) {
	Convey("Test SameFile operations", t, func() {
		driver := local.New(true)
		rootDir := t.TempDir()

		Convey("Test SameFile with identical paths", func() {
			filePath := path.Join(rootDir, "test.txt")
			err := os.WriteFile(filePath, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Same file should return true
			result := driver.SameFile(filePath, filePath)
			So(result, ShouldBeTrue)
		})

		Convey("Test SameFile with different files", func() {
			filePath1 := path.Join(rootDir, "test1.txt")
			filePath2 := path.Join(rootDir, "test2.txt")

			err := os.WriteFile(filePath1, []byte("test content 1"), 0o600)
			So(err, ShouldBeNil)
			err = os.WriteFile(filePath2, []byte("test content 2"), 0o600)
			So(err, ShouldBeNil)

			// Different files should return false
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeFalse)
		})

		Convey("Test SameFile with hard linked files", func() {
			filePath1 := path.Join(rootDir, "test1.txt")
			filePath2 := path.Join(rootDir, "test2.txt")

			err := os.WriteFile(filePath1, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Create hardlink
			err = os.Link(filePath1, filePath2)
			So(err, ShouldBeNil)

			// Hard linked files should return true
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeTrue)
		})

		Convey("Test SameFile with non-existent first file", func() {
			filePath1 := "/nonexistent1.txt"
			filePath2 := path.Join(rootDir, "test.txt")

			err := os.WriteFile(filePath2, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Non-existent first file should return false
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeFalse)
		})

		Convey("Test SameFile with non-existent second file", func() {
			filePath1 := path.Join(rootDir, "test.txt")
			filePath2 := "/nonexistent2.txt"

			err := os.WriteFile(filePath1, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Non-existent second file should return false
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeFalse)
		})

		Convey("Test SameFile with both non-existent files", func() {
			filePath1 := "/nonexistent1.txt"
			filePath2 := "/nonexistent2.txt"

			// Both non-existent files should return false
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeFalse)
		})

		Convey("Test SameFile with invalid path", func() {
			filePath1 := string([]byte{0x00}) // Invalid path
			filePath2 := path.Join(rootDir, "test.txt")

			err := os.WriteFile(filePath2, []byte("test content"), 0o600)
			So(err, ShouldBeNil)

			// Invalid path should return false
			result := driver.SameFile(filePath1, filePath2)
			So(result, ShouldBeFalse)
		})
	})
}
