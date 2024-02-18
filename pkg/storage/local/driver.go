package local

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"time"
	"unicode/utf8"

	storagedriver "github.com/docker/distribution/registry/storage/driver"

	zerr "zotregistry.dev/zot/errors"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/test/inject"
)

type Driver struct {
	commit bool
}

func New(commit bool) *Driver {
	return &Driver{commit: commit}
}

func (driver *Driver) Name() string {
	return storageConstants.LocalStorageDriverName
}

func (driver *Driver) EnsureDir(path string) error {
	err := os.MkdirAll(path, storageConstants.DefaultDirPerms)

	return driver.formatErr(err)
}

func (driver *Driver) DirExists(path string) bool {
	if !utf8.ValidString(path) {
		return false
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		// if os.Stat returns any error, fileInfo will be nil
		// we can't check if the path is a directory using fileInfo if we received an error
		// let's assume the directory doesn't exist in all error cases
		// see possible errors http://man.he.net/man2/newfstatat
		return false
	}

	if !fileInfo.IsDir() {
		return false
	}

	return true
}

func (driver *Driver) Reader(path string, offset int64) (io.ReadCloser, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, storageConstants.DefaultFilePerms)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storagedriver.PathNotFoundError{Path: path}
		}

		return nil, driver.formatErr(err)
	}

	seekPos, err := file.Seek(offset, io.SeekStart)
	if err != nil {
		file.Close()

		return nil, driver.formatErr(err)
	} else if seekPos < offset {
		file.Close()

		return nil, storagedriver.InvalidOffsetError{Path: path, Offset: offset}
	}

	return file, nil
}

func (driver *Driver) ReadFile(path string) ([]byte, error) {
	reader, err := driver.Reader(path, 0)
	if err != nil {
		return nil, err
	}

	defer reader.Close()

	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, driver.formatErr(err)
	}

	return buf, nil
}

func (driver *Driver) Delete(path string) error {
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return driver.formatErr(err)
	} else if err != nil {
		return storagedriver.PathNotFoundError{Path: path}
	}

	return os.RemoveAll(path)
}

func (driver *Driver) Stat(path string) (storagedriver.FileInfo, error) {
	fi, err := os.Stat(path) //nolint: varnamelen
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storagedriver.PathNotFoundError{Path: path}
		}

		return nil, driver.formatErr(err)
	}

	return fileInfo{
		path:     path,
		FileInfo: fi,
	}, nil
}

func (driver *Driver) Writer(filepath string, append bool) (storagedriver.FileWriter, error) { //nolint:predeclared
	if append {
		_, err := os.Stat(filepath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, storagedriver.PathNotFoundError{Path: filepath}
			}

			return nil, driver.formatErr(err)
		}
	}

	parentDir := path.Dir(filepath)
	if err := os.MkdirAll(parentDir, storageConstants.DefaultDirPerms); err != nil {
		return nil, driver.formatErr(err)
	}

	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE, storageConstants.DefaultFilePerms)
	if err != nil {
		return nil, driver.formatErr(err)
	}

	var offset int64

	if !append {
		err := file.Truncate(0)
		if err != nil {
			file.Close()

			return nil, driver.formatErr(err)
		}
	} else {
		n, err := file.Seek(0, io.SeekEnd) //nolint: varnamelen
		if err != nil {
			file.Close()

			return nil, driver.formatErr(err)
		}
		offset = n
	}

	return newFileWriter(file, offset, driver.commit), nil
}

func (driver *Driver) WriteFile(filepath string, content []byte) (int, error) {
	writer, err := driver.Writer(filepath, false)
	if err != nil {
		return -1, err
	}

	nbytes, err := io.Copy(writer, bytes.NewReader(content))
	if err != nil {
		_ = writer.Cancel()

		return -1, driver.formatErr(err)
	}

	return int(nbytes), writer.Close()
}

func (driver *Driver) Walk(path string, walkFn storagedriver.WalkFn) error {
	children, err := driver.List(path)
	if err != nil {
		return err
	}

	sort.Stable(sort.StringSlice(children))

	for _, child := range children {
		// Calling driver.Stat for every entry is quite
		// expensive when running against backends with a slow Stat
		// implementation, such as s3. This is very likely a serious
		// performance bottleneck.
		fileInfo, err := driver.Stat(child)
		if err != nil {
			switch errors.As(err, &storagedriver.PathNotFoundError{}) {
			case true:
				// repository was removed in between listing and enumeration. Ignore it.
				continue
			default:
				return err
			}
		}
		err = walkFn(fileInfo)
		//nolint: gocritic
		if err == nil && fileInfo.IsDir() {
			if err := driver.Walk(child, walkFn); err != nil {
				return err
			}
		} else if errors.Is(err, storagedriver.ErrSkipDir) {
			// Stop iteration if it's a file, otherwise noop if it's a directory
			if !fileInfo.IsDir() {
				return nil
			}
		} else if err != nil {
			return driver.formatErr(err)
		}
	}

	return nil
}

func (driver *Driver) List(fullpath string) ([]string, error) {
	dir, err := os.Open(fullpath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storagedriver.PathNotFoundError{Path: fullpath}
		}

		return nil, driver.formatErr(err)
	}

	defer dir.Close()

	fileNames, err := dir.Readdirnames(0)
	if err != nil {
		return nil, driver.formatErr(err)
	}

	keys := make([]string, 0, len(fileNames))
	for _, fileName := range fileNames {
		keys = append(keys, path.Join(fullpath, fileName))
	}

	return keys, nil
}

func (driver *Driver) Move(sourcePath string, destPath string) error {
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return storagedriver.PathNotFoundError{Path: sourcePath}
	}

	if err := os.MkdirAll(path.Dir(destPath), storageConstants.DefaultDirPerms); err != nil {
		return driver.formatErr(err)
	}

	return driver.formatErr(os.Rename(sourcePath, destPath))
}

func (driver *Driver) SameFile(path1, path2 string) bool {
	file1, err := os.Stat(path1)
	if err != nil {
		return false
	}

	file2, err := os.Stat(path2)
	if err != nil {
		return false
	}

	return os.SameFile(file1, file2)
}

func (driver *Driver) Link(src, dest string) error {
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := os.Link(src, dest); err != nil {
		return driver.formatErr(err)
	}

	/* also update the modtime, so that gc won't remove recently linked blobs
	otherwise ifBlobOlderThan(gcDelay) will return the modtime of the inode */
	currentTime := time.Now() //nolint: gosmopolitan
	if err := os.Chtimes(dest, currentTime, currentTime); err != nil {
		return driver.formatErr(err)
	}

	return nil
}

func (driver *Driver) formatErr(err error) error {
	switch actual := err.(type) { //nolint: errorlint
	case nil:
		return nil
	case storagedriver.PathNotFoundError:
		actual.DriverName = driver.Name()

		return actual
	case storagedriver.InvalidPathError:
		actual.DriverName = driver.Name()

		return actual
	case storagedriver.InvalidOffsetError:
		actual.DriverName = driver.Name()

		return actual
	default:
		storageError := storagedriver.Error{
			DriverName: driver.Name(),
			Enclosed:   err,
		}

		return storageError
	}
}

type fileInfo struct {
	os.FileInfo
	path string
}

// asserts fileInfo implements storagedriver.FileInfo.
var _ storagedriver.FileInfo = fileInfo{}

// Path provides the full path of the target of this file info.
func (fi fileInfo) Path() string {
	return fi.path
}

// Size returns current length in bytes of the file. The return value can
// be used to write to the end of the file at path. The value is
// meaningless if IsDir returns true.
func (fi fileInfo) Size() int64 {
	if fi.IsDir() {
		return 0
	}

	return fi.FileInfo.Size()
}

// ModTime returns the modification time for the file. For backends that
// don't have a modification time, the creation time should be returned.
func (fi fileInfo) ModTime() time.Time {
	return fi.FileInfo.ModTime()
}

// IsDir returns true if the path is a directory.
func (fi fileInfo) IsDir() bool {
	return fi.FileInfo.IsDir()
}

type fileWriter struct {
	file      *os.File
	size      int64
	bw        *bufio.Writer
	closed    bool
	committed bool
	cancelled bool
	commit    bool
}

func newFileWriter(file *os.File, size int64, commit bool) *fileWriter {
	return &fileWriter{
		file:   file,
		size:   size,
		commit: commit,
		bw:     bufio.NewWriter(file),
	}
}

func (fw *fileWriter) Write(buf []byte) (int, error) {
	//nolint: gocritic
	if fw.closed {
		return 0, zerr.ErrFileAlreadyClosed
	} else if fw.committed {
		return 0, zerr.ErrFileAlreadyCommitted
	} else if fw.cancelled {
		return 0, zerr.ErrFileAlreadyCancelled
	}

	n, err := fw.bw.Write(buf)
	fw.size += int64(n)

	return n, err
}

func (fw *fileWriter) Size() int64 {
	return fw.size
}

func (fw *fileWriter) Close() error {
	if fw.closed {
		return zerr.ErrFileAlreadyClosed
	}

	if err := fw.bw.Flush(); err != nil {
		return err
	}

	if fw.commit {
		if err := inject.Error(fw.file.Sync()); err != nil {
			return err
		}
	}

	if err := inject.Error(fw.file.Close()); err != nil {
		return err
	}

	fw.closed = true

	return nil
}

func (fw *fileWriter) Cancel() error {
	if fw.closed {
		return zerr.ErrFileAlreadyClosed
	}

	fw.cancelled = true
	fw.file.Close()

	return os.Remove(fw.file.Name())
}

func (fw *fileWriter) Commit() error {
	//nolint: gocritic
	if fw.closed {
		return zerr.ErrFileAlreadyClosed
	} else if fw.committed {
		return zerr.ErrFileAlreadyCommitted
	} else if fw.cancelled {
		return zerr.ErrFileAlreadyCancelled
	}

	if err := fw.bw.Flush(); err != nil {
		return err
	}

	if fw.commit {
		if err := fw.file.Sync(); err != nil {
			return err
		}
	}

	fw.committed = true

	return nil
}

func ValidateHardLink(rootDir string) error {
	if err := os.MkdirAll(rootDir, storageConstants.DefaultDirPerms); err != nil {
		return err
	}

	err := os.WriteFile(path.Join(rootDir, "hardlinkcheck.txt"),
		[]byte("check whether hardlinks work on filesystem"), storageConstants.DefaultFilePerms)
	if err != nil {
		return err
	}

	err = os.Link(path.Join(rootDir, "hardlinkcheck.txt"), path.Join(rootDir, "duphardlinkcheck.txt"))
	if err != nil {
		// Remove hardlinkcheck.txt if hardlink fails
		zerr := os.RemoveAll(path.Join(rootDir, "hardlinkcheck.txt"))
		if zerr != nil {
			return zerr
		}

		return err
	}

	err = os.RemoveAll(path.Join(rootDir, "hardlinkcheck.txt"))
	if err != nil {
		return err
	}

	return os.RemoveAll(path.Join(rootDir, "duphardlinkcheck.txt"))
}
