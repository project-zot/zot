package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"syscall"
	"time"
	"unicode/utf8"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/test/inject"
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
			return nil, driver.formatErr(storagedriver.PathNotFoundError{Path: path})
		}

		return nil, driver.formatErr(err)
	}

	reader, err := driver.openReader(file, path, offset)
	if err != nil {
		return nil, err
	}

	return errclass.WrapReadCloser(reader, driver.formatErr), nil
}

// openReader seeks an already-opened file and maps Seek / undershoot failures
// through formatErr. Separated so tests can inject Close failures (real *os.File
// Close almost never fails after a successful Seek).
func (driver *Driver) openReader(file readSeekCloser, path string, offset int64) (io.ReadCloser, error) {
	seekPos, err := file.Seek(offset, io.SeekStart)
	if err != nil {
		if cerr := file.Close(); cerr != nil {
			return nil, driver.formatErr(errors.Join(err, cerr))
		}

		return nil, driver.formatErr(err)
	} else if seekPos < offset {
		err := storagedriver.InvalidOffsetError{Path: path, Offset: offset}
		formatted := driver.formatErr(err)

		if cerr := file.Close(); cerr != nil {
			// Keep Close visible: formatErr's InvalidOffset arm returns only the
			// stamped typed error, so Join(offset, close) would drop close.
			return nil, errclass.Wrap(formatted, cerr)
		}

		return nil, formatted
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
	// Not idempotent: missing path → PathNotFound + Missing (unlike GCS/Azure).
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return driver.formatErr(err)
	} else if err != nil {
		return driver.formatErr(storagedriver.PathNotFoundError{Path: path})
	}

	return driver.formatErr(os.RemoveAll(path))
}

func (driver *Driver) Stat(path string) (storagedriver.FileInfo, error) {
	finfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, driver.formatErr(storagedriver.PathNotFoundError{Path: path})
		}

		return nil, driver.formatErr(err)
	}

	return fileInfo{
		path:     path,
		FileInfo: finfo,
	}, nil
}

func (driver *Driver) Writer(filepath string, isAppend bool) (storagedriver.FileWriter, error) {
	if isAppend {
		_, err := os.Stat(filepath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, driver.formatErr(storagedriver.PathNotFoundError{Path: filepath})
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

	if !isAppend {
		err := file.Truncate(0)
		if err != nil {
			if cerr := file.Close(); cerr != nil {
				return nil, driver.formatErr(errors.Join(err, cerr))
			}

			return nil, driver.formatErr(err)
		}
	} else {
		nbytes, err := file.Seek(0, io.SeekEnd)
		if err != nil {
			if cerr := file.Close(); cerr != nil {
				return nil, driver.formatErr(errors.Join(err, cerr))
			}

			return nil, driver.formatErr(err)
		}

		offset = nbytes
	}

	return newFileWriter(file, offset, driver.commit, driver.formatErr), nil
}

func (driver *Driver) WriteFile(filepath string, content []byte) (int, error) {
	writer, err := driver.Writer(filepath, false)
	if err != nil {
		return -1, err
	}

	nbytes, err := io.Copy(writer, bytes.NewReader(content))
	if err != nil {
		_ = writer.Cancel(context.Background())

		// Write already classifies; formatErr is idempotent via isClassified.
		return -1, driver.formatErr(err)
	}

	// Close classifies Flush/Sync/Close failures.
	return int(nbytes), writer.Close()
}

func (driver *Driver) Walk(path string, walkFn storagedriver.WalkFn) error {
	_, err := driver.doWalk(path, walkFn)
	if err == nil {
		return nil
	}

	// io.EOF is a Walk stop signal (e.g. GetNextRepository), not a storage failure.
	if isEOF(err) {
		return io.EOF
	}

	// List/Stat failures are already classified at their call sites.
	// WalkFn / application errors must not be stamped Transient.
	return err
}

// doWalk is the recursive walk body. ok is false when the walk should stop
// without error (ErrFilledBuffer), matching distribution WalkFallback.
func (driver *Driver) doWalk(path string, walkFn storagedriver.WalkFn) (bool, error) {
	children, err := driver.List(path)
	if err != nil {
		return false, err
	}

	sort.Stable(sort.StringSlice(children))

	for _, child := range children {
		// Calling driver.Stat for every entry is quite
		// expensive when running against backends with a slow Stat
		// implementation, such as s3. This is very likely a serious
		// performance bottleneck.
		fileInfo, err := driver.Stat(child)
		if err != nil {
			if errors.As(err, &storagedriver.PathNotFoundError{}) {
				// repository was removed in between listing and enumeration. Ignore it.
				continue
			}

			return false, err
		}

		err = walkFn(fileInfo)

		switch {
		case err == nil && fileInfo.IsDir():
			ok, walkErr := driver.doWalk(child, walkFn)
			if walkErr != nil || !ok {
				return ok, walkErr
			}
		case errors.Is(err, storagedriver.ErrSkipDir):
			// Stop iteration if it's a file, otherwise noop if it's a directory
			if !fileInfo.IsDir() {
				return false, nil
			}
		case errors.Is(err, storagedriver.ErrFilledBuffer):
			// Walk control signal (enough entries); stop all frames, nil at Walk.
			return false, nil
		case err != nil:
			return false, err
		}
	}

	return true, nil
}

// isEOF reports whether err is bare io.EOF or io.EOF wrapped in storagedriver.Error.Detail.
func isEOF(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}

	if storageErr, ok := errors.AsType[storagedriver.Error](err); ok {
		return errors.Is(storageErr.Detail, io.EOF)
	}

	return false
}

func (driver *Driver) List(fullpath string) ([]string, error) {
	entries, err := os.ReadDir(fullpath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, driver.formatErr(storagedriver.PathNotFoundError{Path: fullpath})
		}

		return nil, driver.formatErr(err)
	}

	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, path.Join(fullpath, entry.Name()))
	}

	return keys, nil
}

func (driver *Driver) Move(sourcePath string, destPath string) error {
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return driver.formatErr(storagedriver.PathNotFoundError{Path: sourcePath})
	}

	if err := os.MkdirAll(path.Dir(destPath), storageConstants.DefaultDirPerms); err != nil {
		return driver.formatErr(err)
	}

	// Use renameReplace so an existing destination is replaced (POSIX rename); on Windows,
	// os.Rename does not overwrite an existing file — see driver_unix.go / driver_windows.go.
	return driver.formatErr(renameReplace(sourcePath, destPath, driver.commit))
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
	// Remove(dest) then Link(src, dest) would delete the only copy when paths name
	// the same inode (byte-identical, cleaned equivalents like ./, or hard links).
	// SameFile is false when either path is missing, so Link("/missing","/missing")
	// still surfaces PathNotFound instead of a silent no-op.
	if driver.SameFile(src, dest) {
		return nil
	}

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return driver.formatErr(err)
	}

	if err := os.Link(src, dest); err != nil {
		// os.Link ENOENT covers a missing src or a missing parent of dest.
		// Attribute PathNotFound to the side that is actually absent; if unclear,
		// leave raw ENOENT for formatErr (Missing, no empty-Path invent).
		if os.IsNotExist(err) {
			if _, serr := os.Lstat(src); os.IsNotExist(serr) {
				return driver.formatErr(storagedriver.PathNotFoundError{Path: src})
			}

			destDir := path.Dir(dest)
			if _, derr := os.Lstat(destDir); os.IsNotExist(derr) {
				return driver.formatErr(storagedriver.PathNotFoundError{Path: destDir})
			}
		}

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

func (driver *Driver) RedirectURL(_ *http.Request, _ string) (string, error) {
	return "", nil
}

// formatErr maps local OS / distribution errors onto PathNotFound / Invalid* and
// zot storage sentinels (Missing / Transient / Permanent).
//
// Local has no network surface, so OS/syscall failures are Permanent by default
// (permission, invalid path, ENOSPC, EROFS, …) rather than an errno allowlist.
// Only a small retryable set is Transient; non-OS / unknown errors stay Transient
// (never invent Missing).
func (driver *Driver) formatErr(err error) error {
	if err == nil {
		return nil
	}

	if pathNotFound, ok := errors.AsType[storagedriver.PathNotFoundError](err); ok {
		pathNotFound.DriverName = driver.Name()

		// Mark the stamped value only — Wrap(stamped, err) would stack two typed
		// values that differ only by DriverName (no Is on distribution types).
		return errclass.MarkMissing(pathNotFound)
	}

	if invalidPath, ok := errors.AsType[storagedriver.InvalidPathError](err); ok {
		invalidPath.DriverName = driver.Name()

		return errclass.MarkPermanent(invalidPath)
	}

	if invalidOffset, ok := errors.AsType[storagedriver.InvalidOffsetError](err); ok {
		invalidOffset.DriverName = driver.Name()

		return errclass.MarkPermanent(invalidOffset)
	}

	detail := err

	if storageErr, ok := errors.AsType[storagedriver.Error](err); ok && storageErr.Detail != nil {
		detail = storageErr.Detail
	}

	// Error does not Unwrap Detail — keep detail reachable for errors.Is/As.
	inner := err
	if !errors.Is(err, detail) {
		inner = errclass.Wrap(err, detail)
	}

	// Raw ENOENT (e.g. Move rename race, ambiguous Link) is definite absence.
	// Do not invent PathNotFoundError with an empty Path — PathError/LinkError
	// already carry the useful paths under Detail.
	if errors.Is(detail, os.ErrNotExist) {
		return errclass.MarkMissing(errclass.Wrap(storagedriver.Error{
			DriverName: driver.Name(),
			Detail:     detail,
		}, inner))
	}

	wrapped := errclass.Wrap(storagedriver.Error{
		DriverName: driver.Name(),
		Detail:     detail,
	}, inner)

	if isLocalTransientOSError(detail) {
		return errclass.MarkTransient(wrapped)
	}

	// Any other OS/syscall failure is definite local backend state.
	if isLocalOSError(detail) {
		return errclass.MarkPermanent(wrapped)
	}

	// Non-OS / unknown → Transient (never invent Missing).
	return errclass.MarkTransient(wrapped)
}

// isLocalTransientOSError is the small set of local errno values worth retrying.
func isLocalTransientOSError(err error) bool {
	return errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EBUSY) ||
		errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE)
}

// isLocalOSError reports filesystem / syscall failures (PathError, Errno, …).
func isLocalOSError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, os.ErrPermission) ||
		errors.Is(err, os.ErrInvalid) ||
		errors.Is(err, os.ErrClosed) {
		return true
	}

	if _, ok := errors.AsType[syscall.Errno](err); ok {
		return true
	}

	if _, ok := errors.AsType[*os.PathError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*os.LinkError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*os.SyscallError](err); ok {
		return true
	}

	return false
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

// fileInternal defines the interface for file operations (internal).
type fileInternal interface {
	io.WriteCloser
	Sync() error
	Name() string
}

// readSeekCloser is the Seek/Close surface used by openReader (*os.File satisfies it).
type readSeekCloser interface {
	io.ReadCloser
	Seek(offset int64, whence int) (int64, error)
}

type fileWriter struct {
	file      fileInternal
	size      int64
	bw        *bufio.Writer
	closed    bool
	committed bool
	cancelled bool
	commit    bool
	formatErr func(error) error
}

func newFileWriter(file fileInternal, size int64, commit bool, formatErr func(error) error) *fileWriter {
	return &fileWriter{
		file:      file,
		size:      size,
		commit:    commit,
		bw:        bufio.NewWriter(file),
		formatErr: formatErr,
	}
}

// NewFileWriter creates a new fileWriter for testing purposes.
// OS errors are returned unclassified unless formatErr is set via Writer().
func NewFileWriter(file fileInternal, size int64, commit bool) *fileWriter {
	return newFileWriter(file, size, commit, nil)
}

// classify maps OS I/O errors through formatErr when present. Application
// sentinels (ErrFileAlready*) must not be passed here.
func (fw *fileWriter) classify(err error) error {
	if err == nil {
		return nil
	}

	if fw.formatErr != nil {
		return fw.formatErr(err)
	}

	return err
}

func (fw *fileWriter) Write(buf []byte) (int, error) {
	switch {
	case fw.closed:
		return 0, zerr.ErrFileAlreadyClosed
	case fw.committed:
		return 0, zerr.ErrFileAlreadyCommitted
	case fw.cancelled:
		return 0, zerr.ErrFileAlreadyCancelled
	}

	n, err := fw.bw.Write(buf)
	fw.size += int64(n)

	return n, fw.classify(err)
}

func (fw *fileWriter) Size() int64 {
	return fw.size
}

func (fw *fileWriter) Close() error {
	if fw.closed {
		return zerr.ErrFileAlreadyClosed
	}

	var closeErr error

	if err := fw.bw.Flush(); err != nil {
		closeErr = fw.classify(err)
	} else if fw.commit {
		if err := inject.Error(fw.file.Sync()); err != nil {
			closeErr = fw.classify(err)
		}
	}

	// Always release the underlying descriptor. A Flush/Sync capacity error
	// (ENOSPC/EDQUOT) must not leave the fd open, or an unlinked path can keep
	// its blocks until process exit.
	if err := inject.Error(fw.file.Close()); err != nil && closeErr == nil {
		closeErr = fw.classify(err)
	}

	fw.closed = true

	return closeErr
}

func (fw *fileWriter) Cancel(_ context.Context) error {
	if fw.closed {
		return zerr.ErrFileAlreadyClosed
	}

	fw.cancelled = true
	fw.file.Close()

	return fw.classify(os.Remove(fw.file.Name()))
}

func (fw *fileWriter) Commit(_ context.Context) error {
	switch {
	case fw.closed:
		return zerr.ErrFileAlreadyClosed
	case fw.committed:
		return zerr.ErrFileAlreadyCommitted
	case fw.cancelled:
		return zerr.ErrFileAlreadyCancelled
	}

	if err := fw.bw.Flush(); err != nil {
		return fw.classify(err)
	}

	if fw.commit {
		if err := fw.file.Sync(); err != nil {
			return fw.classify(err)
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
