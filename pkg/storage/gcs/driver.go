package gcs

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	gcsstorage "cloud.google.com/go/storage"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs" // register driver
	"google.golang.org/api/googleapi"

	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

type Driver struct {
	store storagedriver.StorageDriver
}

func New(storeDriver storagedriver.StorageDriver) *Driver {
	return &Driver{store: storeDriver}
}

func (driver *Driver) Name() string {
	return storageConstants.GCSStorageDriverName
}

func (driver *Driver) EnsureDir(path string) error {
	return nil
}

func (driver *Driver) DirExists(path string) bool {
	if fi, err := driver.Stat(path); err == nil && fi.IsDir() {
		return true
	}

	return false
}

func (driver *Driver) Reader(path string, offset int64) (io.ReadCloser, error) {
	reader, err := driver.store.Reader(context.Background(), path, offset)
	if err != nil {
		return nil, driver.formatErr(err, path)
	}

	return errclass.WrapReadCloser(reader, func(err error) error {
		return driver.formatErr(err, path)
	}), nil
}

func (driver *Driver) ReadFile(path string) ([]byte, error) {
	content, err := driver.store.GetContent(context.Background(), path)
	if err != nil {
		return nil, driver.formatErr(err, path)
	}

	return content, nil
}

func (driver *Driver) Delete(path string) error {
	// Upstream returns PathNotFound (never zot ErrStorageMissing). formatErr may also
	// synthesize PathNotFound from typed/string not-found fallbacks, then MarkMissing.
	err := driver.store.Delete(context.Background(), path)
	if err == nil {
		return nil
	}

	formattedErr := driver.formatErr(err, path)

	// Idempotent delete: PathNotFound after formatErr is a no-op. In GCS, directories
	// are just prefixes, so once all objects under a prefix are gone the "directory"
	// may already be absent (especially with eventual consistency).
	if _, ok := errors.AsType[storagedriver.PathNotFoundError](formattedErr); ok {
		return nil
	}

	return formattedErr
}

func (driver *Driver) Stat(path string) (storagedriver.FileInfo, error) {
	fileInfo, err := driver.store.Stat(context.Background(), path)
	if err != nil {
		return nil, driver.formatErr(err, path)
	}

	return fileInfo, nil
}

func (driver *Driver) Writer(filepath string, isAppend bool) (storagedriver.FileWriter, error) {
	writer, err := driver.store.Writer(context.Background(), filepath, isAppend)
	if err != nil {
		return nil, driver.formatErr(err, filepath)
	}

	return errclass.WrapFileWriter(writer, func(err error) error {
		return driver.formatErr(err, filepath)
	}), nil
}

func (driver *Driver) WriteFile(filepath string, content []byte) (int, error) {
	stwr, err := driver.Writer(filepath, false)
	if err != nil {
		return -1, err
	}

	n, err := stwr.Write(content)
	if err != nil {
		_ = stwr.Close()

		return -1, err
	}

	if err := stwr.Commit(context.Background()); err != nil {
		_ = stwr.Close()

		return -1, err
	}

	if err := stwr.Close(); err != nil {
		return n, err
	}

	return n, nil
}

func (driver *Driver) Walk(path string, f storagedriver.WalkFn) error {
	var callbackErr error

	err := driver.store.Walk(context.Background(), path, func(fileInfo storagedriver.FileInfo) error {
		walkErr := f(fileInfo)
		if walkErr == nil {
			return nil
		}

		// Keep Walk control signals for the store; capture real application errors.
		if errors.Is(walkErr, io.EOF) ||
			errors.Is(walkErr, storagedriver.ErrSkipDir) ||
			errors.Is(walkErr, storagedriver.ErrFilledBuffer) {
			return walkErr
		}

		callbackErr = walkErr

		return walkErr
	})

	// io.EOF is used by callers (e.g. GetNextRepository) as a stop signal, not an error, so return directly.
	if isEOF(err) {
		return io.EOF
	}

	// Application WalkFn errors must not be stamped Transient via formatErr.
	if callbackErr != nil {
		return callbackErr
	}

	return driver.formatErr(err, path)
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
	list, err := driver.store.List(context.Background(), fullpath)
	if err != nil {
		return nil, driver.formatErr(err, fullpath)
	}

	return list, nil
}

func (driver *Driver) Move(sourcePath string, destPath string) error {
	return driver.formatErr(driver.store.Move(context.Background(), sourcePath, destPath), sourcePath)
}

func (driver *Driver) SameFile(path1, path2 string) bool {
	fi1, _ := driver.store.Stat(context.Background(), path1)

	fi2, _ := driver.store.Stat(context.Background(), path2)

	if fi1 != nil && fi2 != nil {
		if fi1.IsDir() == fi2.IsDir() &&
			fi1.ModTime() == fi2.ModTime() &&
			fi1.Path() == fi2.Path() &&
			fi1.Size() == fi2.Size() {
			return true
		}
	}

	return false
}

// Link puts an empty file that will act like a link between the original file and deduped one.
// Because GCS doesn't support symlinks, wherever the storage encounters an empty file it will
// get the original one from cache.
func (driver *Driver) Link(src, dest string) error {
	// PutContent ignores src; writing an empty object onto the origin would destroy content.
	if src == dest {
		return nil
	}

	return driver.formatErr(driver.store.PutContent(context.Background(), dest, []byte{}), dest)
}

func (driver *Driver) RedirectURL(r *http.Request, path string) (string, error) {
	redirectURL, err := driver.store.RedirectURL(r, path)

	return redirectURL, driver.formatErr(err, path)
}

// formatErr maps GCS / distribution errors onto PathNotFound / Invalid* and zot
// storage sentinels (Missing / Transient / Permanent). Upstream often already
// returns PathNotFound; typed GCS not-found and narrow string fallbacks are
// converted here. Auth 401/403 are Permanent. Unclassified errors become
// Transient (never invent Missing).
func (driver *Driver) formatErr(err error, path string) error {
	if err == nil {
		return nil
	}

	if errclass.IsWriterLifecycleError(err) {
		return err
	}

	if pathNotFound, ok := errors.AsType[storagedriver.PathNotFoundError](err); ok {
		pathNotFound.DriverName = driver.Name()
		if pathNotFound.Path == "" && path != "" {
			pathNotFound.Path = path
		}

		return errclass.MarkMissing(errclass.Wrap(pathNotFound, err))
	}

	if invalidPath, ok := errors.AsType[storagedriver.InvalidPathError](err); ok {
		invalidPath.DriverName = driver.Name()

		return errclass.MarkPermanent(errclass.Wrap(invalidPath, err))
	}

	if invalidOffset, ok := errors.AsType[storagedriver.InvalidOffsetError](err); ok {
		invalidOffset.DriverName = driver.Name()

		return errclass.MarkPermanent(errclass.Wrap(invalidOffset, err))
	}

	if unsupported, ok := errors.AsType[storagedriver.ErrUnsupportedMethod](err); ok {
		unsupported.DriverName = driver.Name()

		return errclass.MarkPermanent(errclass.Wrap(unsupported, err))
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

	if isGCSNotFound(detail) {
		return errclass.MarkMissing(errclass.Wrap(storagedriver.PathNotFoundError{
			DriverName: driver.Name(),
			Path:       path,
		}, inner))
	}

	wrapped := storagedriver.Error{
		DriverName: driver.Name(),
		Detail:     detail,
	}

	// Order matches matrix: Permanent (auth) before Transient (throttle/5xx).
	if isGCSPermanent(detail) {
		return errclass.MarkPermanent(errclass.Wrap(wrapped, inner))
	}

	if isGCSTransient(detail) {
		return errclass.MarkTransient(errclass.Wrap(wrapped, inner))
	}

	// Unsure → Transient (do not invent Missing).
	return errclass.MarkTransient(errclass.Wrap(wrapped, inner))
}

func isGCSNotFound(err error) bool {
	if errors.Is(err, gcsstorage.ErrObjectNotExist) {
		return true
	}

	if gerr, ok := errors.AsType[*googleapi.Error](err); ok && gerr.Code == http.StatusNotFound {
		return true
	}

	// Narrow string fallback for messages that are not typed googleapi.Error.
	// Avoid broad "does not exist" (over-classifies timeouts).
	msg := err.Error()

	return strings.Contains(msg, "object doesn't exist") ||
		strings.Contains(msg, "Error 404")
}

func isGCSPermanent(err error) bool {
	if gerr, ok := errors.AsType[*googleapi.Error](err); ok {
		return gerr.Code == http.StatusUnauthorized ||
			gerr.Code == http.StatusForbidden
	}

	// Distribution Move formats non-404 copier failures with %v, which drops
	// *googleapi.Error. Match the same "Error NNN" wording used for Missing 404.
	msg := err.Error()

	return strings.Contains(msg, "Error 401") ||
		strings.Contains(msg, "Error 403")
}

func isGCSTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if gerr, ok := errors.AsType[*googleapi.Error](err); ok {
		return gerr.Code == http.StatusTooManyRequests ||
			gerr.Code == http.StatusRequestTimeout ||
			gerr.Code >= http.StatusInternalServerError
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "temporary failure") ||
		strings.Contains(msg, "i/o timeout")
}
