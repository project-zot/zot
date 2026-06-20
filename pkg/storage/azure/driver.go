package azure

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"

	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

type Driver struct {
	store storagedriver.StorageDriver
}

func New(storeDriver storagedriver.StorageDriver) *Driver {
	return &Driver{store: storeDriver}
}

func (driver *Driver) Name() string {
	return storageConstants.AzureStorageDriverName
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

	return reader, nil
}

func (driver *Driver) ReadFile(path string) ([]byte, error) {
	content, err := driver.store.GetContent(context.Background(), path)
	if err != nil {
		return nil, driver.formatErr(err, path)
	}

	return content, nil
}

func (driver *Driver) Delete(path string) error {
	err := driver.store.Delete(context.Background(), path)
	if err == nil {
		return nil
	}

	// Format the error first to convert Azure-specific 404 errors to PathNotFoundError.
	formattedErr := driver.formatErr(err, path)

	// Check if the formatted error is PathNotFoundError.
	var pathNotFoundErr storagedriver.PathNotFoundError
	if errors.As(formattedErr, &pathNotFoundErr) {
		// In Azure Blob, directories are just blob-name prefixes, so once all blobs under a
		// prefix are gone the "directory" no longer exists. Treat deleting a missing path as a
		// no-op so Delete is idempotent (mirrors the gcs driver behavior).
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

func (driver *Driver) Writer(filepath string, append bool) (storagedriver.FileWriter, error) { //nolint:predeclared
	writer, err := driver.store.Writer(context.Background(), filepath, append)
	if err != nil {
		return nil, driver.formatErr(err, filepath)
	}

	return writer, nil
}

func (driver *Driver) WriteFile(filepath string, content []byte) (int, error) {
	var n int

	stwr, err := driver.store.Writer(context.Background(), filepath, false)
	if err != nil {
		return -1, driver.formatErr(err, filepath)
	}
	defer stwr.Close()

	if n, err = stwr.Write(content); err != nil {
		return -1, driver.formatErr(err, filepath)
	}

	if err := stwr.Commit(context.Background()); err != nil {
		return -1, driver.formatErr(err, filepath)
	}

	return n, nil
}

func (driver *Driver) Walk(path string, f storagedriver.WalkFn) error {
	err := driver.store.Walk(context.Background(), path, f)
	// io.EOF is used by callers (e.g. GetNextRepository) as a stop signal, not an error, so return directly.
	if isEOF(err) {
		return io.EOF
	}

	return driver.formatErr(err, path)
}

// isEOF checks whether err is directly io.EOF or if io.EOF is wrapped into storagedriver.Error.Detail.
func isEOF(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}

	var storageErr storagedriver.Error
	if errors.As(err, &storageErr) {
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
		// Compare modification times with Equal, not ==: time.Time values parsed from
		// Azure's LastModified header carry differing monotonic/location data, so == reports
		// two stats of the same blob as unequal. That would make dedupe Link a blob onto
		// itself and overwrite it with an empty placeholder.
		if fi1.IsDir() == fi2.IsDir() &&
			fi1.ModTime().Equal(fi2.ModTime()) &&
			fi1.Path() == fi2.Path() &&
			fi1.Size() == fi2.Size() {
			return true
		}
	}

	return false
}

// Link puts an empty file that will act like a link between the original file and deduped one.
// Because Azure Blob doesn't support symlinks, wherever the storage encounters an empty file it
// will get the original one from cache.
func (driver *Driver) Link(src, dest string) error {
	return driver.formatErr(driver.store.PutContent(context.Background(), dest, []byte{}), dest)
}

func (driver *Driver) RedirectURL(r *http.Request, path string) (string, error) {
	redirectURL, err := driver.store.RedirectURL(r, path)

	return redirectURL, driver.formatErr(err, path)
}

// formatErr converts Azure-specific not-found errors to PathNotFoundError. The upstream azure
// driver usually returns PathNotFoundError already (handled by the first cases); the default case
// is a defensive fallback that maps Azure blob "not found" responses to PathNotFoundError.
func (driver *Driver) formatErr(err error, path string) error {
	switch actual := err.(type) { //nolint: errorlint
	case nil:
		return nil
	case storagedriver.PathNotFoundError:
		actual.DriverName = driver.Name()
		if actual.Path == "" && path != "" {
			actual.Path = path
		}

		return actual
	case storagedriver.InvalidPathError:
		actual.DriverName = driver.Name()

		return actual
	case storagedriver.InvalidOffsetError:
		actual.DriverName = driver.Name()

		return actual
	default:
		// Check for Azure-specific not-found errors by unwrapping the error chain.
		errToCheck := err
		for errToCheck != nil {
			errStr := errToCheck.Error()
			isNotFound := strings.Contains(errStr, "BlobNotFound") ||
				strings.Contains(errStr, "ResourceNotFound") ||
				strings.Contains(errStr, "Error 404") ||
				strings.Contains(errStr, "404 The specified blob does not exist") ||
				strings.Contains(errStr, "does not exist")

			if isNotFound {
				return storagedriver.PathNotFoundError{
					DriverName: driver.Name(),
					Path:       path,
				}
			}

			if unwrappable, ok := errToCheck.(interface{ Unwrap() error }); ok {
				errToCheck = unwrappable.Unwrap()
			} else {
				break
			}
		}

		storageError := storagedriver.Error{
			DriverName: driver.Name(),
			Detail:     err,
		}

		return storageError
	}
}
