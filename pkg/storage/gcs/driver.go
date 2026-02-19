package gcs

import (
	"context"
	"errors"
	"io"
	"strings"

	// Add gcs support.
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/gcs"

	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
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

	// Format the error first to convert GCS-specific 404 errors to PathNotFoundError
	formattedErr := driver.formatErr(err, path)

	// Check if the formatted error is PathNotFoundError
	var pathNotFoundErr storagedriver.PathNotFoundError
	if errors.As(formattedErr, &pathNotFoundErr) {
		// For directory deletion, if the path doesn't exist, treat it as success (idempotent delete)
		// In GCS, directories are just prefixes, so if all objects are deleted,
		// the directory may already be gone (especially with eventual consistency in storage-testbench)
		// This makes Delete idempotent: deleting a non-existent path is a no-op
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
	return driver.formatErr(driver.store.Walk(context.Background(), path, f), path)
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
// Because gcs doesn't support symlinks, wherever the storage will encounter an empty file, it will get the original one
// from cache.
func (driver *Driver) Link(src, dest string) error {
	return driver.formatErr(driver.store.PutContent(context.Background(), dest, []byte{}), dest)
}

// formatErr converts GCS-specific 404/not found errors to PathNotFoundError.
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
		// Check for GCS-specific 404/not found errors by unwrapping the error chain
		errToCheck := err
		for errToCheck != nil {
			errStr := errToCheck.Error()
			isNotFound := strings.Contains(errStr, "object doesn't exist") ||
				strings.Contains(errStr, "Error 404") ||
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
