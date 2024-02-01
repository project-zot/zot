package s3

import (
	"context"
	"io"

	// Add s3 support.
	"github.com/docker/distribution/registry/storage/driver"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"

	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
)

type Driver struct {
	store driver.StorageDriver
}

func New(storeDriver driver.StorageDriver) *Driver {
	return &Driver{store: storeDriver}
}

func (driver *Driver) Name() string {
	return storageConstants.S3StorageDriverName
}

func (driver *Driver) EnsureDir(path string) error {
	return nil
}

func (driver *Driver) DirExists(path string) bool {
	if fi, err := driver.store.Stat(context.Background(), path); err == nil && fi.IsDir() {
		return true
	}

	return false
}

func (driver *Driver) Reader(path string, offset int64) (io.ReadCloser, error) {
	return driver.store.Reader(context.Background(), path, offset)
}

func (driver *Driver) ReadFile(path string) ([]byte, error) {
	return driver.store.GetContent(context.Background(), path)
}

func (driver *Driver) Delete(path string) error {
	return driver.store.Delete(context.Background(), path)
}

func (driver *Driver) Stat(path string) (driver.FileInfo, error) {
	return driver.store.Stat(context.Background(), path)
}

func (driver *Driver) Writer(filepath string, append bool) (driver.FileWriter, error) { //nolint:predeclared
	return driver.store.Writer(context.Background(), filepath, append)
}

func (driver *Driver) WriteFile(filepath string, content []byte) (int, error) {
	var n int

	if stwr, err := driver.store.Writer(context.Background(), filepath, false); err == nil {
		defer stwr.Close()

		if n, err = stwr.Write(content); err != nil {
			return -1, err
		}

		if err := stwr.Commit(); err != nil {
			return -1, err
		}
	} else {
		return -1, err
	}

	return n, nil
}

func (driver *Driver) Walk(path string, f driver.WalkFn) error {
	return driver.store.Walk(context.Background(), path, f)
}

func (driver *Driver) List(fullpath string) ([]string, error) {
	return driver.store.List(context.Background(), fullpath)
}

func (driver *Driver) Move(sourcePath string, destPath string) error {
	return driver.store.Move(context.Background(), sourcePath, destPath)
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

/*
	Link put an empty file that will act like a link between the original file and deduped one

because s3 doesn't support symlinks, wherever the storage will encounter an empty file, it will get the original one
from cache.
*/
func (driver *Driver) Link(src, dest string) error {
	return driver.store.PutContent(context.Background(), dest, []byte{})
}
