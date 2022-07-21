package storage

import (
	"path"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/database"
)

const (
	BlobsCache              = "blobs"
	DBExtensionName         = ".db"
	dbCacheLockCheckTimeout = 10 * time.Second
)

type Driver struct {
	rootDir     string
	db          *bbolt.DB
	log         zlog.Logger
	useRelPaths bool // weather or not to use relative paths, should be true for filesystem and false for s3
}

type BoltDBDriverParameters struct {
	RootDir, Name string
	UseRelPaths   bool
}

const (
	driverName         = "boltdb"
	defaultRootDir     = "/tmp/zot/boltDB"
	defaultName        = "cacheBoltDB"
	defaultUseRelPaths = false
)

// Implements the storage.DatabaseDriverFactory interface.
type boltDBDriverFactory struct{}

func (factory *boltDBDriverFactory) Create(parameters interface{}, log zlog.Logger) (database.Driver, error) {
	properParameters, ok := parameters.(BoltDBDriverParameters)
	if !ok {
		panic("Failed type assertion")
	}

	return FromParameters(properParameters, log)
}

// nolint:gochecknoinits
func init() {
	database.Register(driverName, &boltDBDriverFactory{})
}

func FromParameters(parameters BoltDBDriverParameters, log zlog.Logger) (*Driver, error) {
	params := &BoltDBDriverParameters{
		RootDir:     defaultRootDir,
		Name:        defaultName,
		UseRelPaths: defaultUseRelPaths,
	}

	if parameters.RootDir != "" {
		params.RootDir = parameters.RootDir
	}

	if parameters.Name != "" {
		params.Name = parameters.Name
	}
	params.UseRelPaths = parameters.UseRelPaths

	return NewCache(*params, log), nil
}

func NewCache(parameters BoltDBDriverParameters, log zlog.Logger) *Driver {
	dbPath := path.Join(parameters.RootDir, parameters.Name+DBExtensionName)
	dbOpts := &bbolt.Options{
		Timeout:      dbCacheLockCheckTimeout,
		FreelistType: bbolt.FreelistArrayType,
	}

	cacheDB, err := bbolt.Open(dbPath, 0o600, dbOpts) //nolint:gomnd
	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create cache db")

		return nil
	}

	if err := cacheDB.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(BlobsCache)); err != nil {
			// this is a serious failure
			log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create a root bucket")

			return err
		}

		return nil
	}); err != nil {
		// something went wrong
		log.Error().Err(err).Msg("unable to create a cache")

		return nil
	}

	return &Driver{rootDir: parameters.RootDir, db: cacheDB, useRelPaths: parameters.UseRelPaths, log: log}
}

func (d *Driver) Name() string {
	return "boltdb"
}

func (d *Driver) PutBlob(digest, path string) error {
	if path == "" {
		d.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest).Msg("empty path provided")

		return errors.ErrEmptyValue
	}

	// use only relative (to rootDir) paths on blobs
	var err error
	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("unable to get relative path")
		}
	}

	if err := d.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket, err := root.CreateBucketIfNotExists([]byte(digest))
		if err != nil {
			// this is a serious failure
			d.log.Error().Err(err).Str("bucket", digest).Msg("unable to create a bucket")

			return err
		}

		if err := bucket.Put([]byte(path), nil); err != nil {
			d.log.Error().Err(err).Str("bucket", digest).Str("value", path).Msg("unable to put record")

			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *Driver) GetBlob(digest string) (string, error) {
	var blobPath strings.Builder

	if err := d.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		b := root.Bucket([]byte(digest))
		if b != nil {
			// get first key
			c := b.Cursor()
			k, _ := c.First()
			blobPath.WriteString(string(k))

			return nil
		}

		return errors.ErrCacheMiss
	}); err != nil {
		return "", err
	}

	return blobPath.String(), nil
}

func (d *Driver) HasBlob(digest, blob string) bool {
	if err := d.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		b := root.Bucket([]byte(digest))
		if b == nil {
			return errors.ErrCacheMiss
		}

		if b.Get([]byte(blob)) == nil {
			return errors.ErrCacheMiss
		}

		return nil
	}); err != nil {
		return false
	}

	return true
}

func (d *Driver) DeleteBlob(digest, path string) error {
	// use only relative (to rootDir) paths on blobs
	var err error
	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("unable to get relative path")
		}
	}

	if err := d.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		if err := bucket.Delete([]byte(path)); err != nil {
			d.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

			return err
		}

		cur := bucket.Cursor()

		k, _ := cur.First()
		if k == nil {
			d.log.Debug().Str("digest", digest).Str("path", path).Msg("deleting empty bucket")
			if err := root.DeleteBucket([]byte(digest)); err != nil {
				d.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
