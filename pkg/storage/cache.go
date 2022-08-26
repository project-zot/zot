package storage

import (
	"path"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
)

const (
	UserCache               = "users"
	BlobsCache              = "blobs"
	DBExtensionName         = ".db"
	dbCacheLockCheckTimeout = 10 * time.Second
	// always mark the first key inserted in the BlobsCache with a value.
	firstKeyValue = "first"
)

type Cache struct {
	rootDir     string
	db          *bbolt.DB
	log         zlog.Logger
	useRelPaths bool // weather or not to use relative paths, should be true for filesystem and false for s3
}

func NewCache(rootDir string, name string, useRelPaths bool, log zlog.Logger) *Cache {
	dbPath := path.Join(rootDir, name+DBExtensionName)
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

	return &Cache{rootDir: rootDir, db: cacheDB, useRelPaths: useRelPaths, log: log}
}

func (c *Cache) PutBlob(digest, path string) error {
	if path == "" {
		c.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest).Msg("empty path provided")

		return errors.ErrEmptyValue
	}

	// use only relative (to rootDir) paths on blobs
	var err error
	if c.useRelPaths {
		path, err = filepath.Rel(c.rootDir, path)
		if err != nil {
			c.log.Error().Err(err).Str("path", path).Msg("unable to get relative path")
		}
	}

	if err := c.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		var value string

		bucket := root.Bucket([]byte(digest))
		if bucket == nil {
			/* mark first key in bucket
			in the context of s3 we need to know which blob is real
			and we know that the first one is always the real, so mark them.
			*/
			value = firstKeyValue
			bucket, err = root.CreateBucket([]byte(digest))
			if err != nil {
				// this is a serious failure
				c.log.Error().Err(err).Str("bucket", digest).Msg("unable to create a bucket")

				return err
			}
		}

		if err := bucket.Put([]byte(path), []byte(value)); err != nil {
			c.log.Error().Err(err).Str("bucket", digest).Str("value", path).Msg("unable to put record")

			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (c *Cache) GetBlob(digest string) (string, error) {
	var blobPath strings.Builder

	if err := c.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		b := root.Bucket([]byte(digest))
		if b != nil {
			if err := b.ForEach(func(k, v []byte) error {
				// always return the key with 'first' value
				if string(v) == firstKeyValue {
					blobPath.WriteString(string(k))

					return nil
				}

				return nil
			}); err != nil {
				c.log.Error().Err(err).Msg("unable to access digest bucket")

				return err
			}

			return nil
		}

		return errors.ErrCacheMiss
	}); err != nil {
		return "", err
	}

	return blobPath.String(), nil
}

func (c *Cache) HasBlob(digest, blob string) bool {
	if err := c.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

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

func (c *Cache) DeleteBlob(digest, path string) error {
	// use only relative (to rootDir) paths on blobs
	var err error
	if c.useRelPaths {
		path, err = filepath.Rel(c.rootDir, path)
		if err != nil {
			c.log.Error().Err(err).Str("path", path).Msg("unable to get relative path")
		}
	}

	if err := c.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		value := bucket.Get([]byte(path))

		if err := bucket.Delete([]byte(path)); err != nil {
			c.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

			return err
		}

		cur := bucket.Cursor()

		key, _ := cur.First()
		if key == nil {
			c.log.Debug().Str("digest", digest).Str("path", path).Msg("deleting empty bucket")
			if err := root.DeleteBucket([]byte(digest)); err != nil {
				c.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")

				return err
			}
			// if deleted key has value 'first' then move this value to the next key
		} else if string(value) == firstKeyValue {
			if err := bucket.Put(key, value); err != nil {
				c.log.Error().Err(err).Str("bucket", digest).Str("value", path).Msg("unable to put record")

				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
