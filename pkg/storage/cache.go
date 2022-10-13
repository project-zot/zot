package storage

import (
	"path"
	"path/filepath"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
)

const (
	// global bucket.
	BlobsCache = "blobs"
	// bucket where we store all blobs from storage(deduped blobs + original blob).
	DuplicatesBucket = "duplicates"
	/* bucket where we store only the original/source blob (used by s3 to know which is the blob with content)
	it should contain only one blob, this is the only place from which we'll get blobs. */
	OriginalBucket          = "original"
	DBExtensionName         = ".db"
	dbCacheLockCheckTimeout = 10 * time.Second
)

type Cache struct {
	rootDir     string
	db          *bbolt.DB
	log         zlog.Logger
	useRelPaths bool // weather or not to use relative paths, should be true for filesystem and false for s3
}

// Blob is a blob record.
type Blob struct {
	Path string
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

func (c *Cache) PutBlob(digest godigest.Digest, path string) error {
	if path == "" {
		c.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path provided")

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

		bucket, err := root.CreateBucketIfNotExists([]byte(digest.String()))
		if err != nil {
			// this is a serious failure
			c.log.Error().Err(err).Str("bucket", digest.String()).Msg("unable to create a bucket")

			return err
		}

		// create nested deduped bucket where we store all the deduped blobs + original blob
		deduped, err := bucket.CreateBucketIfNotExists([]byte(DuplicatesBucket))
		if err != nil {
			// this is a serious failure
			c.log.Error().Err(err).Str("bucket", DuplicatesBucket).Msg("unable to create a bucket")

			return err
		}

		if err := deduped.Put([]byte(path), nil); err != nil {
			c.log.Error().Err(err).Str("bucket", DuplicatesBucket).Str("value", path).Msg("unable to put record")

			return err
		}

		// create origin bucket and insert only the original blob
		origin := bucket.Bucket([]byte(OriginalBucket))
		if origin == nil {
			// if the bucket doesn't exist yet then 'path' is the original blob
			origin, err := bucket.CreateBucket([]byte(OriginalBucket))
			if err != nil {
				// this is a serious failure
				c.log.Error().Err(err).Str("bucket", OriginalBucket).Msg("unable to create a bucket")

				return err
			}

			if err := origin.Put([]byte(path), nil); err != nil {
				c.log.Error().Err(err).Str("bucket", OriginalBucket).Str("value", path).Msg("unable to put record")

				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (c *Cache) GetBlob(digest godigest.Digest) (string, error) {
	var blobPath strings.Builder

	if err := c.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest.String()))
		if bucket != nil {
			origin := bucket.Bucket([]byte(OriginalBucket))
			blobPath.WriteString(string(c.getOne(origin)))

			return nil
		}

		return errors.ErrCacheMiss
	}); err != nil {
		return "", err
	}

	return blobPath.String(), nil
}

func (c *Cache) HasBlob(digest godigest.Digest, blob string) bool {
	if err := c.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest.String()))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		origin := bucket.Bucket([]byte(OriginalBucket))
		if origin == nil {
			return errors.ErrCacheMiss
		}

		if origin.Get([]byte(blob)) == nil {
			return errors.ErrCacheMiss
		}

		return nil
	}); err != nil {
		return false
	}

	return true
}

func (c *Cache) getOne(bucket *bbolt.Bucket) []byte {
	if bucket != nil {
		cursor := bucket.Cursor()
		k, _ := cursor.First()

		return k
	}

	return nil
}

func (c *Cache) DeleteBlob(digest godigest.Digest, path string) error {
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

		bucket := root.Bucket([]byte(digest.String()))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		deduped := bucket.Bucket([]byte(DuplicatesBucket))
		if deduped == nil {
			return errors.ErrCacheMiss
		}

		if err := deduped.Delete([]byte(path)); err != nil {
			c.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", DuplicatesBucket).
				Str("path", path).Msg("unable to delete")

			return err
		}

		origin := bucket.Bucket([]byte(OriginalBucket))
		if origin != nil {
			originBlob := c.getOne(origin)
			if originBlob != nil {
				if err := origin.Delete([]byte(path)); err != nil {
					c.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", OriginalBucket).
						Str("path", path).Msg("unable to delete")

					return err
				}

				// move next candidate to origin bucket, next GetKey will return this one and storage will move the content here
				dedupedBlob := c.getOne(deduped)
				if dedupedBlob != nil {
					if err := origin.Put(dedupedBlob, nil); err != nil {
						c.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", OriginalBucket).Str("path", path).
							Msg("unable to put")

						return err
					}
				}
			}
		}

		// if no key in origin bucket then digest bucket is empty, remove it
		k := c.getOne(origin)
		if k == nil {
			c.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")
			if err := root.DeleteBucket([]byte(digest.String())); err != nil {
				c.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", digest.String()).Str("path", path).
					Msg("unable to delete")

				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
