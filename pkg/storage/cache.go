package storage

import (
	"path"
	"strings"

	"github.com/anuvu/zot/errors"
	zlog "github.com/anuvu/zot/pkg/log"
	"go.etcd.io/bbolt"
)

const (
	BlobsCache = "blobs"
)

type Cache struct {
	db  *bbolt.DB
	log zlog.Logger
}

// Blob is a blob record.
type Blob struct {
	Path string
}

func NewCache(rootDir string, name string, log zlog.Logger) *Cache {
	dbPath := path.Join(rootDir, name+".db")
	db, err := bbolt.Open(dbPath, 0600, nil)

	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create cache db")
		return nil
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
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

	return &Cache{db: db, log: log}
}

func (c *Cache) PutBlob(digest string, path string) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(BlobsCache))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			c.log.Error().Err(err).Msg("unable to access root bucket")
			return err
		}
		b, err := root.CreateBucketIfNotExists([]byte(digest))
		if err != nil {
			// this is a serious failure
			c.log.Error().Err(err).Str("bucket", digest).Msg("unable to create a bucket")
			return err
		}
		if err := b.Put([]byte(path), nil); err != nil {
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

	if len(blobPath.String()) == 0 {
		return "", nil
	}

	return blobPath.String(), nil
}

func (c *Cache) HasBlob(digest string, blob string) bool {
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

func (c *Cache) DeleteBlob(digest string, path string) error {
	if err := c.db.Update(func(tx *bbolt.Tx) error {
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

		if err := b.Delete([]byte(path)); err != nil {
			c.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")
			return err
		}

		cur := b.Cursor()
		k, _ := cur.First()

		if k == nil {
			c.log.Debug().Str("digest", digest).Str("path", path).Msg("deleting empty bucket")
			if err := root.DeleteBucket([]byte(digest)); err != nil {
				c.log.Error().Err(err).Str("digest", digest).Str("path", path).Msg("unable to delete")
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
