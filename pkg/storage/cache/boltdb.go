package cache

import (
	"os"
	"path"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/constants"
)

type BoltDBDriver struct {
	rootDir string
	db      *bbolt.DB
	log     zlog.Logger
}

type BoltDBDriverParameters struct {
	RootDir string
	Name    string
}

func NewBoltDBCache(parameters interface{}, log zlog.Logger) (Cache, error) {
	properParameters, ok := parameters.(BoltDBDriverParameters)
	if !ok {
		log.Error().Err(errors.ErrTypeAssertionFailed).Msg("failed type assertion for boltdb")

		return nil, errors.ErrTypeAssertionFailed
	}

	err := os.MkdirAll(properParameters.RootDir, constants.DefaultDirPerms)
	if err != nil {
		log.Error().Err(err).Msgf("unable to create directory for cache db: %v", properParameters.RootDir)

		return nil, err
	}

	dbPath := path.Join(properParameters.RootDir, properParameters.Name+constants.DBExtensionName)
	dbOpts := &bbolt.Options{
		Timeout:      constants.DBCacheLockCheckTimeout,
		FreelistType: bbolt.FreelistArrayType,
	}

	cacheDB, err := bbolt.Open(dbPath, 0o600, dbOpts) //nolint:gomnd
	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create cache db")

		return nil, err
	}

	return &BoltDBDriver{
		rootDir: properParameters.RootDir,
		db:      cacheDB,
		log:     log,
	}, nil
}

func (d *BoltDBDriver) Name() string {
	return "boltdb"
}

func (d *BoltDBDriver) CreateBucket(name string) error {
	if err := d.db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
			// this is a serious failure
			d.log.Error().Err(err).Str("rootDir", d.rootDir).Msg("unable to create root bucket")

			return err
		}

		return nil
	}); err != nil {
		// something went wrong
		d.log.Error().Err(err).Msg("unable to create a cache")

		return err
	}

	return nil
}

func (d *BoltDBDriver) PutBlob(bucket string, digest godigest.Digest, path string) error {
	if path == "" || bucket == "" {
		d.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path or bucket provided")

		return errors.ErrEmptyValue
	}

	if err := d.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(bucket))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket, err := root.CreateBucketIfNotExists([]byte(digest.String()))
		if err != nil {
			// this is a serious failure
			d.log.Error().Err(err).Str("bucket", digest.String()).Msg("unable to create a bucket")

			return err
		}

		// create nested deduped bucket where we store all the deduped blobs + original blob
		deduped, err := bucket.CreateBucketIfNotExists([]byte(constants.DuplicatesBucket))
		if err != nil {
			// this is a serious failure
			d.log.Error().Err(err).Str("bucket", constants.DuplicatesBucket).Msg("unable to create a bucket")

			return err
		}

		if err := deduped.Put([]byte(path), nil); err != nil {
			d.log.Error().Err(err).Str("bucket", constants.DuplicatesBucket).Str("value", path).Msg("unable to put record")

			return err
		}

		// create origin bucket and insert only the original blob
		origin := bucket.Bucket([]byte(constants.OriginalBucket))
		if origin == nil {
			// if the bucket doesn't exist yet then 'path' is the original blob
			origin, err := bucket.CreateBucket([]byte(constants.OriginalBucket))
			if err != nil {
				// this is a serious failure
				d.log.Error().Err(err).Str("bucket", constants.OriginalBucket).Msg("unable to create a bucket")

				return err
			}

			if err := origin.Put([]byte(path), nil); err != nil {
				d.log.Error().Err(err).Str("bucket", constants.OriginalBucket).Str("value", path).Msg("unable to put record")

				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *BoltDBDriver) GetBlob(bucket string, digest godigest.Digest) (string, error) {
	if bucket == "" {
		d.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest.String()).Msg("empty bucket provided")

		return "", errors.ErrEmptyValue
	}

	var blobPath strings.Builder

	if err := d.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(bucket))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest.String()))
		if bucket != nil {
			origin := bucket.Bucket([]byte(constants.OriginalBucket))
			blobPath.WriteString(string(d.getOne(origin)))

			return nil
		}

		return errors.ErrCacheMiss
	}); err != nil {
		return "", err
	}

	return blobPath.String(), nil
}

func (d *BoltDBDriver) HasBlob(bucket string, digest godigest.Digest, path string) bool {
	if bucket == "" || path == "" {
		d.log.Warn().Str("digest", digest.String()).Msg("empty path or bucket provided")

		return false
	}

	if err := d.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(bucket))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest.String()))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		origin := bucket.Bucket([]byte(constants.OriginalBucket))
		if origin == nil {
			return errors.ErrCacheMiss
		}

		deduped := bucket.Bucket([]byte(constants.DuplicatesBucket))
		if deduped == nil {
			return errors.ErrCacheMiss
		}

		if origin.Get([]byte(path)) == nil {
			if deduped.Get([]byte(path)) == nil {
				return errors.ErrCacheMiss
			}
		}

		return nil
	}); err != nil {
		return false
	}

	return true
}

func (d *BoltDBDriver) getOne(bucket *bbolt.Bucket) []byte {
	if bucket != nil {
		cursor := bucket.Cursor()
		k, _ := cursor.First()

		return k
	}

	return nil
}

func (d *BoltDBDriver) DeleteBlob(bucket string, digest godigest.Digest, path string) error {
	if bucket == "" || path == "" {
		d.log.Error().Err(errors.ErrEmptyValue).Str("digest", digest.String()).Msg("empty path or bucket provided")

		return errors.ErrEmptyValue
	}

	if err := d.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket([]byte(bucket))
		if root == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			d.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		bucket := root.Bucket([]byte(digest.String()))
		if bucket == nil {
			return errors.ErrCacheMiss
		}

		deduped := bucket.Bucket([]byte(constants.DuplicatesBucket))
		if deduped == nil {
			return errors.ErrCacheMiss
		}

		if err := deduped.Delete([]byte(path)); err != nil {
			d.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", constants.DuplicatesBucket).
				Str("path", path).Msg("unable to delete")

			return err
		}

		origin := bucket.Bucket([]byte(constants.OriginalBucket))
		if origin != nil {
			originBlob := d.getOne(origin)
			if originBlob != nil {
				if err := origin.Delete([]byte(path)); err != nil {
					d.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", constants.OriginalBucket).
						Str("path", path).Msg("unable to delete")

					return err
				}

				// move next candidate to origin bucket, next GetKey will return this one and storage will move the content here
				dedupedBlob := d.getOne(deduped)
				if dedupedBlob != nil {
					if err := origin.Put(dedupedBlob, nil); err != nil {
						d.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", constants.OriginalBucket).Str("path", path).
							Msg("unable to put")

						return err
					}
				}
			}
		}

		// if no key in origin bucket then digest bucket is empty, remove it
		k := d.getOne(origin)
		if k == nil {
			d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleting empty bucket")
			if err := root.DeleteBucket([]byte(digest)); err != nil {
				d.log.Error().Err(err).Str("digest", digest.String()).Str("bucket", digest.String()).Str("path", path).
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

func (d *BoltDBDriver) Close() error {
	return d.db.Close()
}
