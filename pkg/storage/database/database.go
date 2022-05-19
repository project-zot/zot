package database

import (
	"path"
	"strings"

	"go.etcd.io/bbolt"
	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

type Database interface {
	Put(key, value string) error
	Get(key string) (string, error)
	Has(key string) bool
	Delete(key string) error
	DeleteAll() error
}

// key:value store
type DB struct {
	bucket  string
	rootDir string
	db      *bbolt.DB
	log     zlog.Logger
}

func New(rootDir string, name string, bucket string, log zlog.Logger) (*DB, error) {
	dbPath := path.Join(rootDir, name+storage.DBExtensionName)
	dbOpts := &bbolt.Options{
		Timeout:      storage.DBCacheLockCheckTimeout,
		FreelistType: bbolt.FreelistArrayType,
	}

	database, err := bbolt.Open(dbPath, 0o600, dbOpts) //nolint:gomnd
	if err != nil {
		log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create cache db")

		return nil, err
	}

	if err := database.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
			// this is a serious failure
			log.Error().Err(err).Str("dbPath", dbPath).Msg("unable to create a root bucket")

			return err
		}

		return nil
	}); err != nil {
		// something went wrong
		log.Error().Err(err).Msg("unable to create a database")

		return nil, err
	}

	return &DB{rootDir: rootDir, bucket: bucket, log: log, db: database}, nil
}

func (db *DB) Put(key, value string) error {
	if value == "" || key == "" {
		db.log.Error().Err(errors.ErrEmptyValue).Str("key", key).Str("value", value).Msg("empty key/value provided")

		return errors.ErrEmptyValue
	}

	if err := test.Error(db.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(db.bucket))
		if bucket == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to access root bucket")

			return err
		}

		return bucket.Put([]byte(key), []byte(value))
	})); err != nil {
		db.log.Error().Err(err).Str("bucket", db.bucket).Str("key", key).Str("value", value).Msg("unable to put record")

		return err
	}

	return nil
}

func (db *DB) Get(key string) (string, error) {
	var value strings.Builder

	if err := test.Error(db.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(db.bucket))
		if bucket == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to access root bucket")

			return err
		}

		v := bucket.Get([]byte(key))
		value.Write(v)

		return nil
	})); err != nil {
		return "", err
	}

	return value.String(), nil
}

func (db *DB) Has(key string) bool {
	if err := db.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(db.bucket))
		if bucket == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			db.log.Error().Err(err).Msg("unable to access root bucket")

			return err
		}

		if bucket.Get([]byte(key)) == nil {
			return errors.ErrCacheMiss
		}

		return nil
	}); err != nil {
		return false
	}

	return true
}

func (db *DB) Delete(key string) error {
	if err := test.Error(db.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(db.bucket))
		if bucket == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to access root bucket")

			return err
		}

		return bucket.Delete([]byte(key))
	})); err != nil {
		db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to delete a keys")

		return err
	}

	return nil
}

func (db *DB) DeleteAll() error {
	if err := test.Error(db.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(db.bucket))
		if bucket == nil {
			// this is a serious failure
			err := errors.ErrCacheRootBucket
			db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to access root bucket")

			return err
		}

		err := bucket.ForEach(func(k, v []byte) error {
			return bucket.Delete(k)
		})

		return err
	})); err != nil {
		db.log.Error().Err(err).Str("bucket", db.bucket).Msg("unable to delete all keys")

		return err
	}

	return nil
}

func (db *DB) Close() error {
	return db.db.Close()
}
