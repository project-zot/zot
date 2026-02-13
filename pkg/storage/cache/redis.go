package cache

import (
	"context"
	goerrors "errors"
	"path/filepath"
	"strings"

	"github.com/go-redsync/redsync/v4"
	gors "github.com/go-redsync/redsync/v4/redis/goredis/v9"
	godigest "github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
)

type RedisDriver struct {
	rootDir     string
	db          redis.UniversalClient
	log         zlog.Logger
	keyPrefix   string           // prepended to all keys, logically separating cache drivers accessing the same DB
	useRelPaths bool             // whether or not to use relative paths, should be true for filesystem and false for s3
	rs          *redsync.Redsync // used for locks, at the moment we are locking only for calls writing to the DB
}

type RedisDriverParameters struct {
	Client      redis.UniversalClient
	RootDir     string
	UseRelPaths bool
	KeyPrefix   string
}

func NewRedisCache(parameters any, log zlog.Logger) (*RedisDriver, error) {
	properParameters, ok := parameters.(RedisDriverParameters)
	if !ok {
		log.Error().Err(zerr.ErrTypeAssertionFailed).Msgf("failed to cast type, expected type '%T' but got '%T'",
			RedisDriverParameters{}, parameters)

		return nil, zerr.ErrTypeAssertionFailed
	}

	keyPrefix := properParameters.KeyPrefix
	if len(keyPrefix) == 0 {
		keyPrefix = "zot"
	}

	cacheDB := properParameters.Client

	if _, err := cacheDB.Ping(context.Background()).Result(); err != nil {
		log.Error().Err(err).Msg("failed to ping redis cache")

		return nil, err
	}

	// Create an instance of redisync to be used to obtain locks
	pool := gors.NewPool(cacheDB)

	// note for integration with local storage we need relative paths
	// while for integration with s3 storage we need absolute paths
	driver := &RedisDriver{
		db:          cacheDB,
		log:         log,
		rootDir:     properParameters.RootDir,
		useRelPaths: properParameters.UseRelPaths,
		keyPrefix:   keyPrefix,
		rs:          redsync.New(pool),
	}

	return driver, nil
}

func (d *RedisDriver) join(xs ...string) string {
	return d.keyPrefix + ":" + strings.Join(xs, ":")
}

func (d *RedisDriver) UsesRelativePaths() bool {
	return d.useRelPaths
}

func (d *RedisDriver) Name() string {
	return "redis"
}

// SetClient is supposed to be used only for testing purposes.
func (d *RedisDriver) SetClient(client redis.UniversalClient) {
	d.db = client
}

func (d *RedisDriver) PutBlob(digest godigest.Digest, path string) error {
	ctx := context.TODO()

	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("failed to provide non-empty path")

		return zerr.ErrEmptyValue
	}

	// use only relative (to rootDir) paths on blobs
	var err error
	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("failed to get relative path")
		}
	}

	if len(path) == 0 {
		return zerr.ErrEmptyValue
	}

	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, digest.String()))
	err = lock.Lock()
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire redis lock")

		return err
	}

	defer func() {
		if _, err := lock.Unlock(); err != nil {
			d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to release redis lock")
		}
	}()

	// see if the blob digest exists.
	exists, err := d.db.HExists(ctx, d.join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		return err
	}

	if _, err := d.db.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		if !exists {
			// add the key value pair [digest, path] to blobs:origin if not
			// exist already. the path becomes the canonical blob we do this in
			// a transaction to make sure that if something is in the set, then
			// it is guaranteed to always have a path
			// note that there is a race, but the worst case is that a different
			// origin path that is still valid is used.
			if err := txrp.HSet(ctx, d.join(constants.BlobsCache, constants.OriginalBucket),
				digest.String(), path).Err(); err != nil {
				d.log.Error().Err(err).Str("hset", d.join(constants.BlobsCache, constants.OriginalBucket)).
					Str("value", path).Msg("unable to put record")

				return err
			}

			d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("inserted in original bucket")

			return nil
		}
		ctx := context.TODO()
		// see if we are in the set
		exists, err := d.db.SIsMember(ctx, d.join(constants.BlobsCache, constants.OriginalBucket,
			digest.String()), path).Result()
		if err != nil {
			d.log.Error().Err(err).Str("sismember", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
				Str("digest", digest.String()).Msg("unable to get record")

			return err
		}

		if exists {
			d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("inserted same key in original bucket")

			return nil
		}

		// add path to the set of paths which the digest represents
		if err := txrp.SAdd(ctx, d.join(constants.BlobsCache, constants.DuplicatesBucket,
			digest.String()), path).Err(); err != nil {
			d.log.Error().Err(err).Str("sadd", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
				Str("value", path).Msg("unable to put record")

			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *RedisDriver) GetBlob(digest godigest.Digest) (string, error) {
	ctx := context.TODO()

	path, err := d.db.HGet(ctx, d.join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			return "", zerr.ErrCacheMiss
		}

		d.log.Error().Err(err).Str("hget", d.join(constants.BlobsCache, constants.OriginalBucket)).
			Str("digest", digest.String()).Msg("unable to get record")

		return "", err
	}

	return path, nil
}

func (d *RedisDriver) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	blobPaths := []string{}

	ctx := context.TODO()

	originalPath, err := d.db.HGet(ctx, d.join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			return nil, zerr.ErrCacheMiss
		}

		d.log.Error().Err(err).Str("hget", d.join(constants.BlobsCache, constants.OriginalBucket)).
			Str("digest", digest.String()).Msg("unable to get record")

		return nil, err
	}

	blobPaths = append(blobPaths, originalPath)

	// see if we are in the set
	duplicateBlobPaths, err := d.db.SMembers(ctx, d.join(constants.BlobsCache, constants.DuplicatesBucket,
		digest.String())).Result()
	if err != nil {
		d.log.Error().Err(err).Str("smembers", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg("unable to get record")

		return nil, err
	}

	for _, item := range duplicateBlobPaths {
		if item != originalPath {
			blobPaths = append(blobPaths, item)
		}
	}

	return blobPaths, nil
}

func (d *RedisDriver) HasBlob(digest godigest.Digest, path string) bool {
	var err error

	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("failed to get relative path")
		}
	}

	if len(path) == 0 {
		return false
	}

	ctx := context.TODO()

	// see if we are in the set
	exists, err := d.db.SIsMember(ctx, d.join(constants.BlobsCache, constants.OriginalBucket,
		digest.String()), path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg("unable to get record")

		return false
	}

	if !exists {
		return false
	}

	// see if we are in the set
	exists, err = d.db.SIsMember(ctx, d.join(constants.BlobsCache, constants.DuplicatesBucket,
		digest.String()), path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg("unable to get record")

		return false
	}

	if !exists {
		return false
	}

	return true
}

func (d *RedisDriver) DeleteBlob(digest godigest.Digest, path string) error {
	ctx := context.TODO()

	// use only relative (to rootDir) paths on blobs
	var err error
	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("failed to get relative path")
		}
	}

	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, digest.String()))
	err = lock.Lock()
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire redis lock")

		return err
	}

	defer func() {
		if _, err := lock.Unlock(); err != nil {
			d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to release redis lock")
		}
	}()

	// look first in the duplicates bucket
	pathSet := d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())

	exists, err := d.db.SIsMember(ctx, pathSet, path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to lookup record")

		return err
	}

	if exists {
		// delete path from the set of paths which the digest represents
		_, err = d.db.SRem(ctx, pathSet, path).Result()
		if err != nil {
			d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to delete record")

			return err
		}

		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("deleted from dedupe bucket")

		return nil
	}

	currentPath, err := d.GetBlob(digest)
	if err != nil {
		return err
	}

	if currentPath != path {
		// nothing we need to do, return nil yay
		return nil
	}

	dupes, err := d.db.SCard(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to lookup record")

		return err
	}

	if dupes > 0 {
		d.log.Debug().Str("digest", digest.String()).Str("path", path).Msg("more in dedupe bucket, leaving original alone")

		return nil
	}

	/*
		// we need to set a new path
		newPath, err := d.db.SRandMember(ctx, pathSet).Result()
		if err != nil {
			if goerrors.Is(err, redis.Nil) {
				_, err := d.db.HDel(ctx, d.join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
				if err != nil {
					return err
				}

				return nil
			}

			d.log.Error().Err(err).Str("srandmember", pathSet).Msg("failed to get new path")

			return err
		}
	*/

	if _, err := d.db.HDel(ctx, d.join(constants.BlobsCache, constants.OriginalBucket),
		digest.String()).Result(); err != nil {
		d.log.Error().Err(err).Str("hset", d.join(constants.BlobsCache, constants.OriginalBucket)).Str("value", path).
			Msg("failed to delete record")

		return err
	}

	return nil
}
