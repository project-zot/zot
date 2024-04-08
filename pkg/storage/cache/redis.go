package cache

import (
	"context"
	goerrors "errors"
	"path/filepath"
	"strings"

	godigest "github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"

	zerr "zotregistry.dev/zot/errors"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage/constants"
)

type RedisDriver struct {
	rootDir     string
	db          redis.UniversalClient
	log         zlog.Logger
	useRelPaths bool // whether or not to use relative paths, should be true for filesystem and false for s3
}

type RedisDriverParameters struct {
	RootDir     string
	URL         string // https://github.com/redis/redis-specifications/blob/master/uri/redis.txt
	UseRelPaths bool
}

func NewRedisCache(parameters interface{}, log zlog.Logger) (*RedisDriver, error) {
	properParameters, ok := parameters.(RedisDriverParameters)
	if !ok {
		log.Error().Err(zerr.ErrTypeAssertionFailed).Msgf("failed to cast type, expected type '%T' but got '%T'",
			BoltDBDriverParameters{}, parameters)

		return nil, zerr.ErrTypeAssertionFailed
	}

	connOpts, err := redis.ParseURL(properParameters.URL)
	if err != nil {
		log.Error().Err(err).Str("directory", properParameters.URL).Msg("failed to connect to redis")
	}
	cacheDB := redis.NewClient(connOpts)

	if _, err := cacheDB.Ping(context.Background()).Result(); err != nil {
		log.Error().Err(err).Msg("failed to ping redis cache")

		return nil, err
	}

	driver := &RedisDriver{
		db:          cacheDB,
		log:         log,
		rootDir:     properParameters.RootDir,
		useRelPaths: properParameters.UseRelPaths,
	}

	return driver, nil
}

func join(xs ...string) string {
	return "zot:" + strings.Join(xs, ":")
}

func (d *RedisDriver) UsesRelativePaths() bool {
	return d.useRelPaths
}

func (d *RedisDriver) Name() string {
	return "redis"
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

	// see if the blob digest exists.
	exists, err := d.db.HExists(ctx, join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		return err
	}

	if _, err := d.db.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		if !exists {
			// add the key value pair [digest, path] to blobs:origin if not
			// exist already. the path becomes the canonical blob we do this in
			// a transaction to make sure that if something is in the set, then
			// it is guaranteed to always have a path note that there is a
			// race, but the worst case is that a different origin path that is
			// still valid is used.
			if err := txrp.HSet(ctx, join(constants.BlobsCache, constants.OriginalBucket),
				digest.String(), path).Err(); err != nil {
				d.log.Error().Err(err).Str("hset", join(constants.BlobsCache, constants.OriginalBucket)).
					Str("value", path).Msg("unable to put record")

				return err
			}
		}
		// add path to the set of paths which the digest represents
		if err := d.db.SAdd(ctx, join(constants.BlobsCache, constants.DuplicatesBucket,
			digest.String()), path).Err(); err != nil {
			d.log.Error().Err(err).Str("sadd", join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
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

	path, err := d.db.HGet(ctx, join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			return "", zerr.ErrCacheMiss
		}

		d.log.Error().Err(err).Str("hget", join(constants.BlobsCache, constants.OriginalBucket)).
			Str("digest", digest.String()).Msg("unable to get record")

		return "", err
	}

	return path, nil
}

func (d *RedisDriver) HasBlob(digest godigest.Digest, blob string) bool {
	ctx := context.TODO()
	// see if we are in the set
	exists, err := d.db.SIsMember(ctx, join(constants.BlobsCache, constants.DuplicatesBucket,
		digest.String()), blob).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg("unable to get record")

		return false
	}

	if !exists {
		return false
	}

	// see if the path entry exists. is this actually needed? i guess it doesn't really hurt (it is fast)
	exists, err = d.db.HExists(ctx, join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()

	d.log.Error().Err(err).Str("hexists", join(constants.BlobsCache, constants.OriginalBucket)).
		Str("digest", digest.String()).Msg("unable to get record")

	if err != nil {
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

	pathSet := join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())

	// delete path from the set of paths which the digest represents
	_, err = d.db.SRem(ctx, pathSet, path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to delete record")

		return err
	}

	currentPath, err := d.GetBlob(digest)
	if err != nil {
		return err
	}

	if currentPath != path {
		// nothing we need to do, return nil yay
		return nil
	}

	// we need to set a new path
	newPath, err := d.db.SRandMember(ctx, pathSet).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			_, err := d.db.HDel(ctx, join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
			if err != nil {
				return err
			}

			return nil
		}

		d.log.Error().Err(err).Str("srandmember", pathSet).Msg("failed to get new path")

		return err
	}

	if _, err := d.db.HSet(ctx, join(constants.BlobsCache, constants.OriginalBucket),
		digest.String(), newPath).Result(); err != nil {
		d.log.Error().Err(err).Str("hset", join(constants.BlobsCache, constants.OriginalBucket)).Str("value", newPath).
			Msg("unable to put record")

		return err
	}

	return nil
}
