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

func (d *RedisDriver) putBlobLike(digest godigest.Digest, path, rootBucket, putLogMsg string) error {
	ctx := context.TODO()

	exists, err := d.db.HExists(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		return err
	}

	originMissing := !exists
	if exists {
		// Read current origin outside TxPipelined: this avoids mixing decision reads
		// with queued writes and keeps idempotency checks deterministic.
		currentPath, err := d.db.HGet(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String()).Result()
		if err != nil {
			if !goerrors.Is(err, redis.Nil) {
				return err
			}

			// Hash key disappeared between HExists and HGet; treat as first-writer path.
			originMissing = true
		} else if currentPath == path {
			return nil
		}
	}

	if _, err := d.db.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		if originMissing {
			if err := txrp.HSet(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String(), path).Err(); err != nil {
				d.log.Error().Err(err).Str("hset", d.join(rootBucket, constants.OriginalBucket)).
					Str("value", path).Msg(putLogMsg)

				return err
			}

			return nil
		}

		if err := txrp.SAdd(ctx, d.join(rootBucket, constants.DuplicatesBucket, digest.String()), path).Err(); err != nil {
			d.log.Error().Err(err).Str("sadd", d.join(rootBucket, constants.DuplicatesBucket, digest.String())).
				Str("value", path).Msg(putLogMsg)

			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (d *RedisDriver) getAllBlobLike(digest godigest.Digest, rootBucket, getLogMsg string) ([]string, error) {
	ctx := context.TODO()

	originalPath, err := d.db.HGet(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			return nil, zerr.ErrCacheMiss
		}

		d.log.Error().Err(err).Str("hget", d.join(rootBucket, constants.OriginalBucket)).
			Str("digest", digest.String()).Msg(getLogMsg)

		return nil, err
	}

	blobPaths := []string{originalPath}

	duplicateBlobPaths, err := d.db.SMembers(ctx, d.join(rootBucket, constants.DuplicatesBucket, digest.String())).Result()
	if err != nil {
		d.log.Error().Err(err).Str("smembers", d.join(rootBucket, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg(getLogMsg)

		return nil, err
	}

	for _, item := range duplicateBlobPaths {
		if item != originalPath {
			blobPaths = append(blobPaths, item)
		}
	}

	return blobPaths, nil
}

func (d *RedisDriver) PutBlob(digest godigest.Digest, path string) error {
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

	return d.putBlobLike(digest, path, constants.BlobsCache, "unable to put record")
}

func (d *RedisDriver) PutBlobRef(digest godigest.Digest, path string) error {
	if path == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("failed to provide non-empty path")

		return zerr.ErrEmptyValue
	}

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

	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, constants.BlobRefs, digest.String()))
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

	return d.putBlobLike(digest, path, constants.BlobRefs, "unable to put blob ref")
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
	return d.getAllBlobLike(digest, constants.BlobsCache, "unable to get record")
}

func (d *RedisDriver) GetBlobRefs(digest godigest.Digest) ([]string, error) {
	return d.getAllBlobLike(digest, constants.BlobRefs, "unable to get blob ref")
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

	// check if path is the original
	currentPath, err := d.db.HGet(ctx, d.join(constants.BlobsCache, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if !goerrors.Is(err, redis.Nil) {
			d.log.Error().Err(err).Str("hget", d.join(constants.BlobsCache, constants.OriginalBucket)).
				Str("digest", digest.String()).Msg("unable to get record")

			return false
		}
	}

	if currentPath == path {
		return true
	}

	// check if path is in the duplicates set
	exists, err := d.db.SIsMember(ctx, d.join(constants.BlobsCache, constants.DuplicatesBucket,
		digest.String()), path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())).
			Str("digest", digest.String()).Msg("unable to get record")

		return false
	}

	return exists
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

	// check duplicates first
	pathSet := d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())

	exists, err := d.db.SIsMember(ctx, pathSet, path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", pathSet).Str("value", path).Msg("failed to lookup record")

		return err
	}

	if exists {
		// delete path from the set of paths which the digest represents
		_, err = d.db.SRem(ctx, pathSet, path).Result()
		if err != nil {
			d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to delete record")

			return err
		}

		return nil
	}

	// check if path is the original
	currentPath, err := d.GetBlob(digest)
	if err != nil {
		return err
	}

	if currentPath != path {
		// path not found in duplicates or original
		return zerr.ErrCacheMiss
	}

	// path is the original - check if there are still duplicates
	dupes, err := d.db.SCard(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("scard", pathSet).Msg("failed to count duplicates")

		return err
	}

	if dupes > 0 {
		// duplicates still exist: promote one of them to be the new origin, so
		// GetAllBlobs/HasBlob don't keep reporting this now-deleted path forever
		return d.promoteDuplicateToOrigin(ctx, digest, constants.BlobsCache, pathSet)
	}

	// no more duplicates, remove the original
	if _, err := d.db.HDel(ctx, d.join(constants.BlobsCache, constants.OriginalBucket),
		digest.String()).Result(); err != nil {
		d.log.Error().Err(err).Str("hdel", d.join(constants.BlobsCache, constants.OriginalBucket)).Str("value", path).
			Msg("failed to delete record")

		return err
	}

	return nil
}

// promoteDuplicateToOrigin pops an arbitrary path out of the duplicates set for digest
// and installs it as the new origin. Called while the caller still holds the per-digest
// redsync lock, so no other Put/Delete for this digest can race with the pop+set below.
func (d *RedisDriver) promoteDuplicateToOrigin(ctx context.Context, digest godigest.Digest,
	rootBucket, pathSet string,
) error {
	newOrigin, err := d.db.SPop(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("spop", pathSet).Msg("failed to promote duplicate to origin")

		return err
	}

	if err := d.db.HSet(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String(), newOrigin).Err(); err != nil {
		d.log.Error().Err(err).Str("hset", d.join(rootBucket, constants.OriginalBucket)).
			Str("value", newOrigin).Msg("failed to promote duplicate to origin")

		return err
	}

	return nil
}

func (d *RedisDriver) DeleteBlobRef(digest godigest.Digest, path string) error {
	ctx := context.TODO()

	var err error
	if d.useRelPaths {
		path, err = filepath.Rel(d.rootDir, path)
		if err != nil {
			d.log.Error().Err(err).Str("path", path).Msg("failed to get relative path")
		}
	}

	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, constants.BlobRefs, digest.String()))
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

	pathSet := d.join(constants.BlobRefs, constants.DuplicatesBucket, digest.String())
	exists, err := d.db.SIsMember(ctx, pathSet, path).Result()
	if err != nil {
		d.log.Error().Err(err).Str("sismember", pathSet).Str("value", path).Msg("failed to lookup record")

		return err
	}

	if exists {
		_, err = d.db.SRem(ctx, pathSet, path).Result()
		if err != nil {
			d.log.Error().Err(err).Str("srem", pathSet).Str("value", path).Msg("failed to delete record")

			return err
		}

		return nil
	}

	currentPath, err := d.db.HGet(ctx, d.join(constants.BlobRefs, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		if goerrors.Is(err, redis.Nil) {
			return zerr.ErrCacheMiss
		}

		return err
	}

	if currentPath != path {
		return zerr.ErrCacheMiss
	}

	dupes, err := d.db.SCard(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("scard", pathSet).Msg("failed to count duplicates")

		return err
	}

	if dupes > 0 {
		// duplicates still exist: promote one of them to be the new origin, so
		// GetBlobRefs doesn't keep reporting this now-deleted path forever
		return d.promoteDuplicateToOrigin(ctx, digest, constants.BlobRefs, pathSet)
	}

	if _, err := d.db.HDel(ctx, d.join(constants.BlobRefs, constants.OriginalBucket),
		digest.String()).Result(); err != nil {
		d.log.Error().Err(err).Str("hdel", d.join(constants.BlobRefs, constants.OriginalBucket)).Str("value", path).
			Msg("failed to delete record")

		return err
	}

	return nil
}
