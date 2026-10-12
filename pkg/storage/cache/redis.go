package cache

import (
	"context"
	goerrors "errors"
	"path"
	"path/filepath"
	"strings"
	"time"

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

// lockKeySuffix distinguishes the lock namespace per caller (see PutBlob/PutBlobRef) so a
// blob's cache entry and its blob-ref entry serialize independently, matching rootBucket.
func (d *RedisDriver) putBlobLike(digest godigest.Digest, path, rootBucket, lockKeySuffix, putLogMsg string) error {
	lockKeyParts := []string{constants.RedisLocksBucket}
	if lockKeySuffix != "" {
		lockKeyParts = append(lockKeyParts, lockKeySuffix)
	}

	lockKeyParts = append(lockKeyParts, digest.String())

	lock := d.rs.NewMutex(d.join(lockKeyParts...))
	if err := lock.Lock(); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire redis lock")

		return err
	}

	defer func() {
		if _, err := lock.Unlock(); err != nil {
			d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to release redis lock")
		}
	}()

	ctx := context.TODO()

	exists, err := d.db.HExists(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String()).Result()
	if err != nil {
		return err
	}

	originMissing := !exists
	if exists {
		// read outside TxPipelined so the idempotency check doesn't mix with queued writes
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

	return d.putBlobLike(digest, path, constants.BlobsCache, "", "unable to put record")
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

	return d.putBlobLike(digest, path, constants.BlobRefs, constants.BlobRefs, "unable to put blob ref")
}

func (d *RedisDriver) SetOrigin(digest godigest.Digest, originPath string) error {
	ctx := context.TODO()

	if originPath == "" {
		d.log.Error().Err(zerr.ErrEmptyValue).Str("digest", digest.String()).Msg("failed to provide non-empty path")

		return zerr.ErrEmptyValue
	}

	comparePath := originPath
	if d.useRelPaths {
		rel, err := filepath.Rel(d.rootDir, originPath)
		if err != nil {
			d.log.Error().Err(err).Str("path", originPath).Msg("failed to get relative path")

			return err
		}

		comparePath = rel
	}

	if comparePath == "" {
		return zerr.ErrEmptyValue
	}

	// Hold the same per-digest lock as PutBlob/DeleteBlob for the whole replace so
	// concurrent writers cannot observe a half-updated origin/duplicate pair.
	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, digest.String()))
	if err := lock.Lock(); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire redis lock")

		return err
	}

	defer func() {
		if _, err := lock.Unlock(); err != nil {
			d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to release redis lock")
		}
	}()

	originKey := d.join(constants.BlobsCache, constants.OriginalBucket)
	pathSet := d.join(constants.BlobsCache, constants.DuplicatesBucket, digest.String())

	current, err := d.db.HGet(ctx, originKey, digest.String()).Result()
	if err != nil && !goerrors.Is(err, redis.Nil) {
		d.log.Error().Err(err).Str("hget", originKey).Str("digest", digest.String()).Msg("failed to get record")

		return err
	}

	if err == nil && path.Clean(current) == path.Clean(comparePath) {
		return nil
	}

	demoteStale := err == nil && current != ""

	if _, err := d.db.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		// Overwrite origin (PutBlob never does this).
		if err := txrp.HSet(ctx, originKey, digest.String(), comparePath).Err(); err != nil {
			d.log.Error().Err(err).Str("hset", originKey).Str("value", comparePath).Msg("failed to put record")

			return err
		}

		// The origin and the duplicate set are disjoint (see putBlobLike): the new origin
		// must not stay behind as a duplicate, because DeleteBlob checks the set first and
		// would otherwise leave the origin pointing at a deleted path.
		if err := txrp.SRem(ctx, pathSet, comparePath).Err(); err != nil {
			d.log.Error().Err(err).Str("srem", pathSet).Str("value", comparePath).Msg("failed to delete record")

			return err
		}

		if !demoteStale {
			return nil
		}

		// ... and the replaced origin is demoted into the set or it drops out of the cache.
		if err := txrp.SAdd(ctx, pathSet, current).Err(); err != nil {
			d.log.Error().Err(err).Str("sadd", pathSet).Str("value", current).Msg("failed to put record")

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
	return d.getAllBlobLike(digest, constants.BlobsCache, "unable to get record")
}

func (d *RedisDriver) GetBlobRefs(digest godigest.Digest) ([]string, error) {
	return d.getAllBlobLike(digest, constants.BlobRefs, "unable to get blob ref")
}

func (d *RedisDriver) GetAllBlobRefs() (map[godigest.Digest][]string, error) {
	origins, err := d.db.HGetAll(context.TODO(), d.join(constants.BlobRefs, constants.OriginalBucket)).Result()
	if err != nil {
		return nil, err
	}

	allRefs := make(map[godigest.Digest][]string, len(origins))
	for digestString := range origins {
		digest := godigest.Digest(digestString)
		if err := digest.Validate(); err != nil {
			continue
		}

		refs, err := d.GetBlobRefs(digest)
		if err != nil {
			return nil, err
		}

		allRefs[digest] = refs
	}

	return allRefs, nil
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

	currentPath, err := d.GetBlob(digest)
	if err != nil {
		// Idempotent with DynamoDB: a concurrent DeleteBlob may have already
		// removed the digest after our SRem, or the digest was never present.
		if goerrors.Is(err, zerr.ErrCacheMiss) {
			return nil
		}

		return err
	}

	if currentPath != path {
		// path not found in duplicates or original - nothing to delete
		return nil
	}

	// at this point path is the original
	dupes, err := d.db.SCard(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("scard", pathSet).Msg("failed to count duplicates")

		return err
	}

	if dupes > 0 {
		// promote a duplicate to origin so GetAllBlobs/HasBlob stop reporting this deleted path
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

// promoteDuplicateToOrigin installs an arbitrary duplicate as the new origin. The origin write
// and the duplicate's removal go in one transaction: popping first would lose the path for
// good if the origin write then failed, and with it the last record that the digest is in use.
// Callers must hold the per-digest redsync lock so the pick cannot go stale before the swap.
func (d *RedisDriver) promoteDuplicateToOrigin(ctx context.Context, digest godigest.Digest,
	rootBucket, pathSet string,
) error {
	newOrigin, err := d.db.SRandMember(ctx, pathSet).Result()
	if err != nil {
		d.log.Error().Err(err).Str("srandmember", pathSet).Msg("failed to select duplicate for promotion")

		return err
	}

	if _, err := d.db.TxPipelined(ctx, func(txrp redis.Pipeliner) error {
		txrp.HSet(ctx, d.join(rootBucket, constants.OriginalBucket), digest.String(), newOrigin)
		txrp.SRem(ctx, pathSet, newOrigin)

		return nil
	}); err != nil {
		d.log.Error().Err(err).Str("pathSet", pathSet).Str("value", newOrigin).
			Msg("failed to promote duplicate to origin")

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
		// promote a duplicate to origin so GetBlobRefs stops reporting this deleted path
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

// TryLockBlobReclaim takes the cross-instance lock a global blob reclaim sweep holds while it
// decides on and deletes digest's payload. It makes one attempt and reports false, not an
// error, if another instance holds the lock. The lock expires by itself after ttl, so a sweep
// that crashed while holding it only delays that digest's next sweep.
func (d *RedisDriver) TryLockBlobReclaim(digest godigest.Digest, ttl time.Duration) (func(), bool, error) {
	lock := d.rs.NewMutex(d.join(constants.RedisLocksBucket, "reclaim", digest.String()),
		redsync.WithExpiry(ttl), redsync.WithTries(1))

	if err := lock.TryLock(); err != nil {
		if goerrors.Is(err, redsync.ErrFailed) {
			return nil, false, nil
		}

		if _, taken := goerrors.AsType[*redsync.ErrTaken](err); taken {
			return nil, false, nil
		}

		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to acquire blob reclaim lock")

		return nil, false, err
	}

	return func() {
		if _, err := lock.Unlock(); err != nil {
			// Not fatal: the lock expires on its own.
			d.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to release blob reclaim lock")
		}
	}, true, nil
}
