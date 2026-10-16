package cache

import (
	"context"
	goerrors "errors"
	"fmt"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// The Redis blob reference index keeps three keys per digest: "global", set once the payload
// is recorded, "refs", the set of owning paths, and "claim", a hash with the id and time of a
// sweep's claim. Their names share the digest as a hash tag, so they live in one Redis Cluster
// slot, and each operation that reads and writes them is one Lua script, which Redis runs
// atomically. Claim times come from the Redis server's TIME, so instance clocks never matter.

// Results of the claim script, as its Lua returns them.
const (
	redisClaimTaken      = 1
	redisClaimMiss       = -1
	redisClaimReferenced = -2
	redisClaimHeld       = -3
)

// redisNowMillis is a Lua prelude setting now to the Redis server's time, in milliseconds.
const redisNowMillis = `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local function claimLive(claimKey, lease)
	local at = redis.call('HGET', claimKey, 'at')
	return at and now - tonumber(at) < lease
end
`

// redisBlobRefScripts are the Lua scripts of the blob reference index. Each one runs on a
// digest's global, refs and claim keys, in that order.
type redisBlobRefScripts struct {
	// ARGV: path, lease in milliseconds. Returns 1, or 0 while a live claim is held.
	addReference *redis.Script
	// ARGV: claim id, lease in milliseconds. Returns {result, now}, result one of redisClaim*.
	claimReclaim *redis.Script
	// ARGV: claim id. Returns 1, or 0 when the claim is no longer held.
	finishReclaim *redis.Script
	// ARGV: claim id.
	abandonReclaim *redis.Script
}

// newRedisBlobRefScripts loads the Lua scripts that make each index operation atomic on the server.
func newRedisBlobRefScripts() redisBlobRefScripts {
	return redisBlobRefScripts{
		addReference: redis.NewScript(redisNowMillis + `
if claimLive(KEYS[3], tonumber(ARGV[2])) then
	return 0
end
redis.call('DEL', KEYS[3])
redis.call('SADD', KEYS[2], ARGV[1])
return 1
`),
		claimReclaim: redis.NewScript(redisNowMillis + `
if redis.call('SCARD', KEYS[2]) > 0 then
	return {-2, now}
end
if redis.call('EXISTS', KEYS[1]) == 0 then
	return {-1, now}
end
if claimLive(KEYS[3], tonumber(ARGV[2])) then
	return {-3, now}
end
redis.call('HSET', KEYS[3], 'id', ARGV[1], 'at', now)
return {1, now}
`),
		finishReclaim: redis.NewScript(`
if redis.call('HGET', KEYS[3], 'id') ~= ARGV[1] then
	return 0
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
return 1
`),
		abandonReclaim: redis.NewScript(`
if redis.call('HGET', KEYS[3], 'id') == ARGV[1] then
	redis.call('DEL', KEYS[3])
end
return 1
`),
	}
}

// SetReclaimClaimLease sets how long a reclaim claim stays live, constants.DefaultReclaimClaimLease
// unless set.
func (d *RedisDriver) SetReclaimClaimLease(lease time.Duration) {
	d.claimLease = lease
}

// blobRefKeys returns the global, refs and claim keys of digest.
func (d *RedisDriver) blobRefKeys(digest godigest.Digest) []string {
	record := d.join(constants.BlobRefsBucket, "{"+digest.String()+"}")

	return []string{record + ":global", record + ":refs", record + ":claim"}
}

func (d *RedisDriver) AddReference(digest godigest.Digest, path string) error {
	if path == "" {
		return zerr.ErrEmptyValue
	}

	added, err := d.blobRefScripts.addReference.Run(context.TODO(), d.db, d.blobRefKeys(digest),
		path, d.claimLease.Milliseconds()).Int()
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to add blob reference")

		return err
	}

	if added == 0 {
		return zerr.ErrDigestClaimed
	}

	return nil
}

func (d *RedisDriver) RemoveReference(digest godigest.Digest, path string) (bool, error) {
	keys := d.blobRefKeys(digest)

	// an emptied set is removed by Redis, so no script is needed: SREM and SCARD run in one
	// MULTI/EXEC, and nothing else is left to clean up
	var remaining *redis.IntCmd

	if _, err := d.db.TxPipelined(context.TODO(), func(pipe redis.Pipeliner) error {
		pipe.SRem(context.TODO(), keys[1], path)
		remaining = pipe.SCard(context.TODO(), keys[1])

		return nil
	}); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to remove blob reference")

		return false, err
	}

	return remaining.Val() == 0, nil
}

func (d *RedisDriver) GetReferences(digest godigest.Digest) ([]string, error) {
	keys := d.blobRefKeys(digest)

	paths, err := d.db.SMembers(context.TODO(), keys[1]).Result()
	if err != nil {
		return nil, err
	}

	if len(paths) > 0 {
		return paths, nil
	}

	exists, err := d.db.Exists(context.TODO(), keys[0], keys[2]).Result()
	if err != nil {
		return nil, err
	}

	if exists == 0 {
		return nil, zerr.ErrCacheMiss
	}

	return []string{}, nil
}

func (d *RedisDriver) RecordGlobal(digest godigest.Digest) error {
	if err := d.db.Set(context.TODO(), d.blobRefKeys(digest)[0], "1", 0).Err(); err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to record global blob")

		return err
	}

	return nil
}

func (d *RedisDriver) ClaimReclaim(digest godigest.Digest) (storageTypes.ReclaimClaim, error) {
	claimID := newClaimID()

	result, err := d.blobRefScripts.claimReclaim.Run(context.TODO(), d.db, d.blobRefKeys(digest),
		claimID, d.claimLease.Milliseconds()).Int64Slice()
	if err != nil {
		d.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to claim blob for reclaim")

		return storageTypes.ReclaimClaim{}, err
	}

	if len(result) != 2 { //nolint:mnd // status, time
		return storageTypes.ReclaimClaim{}, fmt.Errorf("%w: unexpected claim script result %v",
			zerr.ErrCacheMiss, result)
	}

	switch result[0] {
	case redisClaimTaken:
		return storageTypes.ReclaimClaim{Digest: digest, ID: claimID, At: time.UnixMilli(result[1])}, nil
	case redisClaimReferenced:
		return storageTypes.ReclaimClaim{}, zerr.ErrDigestReferenced
	case redisClaimHeld:
		return storageTypes.ReclaimClaim{}, zerr.ErrDigestClaimed
	default:
		return storageTypes.ReclaimClaim{}, zerr.ErrCacheMiss
	}
}

func (d *RedisDriver) FinishReclaim(claim storageTypes.ReclaimClaim) error {
	finished, err := d.blobRefScripts.finishReclaim.Run(context.TODO(), d.db, d.blobRefKeys(claim.Digest), claim.ID).Int()
	if err != nil {
		d.log.Error().Err(err).Str("digest", claim.Digest.String()).Msg("failed to finish blob reclaim")

		return err
	}

	// a reference is only ever added after breaking the claim, so a held claim means none
	if finished == 0 {
		return zerr.ErrReclaimClaimLost
	}

	return nil
}

func (d *RedisDriver) AbandonReclaim(claim storageTypes.ReclaimClaim) error {
	err := d.blobRefScripts.abandonReclaim.Run(context.TODO(), d.db, d.blobRefKeys(claim.Digest), claim.ID).Err()
	if err != nil && !goerrors.Is(err, redis.Nil) {
		d.log.Error().Err(err).Str("digest", claim.Digest.String()).Msg("failed to abandon blob reclaim")

		return err
	}

	return nil
}
