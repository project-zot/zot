//go:build sync

package sync

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisDistributedLock struct {
	client redis.UniversalClient
}

func NewRedisDistributedLock(client redis.UniversalClient) *RedisDistributedLock {
	return &RedisDistributedLock{client: client}
}

func (lock *RedisDistributedLock) TryLock(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	return lock.client.SetNX(ctx, key, value, ttl).Result()
}

func (lock *RedisDistributedLock) Unlock(ctx context.Context, key, value string) error {
	const unlockScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`

	return lock.client.Eval(ctx, unlockScript, []string{key}, value).Err()
}

// Refresh extends the TTL of an existing lock if the caller still owns it.
// Returns (true, nil) on successful refresh, (false, nil) if the key is
// missing or owned by another holder, (false, err) on Redis failures.
func (lock *RedisDistributedLock) Refresh(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	const refreshScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0
`

	res, err := lock.client.Eval(ctx, refreshScript, []string{key}, value, ttl.Milliseconds()).Result()
	if err != nil {
		return false, err
	}

	n, ok := res.(int64)
	if !ok {
		return false, nil
	}

	return n == 1, nil
}

func (lock *RedisDistributedLock) IsLocked(ctx context.Context, key string) (bool, error) {
	n, err := lock.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return n > 0, nil
}
