//go:build sync

package sync_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	syncext "zotregistry.dev/zot/v2/pkg/extensions/sync"
)

func newMiniredisClient(t *testing.T) (*miniredis.Miniredis, redis.UniversalClient) {
	t.Helper()

	miniRedis := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: miniRedis.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return miniRedis, client
}

func TestRefreshExtendsTTLWhenOwnerMatches(t *testing.T) {
	miniRedis, client := newMiniredisClient(t)
	lock := syncext.NewRedisDistributedLock(client)
	ctx := context.Background()

	ok, err := lock.TryLock(ctx, "k", "owner-A", 5*time.Second)
	if err != nil || !ok {
		t.Fatalf("TryLock: ok=%v err=%v", ok, err)
	}
	miniRedis.FastForward(3 * time.Second)

	refreshed, err := lock.Refresh(ctx, "k", "owner-A", 10*time.Second)
	if err != nil || !refreshed {
		t.Fatalf("Refresh: refreshed=%v err=%v", refreshed, err)
	}
	if miniRedis.TTL("k") < 9*time.Second {
		t.Fatalf("TTL not extended: got %v", miniRedis.TTL("k"))
	}
}

func TestRefreshFailsWhenOwnerMismatched(t *testing.T) {
	_, client := newMiniredisClient(t)
	lock := syncext.NewRedisDistributedLock(client)
	ctx := context.Background()

	_, _ = lock.TryLock(ctx, "k", "owner-A", 5*time.Second)

	refreshed, err := lock.Refresh(ctx, "k", "owner-B", 10*time.Second)
	if err != nil {
		t.Fatalf("Refresh err: %v", err)
	}
	if refreshed {
		t.Fatalf("Refresh must return false when owner mismatched")
	}
}

func TestRefreshFailsWhenKeyMissing(t *testing.T) {
	_, client := newMiniredisClient(t)
	lock := syncext.NewRedisDistributedLock(client)
	ctx := context.Background()

	refreshed, err := lock.Refresh(ctx, "missing", "owner-A", 10*time.Second)
	if err != nil {
		t.Fatalf("Refresh err: %v", err)
	}
	if refreshed {
		t.Fatalf("Refresh must return false when key missing")
	}
}
