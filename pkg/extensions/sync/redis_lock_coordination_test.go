//go:build sync

package sync

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// newReplica builds a BaseOnDemand backed by the shared miniredis lock,
// modelling one zot replica in a multi-replica deployment.
func newReplica(t *testing.T, client redis.UniversalClient) *BaseOnDemand {
	t.Helper()

	onDemand := NewOnDemand(log.NewLogger("debug", ""))
	onDemand.SetDistributedLock(NewRedisDistributedLock(client), "zot")

	return onDemand
}

func TestDistributedLockDedupAcrossReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	replicaA := newReplica(t, client)
	replicaB := newReplica(t, client)
	ctx := context.Background()

	const repo, ref = "library/busybox", "latest"

	if replicaA.IsSyncInFlight(repo, ref) {
		t.Fatal("expected no sync in flight before any lock is acquired")
	}

	_, release, err := replicaA.acquireDistributedLock(ctx, "image", repo, ref)
	if err != nil {
		t.Fatalf("replicaA acquire: %v", err)
	}

	// A second replica must observe the in-flight sync and be refused the lock.
	if !replicaB.IsSyncInFlight(repo, ref) {
		t.Fatal("expected replicaB to observe sync in flight")
	}

	if _, _, err := replicaB.acquireDistributedLock(ctx, "image", repo, ref); !errors.Is(err, zerr.ErrSyncInFlight) {
		t.Fatalf("expected ErrSyncInFlight for replicaB, got %v", err)
	}

	release()

	// After the leader releases, another replica can claim the lock.
	if replicaB.IsSyncInFlight(repo, ref) {
		t.Fatal("expected no sync in flight after release")
	}

	_, releaseB, err := replicaB.acquireDistributedLock(ctx, "image", repo, ref)
	if err != nil {
		t.Fatalf("replicaB acquire after release: %v", err)
	}

	releaseB()
}

func TestAcquireDistributedLockNoBackendIsNoop(t *testing.T) {
	onDemand := NewOnDemand(log.NewLogger("debug", ""))

	handle, release, err := onDemand.acquireDistributedLock(context.Background(), "image", "repo", "ref")
	if err != nil {
		t.Fatalf("acquire without backend: %v", err)
	}

	if handle != nil {
		t.Fatal("expected nil handle without a distributed lock backend")
	}

	// release must be a callable no-op.
	release()

	if onDemand.IsSyncInFlight("repo", "ref") {
		t.Fatal("expected no sync in flight without a distributed lock backend")
	}
}
