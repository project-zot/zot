//go:build sync

package sync

import (
	"context"
	"time"
)

// syncLeaseStore hands out one lease per key to replicas that share storage, so that only the
// holder syncs an image from upstream while the others wait for it. A lease that is not renewed
// before ttl elapses can be acquired by another replica.
type syncLeaseStore interface {
	// Acquire takes the lease for key when it is free, expired or already owned by owner.
	Acquire(ctx context.Context, key, owner string, ttl time.Duration) (bool, error)
	// Renew extends the lease for key while owner still holds it.
	Renew(ctx context.Context, key, owner string, ttl time.Duration) (bool, error)
	// Release drops the lease for key if owner still holds it.
	Release(ctx context.Context, key, owner string) error
}
