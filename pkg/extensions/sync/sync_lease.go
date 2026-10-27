//go:build sync

package sync

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	// syncLeaseTTL is how long a lease lives without renewal; the holder renews every third of it.
	syncLeaseTTL = 30 * time.Second
	// syncLeaseMinPoll and syncLeaseMaxPoll bound a waiter's backoff between attempts.
	syncLeaseMinPoll = 250 * time.Millisecond
	syncLeaseMaxPoll = 5 * time.Second
)

var errSyncLeaseLost = errors.New("sync lease lost")

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

// syncLeaseCoordinator runs a sync for repo:reference on one replica at a time. It sits behind
// imageFlight: singleflight already dedupes within the process, so only the goroutine it lets
// through consults the lease.
type syncLeaseCoordinator struct {
	store       syncLeaseStore
	owner       string
	ttl         time.Duration
	minPoll     time.Duration
	maxPoll     time.Duration
	localDigest func(repo, reference string) godigest.Digest
	log         log.Logger
}

func newSyncLeaseCoordinator(store syncLeaseStore, localDigest func(repo, reference string) godigest.Digest,
	log log.Logger,
) (*syncLeaseCoordinator, error) {
	owner, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	return &syncLeaseCoordinator{
		store:       store,
		owner:       owner.String(),
		ttl:         syncLeaseTTL,
		minPoll:     syncLeaseMinPoll,
		maxPoll:     syncLeaseMaxPoll,
		localDigest: localDigest,
		log:         log,
	}, nil
}

// run executes sync under the lease for repo:reference. While another replica holds the lease it
// waits, with backoff, until the local manifest changes (the holder committed), or the lease is
// released or lapses, in which case it takes the lease and syncs itself. A store error means the
// sync runs without coordination, as it would with no store configured.
func (c *syncLeaseCoordinator) run(ctx context.Context, repo, reference string,
	sync func(ctx context.Context) error,
) error {
	key := trackerKey(repo, reference)
	before := c.localDigest(repo, reference)
	poll := c.minPoll
	waiting := false

	for {
		held, err := c.store.Acquire(ctx, key, c.owner, c.ttl)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			c.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
				Msg("sync lease store unavailable, syncing without coordination")

			return sync(ctx)
		}

		if held {
			return c.hold(ctx, key, sync)
		}

		if !waiting {
			waiting = true

			c.log.Info().Str("repo", repo).Str("reference", reference).
				Msg("another replica is syncing the image, waiting for it")
		}

		timer := time.NewTimer(poll/2 + rand.N(poll/2)) //nolint:gosec // jitter, not security
		select {
		case <-ctx.Done():
			timer.Stop()

			return ctx.Err()
		case <-timer.C:
		}

		if current := c.localDigest(repo, reference); current != "" && current != before {
			c.log.Info().Str("repo", repo).Str("reference", reference).Str("digest", current.String()).
				Msg("image was synced by another replica")

			return nil
		}

		poll = min(2*poll, c.maxPoll)
	}
}

// hold renews the lease while sync runs and releases it afterwards. Losing the lease cancels
// sync's context so that the replica taking over does not race it to the commit.
func (c *syncLeaseCoordinator) hold(ctx context.Context, key string, sync func(ctx context.Context) error) error {
	leaseCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	stop := make(chan struct{})
	done := make(chan struct{})

	go c.renew(leaseCtx, key, cancel, stop, done)

	err := sync(leaseCtx)

	close(stop)
	<-done

	if err := c.store.Release(context.WithoutCancel(ctx), key, c.owner); err != nil {
		c.log.Warn().Err(err).Str("key", key).Msg("failed to release sync lease")
	}

	if err != nil && errors.Is(context.Cause(leaseCtx), errSyncLeaseLost) {
		return errors.Join(errSyncLeaseLost, err)
	}

	return err
}

func (c *syncLeaseCoordinator) renew(ctx context.Context, key string, lost context.CancelCauseFunc,
	stop <-chan struct{}, done chan<- struct{},
) {
	defer close(done)

	interval := max(c.ttl/3, time.Millisecond)
	expiresAt := time.Now().Add(c.ttl)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}

		renewed, err := c.store.Renew(ctx, key, c.owner, c.ttl)
		if err == nil && renewed {
			expiresAt = time.Now().Add(c.ttl)

			continue
		}

		if err != nil {
			if ctx.Err() != nil {
				return
			}

			c.log.Warn().Err(err).Str("key", key).Msg("failed to renew sync lease")

			if time.Now().Before(expiresAt) {
				continue
			}
		}

		c.log.Warn().Str("key", key).Msg("sync lease lost, cancelling the sync")
		lost(errSyncLeaseLost)

		return
	}
}
