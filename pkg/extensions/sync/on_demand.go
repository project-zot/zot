//go:build sync

package sync

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

type request struct {
	repo      string
	reference string
	// used for background retries, at most one background retry per service
	serviceID    int
	isBackground bool
}

// syncLockTTL is the fixed expiry of the on-demand distributed lock.
// The leader replica refreshes the TTL every syncLockHeartbeatInterval
// so the lock survives long syncs. If the leader dies the lock expires
// within syncLockTTL after the last heartbeat, so the next replica can
// start a fresh sync.
const syncLockTTL = 90 * time.Second

// syncLockHeartbeatInterval is how often the leader replica refreshes
// the lock TTL while a sync is in progress. Must be < syncLockTTL/2 so
// a single missed heartbeat doesn't drop the lock.
const syncLockHeartbeatInterval = 30 * time.Second

// distributedLockBackend abstracts the cluster-wide lock store so it can
// be backed by Redis in multi-replica deployments or left unset for
// single-replica deployments (in-process dedup only).
type distributedLockBackend interface {
	TryLock(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Unlock(ctx context.Context, key, value string) error
	Refresh(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	IsLocked(ctx context.Context, key string) (bool, error)
}

type lockHandle struct {
	key   string
	owner string
}

// syncResult is the shared outcome of a single in-flight on-demand sync.
// Every caller that dedups onto the same request blocks on done and then
// reads err, so all waiters observe the same result reliably, including
// early failures (e.g. lock rejection) before the sync goroutine starts.
type syncResult struct {
	done chan struct{}
	err  error
}

/*
BaseOnDemand tracks requests that can be an image/signature/sbom.

It keeps track of all parallel requests, if two requests of same image/signature/sbom comes at the same time,
process just the first one, also keep track of all background retrying routines.
*/
type BaseOnDemand struct {
	services []Service
	// map[request]*syncResult for in-flight syncs; struct{}{} for background retries
	requestStore          *sync.Map
	distributedLock       distributedLockBackend
	distributedLockOwner  string
	distributedLockPrefix string
	log                   log.Logger
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{
		log:                   log,
		requestStore:          &sync.Map{},
		distributedLockOwner:  newLockOwnerID(),
		distributedLockPrefix: "zot",
	}
}

// SetDistributedLock enables cluster-wide on-demand sync deduplication
// using the provided backend. Without it, BaseOnDemand only dedups
// within a single process.
func (onDemand *BaseOnDemand) SetDistributedLock(lock distributedLockBackend, keyPrefix string) {
	onDemand.distributedLock = lock
	if keyPrefix != "" {
		onDemand.distributedLockPrefix = keyPrefix
	}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)
}

// IsSyncInFlight reports whether an on-demand image sync is currently
// running for this repo+reference, locally or on another replica. It is
// advisory: the authoritative dedup is the atomic TryLock in
// acquireDistributedLock, which returns ErrSyncInFlight to the loser.
func (onDemand *BaseOnDemand) IsSyncInFlight(repo, reference string) bool {
	req := request{repo: repo, reference: reference}
	if _, ok := onDemand.requestStore.Load(req); ok {
		return true
	}

	if onDemand.distributedLock == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	locked, err := onDemand.distributedLock.IsLocked(ctx, onDemand.lockKey("image", repo, reference))
	if err != nil {
		onDemand.log.Warn().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to check distributed on-demand sync lock")

		return false
	}

	return locked
}

func (onDemand *BaseOnDemand) lockKey(kind, repo, reference string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + repo + "\x00" + reference))

	return fmt.Sprintf("%s:sync:ondemand:locks:%s:%s",
		onDemand.distributedLockPrefix, kind, hex.EncodeToString(sum[:]))
}

func newLockOwnerID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}

	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

// acquireDistributedLock claims the cluster-wide lock for repo+reference.
// Returns:
//   - (handle, release, nil) on success; caller must defer release()
//   - (nil, nil, ErrSyncInFlight) if another replica holds the lock
//   - (nil, nil, err) on Redis failure
//
// When no distributed lock backend is configured, returns (nil, no-op, nil).
func (onDemand *BaseOnDemand) acquireDistributedLock(ctx context.Context,
	kind, repo, reference string,
) (*lockHandle, func(), error) {
	if onDemand.distributedLock == nil {
		return nil, func() {}, nil
	}

	key := onDemand.lockKey(kind, repo, reference)
	value := onDemand.distributedLockOwner

	locked, err := onDemand.distributedLock.TryLock(ctx, key, value, syncLockTTL)
	if err != nil {
		onDemand.log.Error().Err(err).
			Str("repo", repo).Str("reference", reference).Str("kind", kind).
			Msg("failed to acquire distributed on-demand sync lock")

		return nil, nil, err
	}

	if !locked {
		onDemand.log.Info().
			Str("repo", repo).Str("reference", reference).Str("kind", kind).
			Msg("distributed on-demand sync already in flight")

		return nil, nil, zerr.ErrSyncInFlight
	}

	handle := &lockHandle{key: key, owner: value}
	release := func() {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := onDemand.distributedLock.Unlock(rctx, key, value); err != nil {
			onDemand.log.Warn().Err(err).
				Str("repo", repo).Str("reference", reference).Str("kind", kind).
				Msg("failed to release distributed on-demand sync lock")
		}
	}

	return handle, release, nil
}

// runLockHeartbeat refreshes the distributed lock TTL on a fixed interval
// until ctx is cancelled. Caller must cancel ctx (typically via defer)
// before releasing the lock so the heartbeat stops first.
func (onDemand *BaseOnDemand) runLockHeartbeat(ctx context.Context,
	key, owner string, interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			ok, err := onDemand.distributedLock.Refresh(refreshCtx, key, owner, syncLockTTL)
			cancel()

			if err != nil {
				onDemand.log.Warn().Err(err).Str("key", key).
					Msg("failed to refresh distributed sync lock")

				continue
			}

			if !ok {
				onDemand.log.Warn().Str("key", key).
					Msg("lost ownership of distributed sync lock; stopping heartbeat")

				return
			}
		}
	}
}

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	return onDemand.runWithLock(ctx, "image", repo, reference, func(result *syncResult) {
		onDemand.syncImage(ctx, repo, reference, result)
	})
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	return onDemand.runWithLock(ctx, "referrers", repo, subjectDigestStr, func(result *syncResult) {
		onDemand.syncReferrers(ctx, repo, subjectDigestStr, referenceTypes, result)
	})
}

// runWithLock combines in-process dedup, distributed locking, and the
// heartbeat goroutine. The run closure executes the actual sync and is
// expected to set result.err and close result.done.
func (onDemand *BaseOnDemand) runWithLock(ctx context.Context, kind, repo, reference string,
	run func(*syncResult),
) error {
	req := request{repo: repo, reference: reference}
	result := &syncResult{done: make(chan struct{})}

	val, loaded := onDemand.requestStore.LoadOrStore(req, result)
	if loaded {
		onDemand.log.Info().Str("repo", repo).Str("reference", reference).Str("kind", kind).
			Msg("on-demand sync already in flight on this replica, waiting on result")

		existing, _ := val.(*syncResult)

		<-existing.done

		return existing.err
	}

	defer onDemand.requestStore.Delete(req)

	handle, release, err := onDemand.acquireDistributedLock(ctx, kind, repo, reference)
	if err != nil {
		result.err = err
		close(result.done)

		return err
	}

	defer release()

	// Heartbeat lifetime is bound to the sync run, not ctx, so we keep
	// refreshing even if the client disconnects (mirroring syncImage's
	// detached context behavior). WithoutCancel keeps the request context's
	// values while dropping its cancellation; linking to ctx instead would
	// drop the lock mid-sync on a client disconnect while the detached sync
	// (run on context.WithoutCancel(ctx)) keeps copying.
	if handle != nil {
		heartbeatCtx, heartbeatCancel := context.WithCancel(context.WithoutCancel(ctx))
		defer heartbeatCancel()

		// gosec G118: the goroutine intentionally uses a cancellation-detached
		// derivative of ctx so the lock heartbeat survives client disconnects.
		go onDemand.runLockHeartbeat(heartbeatCtx, handle.key, handle.owner, syncLockHeartbeatInterval) //nolint:gosec
	}

	go run(result)

	<-result.done

	return result.err
}

func (onDemand *BaseOnDemand) syncReferrers(ctx context.Context, repo, subjectDigestStr string,
	referenceTypes []string, result *syncResult,
) {
	defer close(result.done)

	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", subjectDigestStr).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg("starting on-demand referrer sync")

		// Create a detached context with timeout to ensure sync completes even if HTTP client disconnects.
		// This prevents Kubernetes timeout/retries from aborting in-progress referrer downloads.
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		err = service.SyncReferrers(syncCtx, repo, subjectDigestStr, referenceTypes)

		cancel()

		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrRepoNotFound) ||
				// some public registries may return 401 for not found.
				errors.Is(err, zerr.ErrUnauthorizedAccess) {
				continue
			}

			req := request{
				repo:         repo,
				reference:    subjectDigestStr,
				serviceID:    serviceID,
				isBackground: true,
			}

			// if there is already a background routine, skip
			if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
				continue
			}

			if service.CanRetryOnError() {
				retryErr := err

				// retry in background
				go func(service Service, serviceTimeout time.Duration) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", subjectDigestStr).Str("err", retryErr.Error()).
						Msg("sync routine: starting routine to copy image, because of error")

					// Use detached context with timeout for background retry
					retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serviceTimeout)
					defer cancel()

					err := service.SyncReferrers(retryCtx, repo, subjectDigestStr, referenceTypes)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", subjectDigestStr).
							Err(err).Msg("sync routine: starting routine to retry copy image due to error")
					}
				}(service, timeout)
			}
		} else {
			break
		}
	}

	result.err = err
}

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string, result *syncResult) {
	defer close(result.done)

	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", reference).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg("starting on-demand image sync")

		// Create a detached context with timeout to ensure sync completes even if HTTP client disconnects.
		// This prevents Kubernetes timeout/retries from aborting in-progress image downloads.
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		err = service.SyncImage(syncCtx, repo, reference)

		cancel()

		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) ||
				errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
				errors.Is(err, zerr.ErrSyncImageNotSigned) ||
				errors.Is(err, zerr.ErrRepoNotFound) ||
				// some public registries may return 401 for not found.
				errors.Is(err, zerr.ErrUnauthorizedAccess) {
				continue
			}

			req := request{
				repo:         repo,
				reference:    reference,
				serviceID:    serviceID,
				isBackground: true,
			}

			// if there is already a background routine, skip
			if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
				continue
			}

			if service.CanRetryOnError() {
				retryErr := err

				// retry in background
				go func(service Service, serviceTimeout time.Duration) {
					// remove image after syncing
					defer func() {
						onDemand.requestStore.Delete(req)
						onDemand.log.Info().Str("repo", repo).Str("reference", reference).
							Msg("sync routine for image exited")
					}()

					onDemand.log.Info().Str("repo", repo).Str("reference", reference).Str("err", retryErr.Error()).
						Msg("sync routine: starting routine to retry copy image due to error")

					// Use detached context with timeout for background retry
					retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serviceTimeout)
					defer cancel()

					err := service.SyncImage(retryCtx, repo, reference)
					if err != nil {
						onDemand.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
							Err(err).Msg("sync routine: error while copying image")
					}
				}(service, timeout)
			}
		} else {
			break
		}
	}

	result.err = err
}
