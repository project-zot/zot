//go:build sync

package sync

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/sync/singleflight"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

const (
	onDemandKindImage     = "image"
	onDemandKindReferrers = "referrers"
)

// request keys in-flight background retries (one per kind+repo+reference).
type request struct {
	kind         string
	repo         string
	reference    string
	isBackground bool
}

/*
BaseOnDemand tracks on-demand image/referrer sync requests.

Concurrent SyncImage/SyncReferrers calls for the same key are deduplicated with
singleflight (one upstream sync, shared result). Background retries re-enter the
same flight so a later request for the same kind+repo+reference waits on that work.
requestStore ensures at most one background goroutine is scheduled per key.
Image and referrer keys are prefixed so a digest pull and a referrer sync for the
same subject do not share results.
*/
type BaseOnDemand struct {
	services []Service
	// background retry scheduling dedup: map[request]struct{}
	requestStore *sync.Map
	flight       singleflight.Group
	log          log.Logger
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{log: log, requestStore: &sync.Map{}}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)
}

// ShouldCheckUpstreamManifest reports whether the manifest for repo:reference has to be
// validated against upstream. Only a service that completed a successful check records a
// timestamp, so a single service reporting that the interval has not elapsed means this
// reference was verified recently and can be served from local storage.
func (onDemand *BaseOnDemand) ShouldCheckUpstreamManifest(repo, reference string) bool {
	for _, service := range onDemand.services {
		if !service.ShouldCheckUpstream(repo, reference) {
			return false
		}
	}

	return true
}

// ShouldQueueOnDemandSync reports whether any configured registry uses
// on-demand-in-background sync for this local repo.
func (onDemand *BaseOnDemand) ShouldQueueOnDemandSync(repo string) bool {
	return len(onDemand.onDemandInBackgroundServicesForRepo(repo)) > 0
}

// QueueImage schedules at most one background image sync for repo:reference, using only
// onDemandInBackground registries that match the repo. Concurrent callers for the same key
// share a singleflight; spawn itself is also deduplicated via requestStore.
func (onDemand *BaseOnDemand) QueueImage(ctx context.Context, repo, reference string) {
	if !onDemand.ShouldQueueOnDemandSync(repo) {
		return
	}

	req := request{
		kind:         onDemandKindImage,
		repo:         repo,
		reference:    reference,
		isBackground: true,
	}

	if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
		return
	}

	detachedContext := context.WithoutCancel(ctx)
	key := onDemandKey(onDemandKindImage, repo, reference)

	go func() {
		defer func() {
			onDemand.requestStore.Delete(req)
		}()

		err := onDemand.doOnDemandFlight(key, repo, reference,
			"image already demanded, on-demand sync result was shared",
			func() error {
				return onDemand.syncImageInBackground(detachedContext, repo, reference)
			})
		if err != nil {
			onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Msg("on-demand-in-background image sync failed")
		}
	}()
}

func onDemandKey(kind, repo, reference string) string {
	return kind + "\x00" + repo + "\x00" + reference
}

// onDemandSyncFn runs one registry sync attempt (image or referrers) under a timeout ctx.
type onDemandSyncFn func(ctx context.Context, service Service) error

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	// Classify after the flight so waiters that join a background retry (same key,
	// raw syncImage result) still receive opaque client sentinels. Root-cause
	// logging stays in the leader closure only.
	err := onDemand.doOnDemandFlight(onDemandKey(onDemandKindImage, repo, reference), repo, reference,
		"image already demanded, on-demand sync result was shared",
		func() error {
			err := onDemand.syncImage(ctx, repo, reference, true)

			if err != nil && !isSoftOnDemandSyncErr(err) {
				onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
					Msg("on-demand image sync failed")
			}

			return err
		})

	return classifyOnDemandClientError(err)
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	err := onDemand.doOnDemandFlight(onDemandKey(onDemandKindReferrers, repo, subjectDigestStr),
		repo, subjectDigestStr,
		"referrers for image already demanded, on-demand sync result was shared",
		func() error {
			err := onDemand.syncReferrers(ctx, repo, subjectDigestStr, referenceTypes, true)

			if err != nil && !isSoftOnDemandSyncErr(err) {
				onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", subjectDigestStr).
					Msg("on-demand referrer sync failed")
			}

			return err
		})

	return classifyOnDemandClientError(err)
}

func (onDemand *BaseOnDemand) doOnDemandFlight(key, repo, reference, sharedMsg string,
	syncFn func() error,
) error {
	// leader is set only in the closure that actually runs; waiters never execute it.
	leader := false

	_, err, shared := onDemand.flight.Do(key, func() (any, error) {
		leader = true

		return nil, syncFn()
	})

	// singleflight sets shared for every participant when dups > 0, including the leader.
	if shared && !leader {
		onDemand.log.Info().Str("repo", repo).Str("reference", reference).Msg(sharedMsg)
	}

	return err
}

func (onDemand *BaseOnDemand) syncReferrers(ctx context.Context, repo, subjectDigestStr string,
	referenceTypes []string, scheduleBackground bool,
) error {
	return onDemand.runOnDemandServices(ctx, repo, subjectDigestStr, "starting on-demand referrer sync",
		onDemand.services,
		func(syncCtx context.Context, service Service) error {
			err := service.SyncReferrers(syncCtx, repo, subjectDigestStr, referenceTypes)
			if scheduleBackground && err != nil && !isSkippableSyncImageErr(err) {
				onDemand.maybeRetryInBackground(ctx, onDemandKindReferrers, repo, subjectDigestStr,
					"referrers for image already demanded, on-demand sync result was shared",
					service, err,
					func(retryCtx context.Context) error {
						return onDemand.syncReferrers(retryCtx, repo, subjectDigestStr, referenceTypes, false)
					})
			}

			return err
		})
}

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string, scheduleBackground bool,
) error {
	return onDemand.runOnDemandServices(ctx, repo, reference, "starting on-demand image sync",
		onDemand.services,
		func(syncCtx context.Context, service Service) error {
			err := service.SyncImage(syncCtx, repo, reference)
			if scheduleBackground && err != nil && !isSkippableSyncImageErr(err) {
				onDemand.maybeRetryInBackground(ctx, onDemandKindImage, repo, reference,
					"image already demanded, on-demand sync result was shared",
					service, err,
					func(retryCtx context.Context) error {
						return onDemand.syncImage(retryCtx, repo, reference, false)
					})
			}

			return err
		})
}

// syncImageInBackground tries only onDemandInBackground registries that match the repo.
func (onDemand *BaseOnDemand) syncImageInBackground(ctx context.Context, repo, reference string) error {
	services := onDemand.onDemandInBackgroundServicesForRepo(repo)
	if len(services) == 0 {
		return nil
	}

	return onDemand.runOnDemandServices(ctx, repo, reference, "starting on-demand-in-background image sync",
		services,
		func(syncCtx context.Context, service Service) error {
			return service.SyncImage(syncCtx, repo, reference)
		})
}

func (onDemand *BaseOnDemand) onDemandInBackgroundServicesForRepo(repo string) []Service {
	services := make([]Service, 0, len(onDemand.services))

	for _, service := range onDemand.services {
		if service.IsOnDemandInBackgroundForRepo(repo) {
			services = append(services, service)
		}
	}

	return services
}

// rankOnDemandErr picks the preferred error across multi-registry on-demand attempts.
//
// Three classes (see isSoftOnDemandSyncErr / isTransientRemoteConnectivityErr):
//   - soft: registry answered with a client miss → HTTP 404
//   - weak: no content answer (dial/timeout/TLS/bad host) → demoted vs soft; alone → 503
//   - hard: everything else (auth, storage, docker-compat, …) → opaque ErrSyncInternal (503)
//
// Precedence: hard > soft > weak. Among hard errors, docker-compat wins; otherwise
// the first hard failure is kept (usually from the registry that matched the path).
func rankOnDemandErr(current, candidate error) error {
	if candidate == nil {
		return current
	}

	if current == nil {
		return candidate
	}

	currentSoft := isSoftOnDemandSyncErr(current)
	candidateSoft := isSoftOnDemandSyncErr(candidate)
	currentWeak := isTransientRemoteConnectivityErr(current)
	candidateWeak := isTransientRemoteConnectivityErr(candidate)

	switch {
	case currentSoft && !candidateSoft:
		// Soft held; candidate is hard or weak.
		if candidateWeak {
			return current // soft > weak
		}

		return candidate // hard > soft
	case !currentSoft && candidateSoft:
		// Candidate is soft; current is hard or weak.
		if currentWeak {
			return candidate // soft > weak
		}

		return current // hard > soft
	case errors.Is(candidate, zerr.ErrSyncDockerCompatRequired):
		// Prefer docker-compat config failure over other hard/weak errors.
		return candidate
	case errors.Is(current, zerr.ErrSyncDockerCompatRequired):
		return current
	case currentWeak && !candidateWeak:
		// Both non-soft: keep non-weak (hard) over weak.
		return candidate
	case !currentWeak && candidateWeak:
		return current
	case !currentSoft && !candidateSoft:
		// Two hard failures: keep the first.
		return current
	default:
		// Two soft (or leftover) outcomes: prefer the later one.
		return candidate
	}
}

// runOnDemandServices tries each service in order until one succeeds.
func (onDemand *BaseOnDemand) runOnDemandServices(ctx context.Context, repo, reference, startMsg string,
	services []Service, syncFn onDemandSyncFn,
) error {
	var preferredErr error

	for serviceID, service := range services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", reference).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg(startMsg)

		// Detached context with timeout so sync can finish if the HTTP client disconnects.
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		err := syncFn(syncCtx, service)

		cancel()

		if err == nil {
			return nil
		}

		preferredErr = rankOnDemandErr(preferredErr, err)
	}

	return preferredErr
}

// maybeRetryInBackground schedules at most one background retry for kind+repo+reference.
// The retry re-enters the same singleflight so a later matching request waits on it.
func (onDemand *BaseOnDemand) maybeRetryInBackground(ctx context.Context, kind, repo, reference, sharedMsg string,
	service Service, retryErr error, backgroundFullSync func(context.Context) error,
) {
	if !service.CanRetryOnError() {
		return
	}

	req := request{
		kind:         kind,
		repo:         repo,
		reference:    reference,
		isBackground: true,
	}

	if _, requested := onDemand.requestStore.LoadOrStore(req, struct{}{}); requested {
		return
	}

	key := onDemandKey(kind, repo, reference)

	go func() {
		defer func() {
			onDemand.requestStore.Delete(req)
			onDemand.log.Info().Str("repo", repo).Str("reference", reference).
				Msg("sync routine for image exited")
		}()

		onDemand.log.Info().Str("repo", repo).Str("reference", reference).Str("err", retryErr.Error()).
			Msg("sync routine: starting routine to retry copy image due to error")

		// Loop until we are the flight leader (or a concurrent request already succeeded):
		// a Do started while the failed call still holds the key shares that failure and
		// would otherwise skip the retry while still holding requestStore.
		for {
			leader := false

			err := onDemand.doOnDemandFlight(key, repo, reference, sharedMsg, func() error {
				leader = true

				return backgroundFullSync(context.WithoutCancel(ctx))
			})
			if leader {
				if err != nil {
					onDemand.log.Error().Str("errorType", common.TypeOf(err)).
						Str("repo", repo).Str("reference", reference).
						Err(err).Msg("sync routine: error while copying image")
				}

				return
			}

			if err == nil {
				return
			}
		}
	}()
}
