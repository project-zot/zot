//go:build sync

package sync

import (
	"context"
	"errors"
	"sync"

	"github.com/regclient/regclient/types/manifest"
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
	requestStore  *sync.Map
	flight        singleflight.Group
	streamManager StreamManager
	log           log.Logger
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{log: log, requestStore: &sync.Map{}}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)
}

// SetStreamManager wires the stream manager shared by every streaming-enabled service into this
// on-demand handler. Left nil when no registry config enables streaming.
func (onDemand *BaseOnDemand) SetStreamManager(sm StreamManager) {
	onDemand.streamManager = sm
}

func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return onDemand.streamManager
}

// IsStreamingEnabledForRepo returns true if any on-demand service streams blobs for repo.
//
// Note: this only gates whether the caller attempts to stream at all - it does not guarantee the
// service that actually ends up serving repo (the first one in onDemand.services whose
// FetchManifest/SyncImage succeeds, chosen independently by FetchManifestForStream and syncImage)
// is one of the streaming-enabled ones. That match only holds if streaming-enabled services are
// listed so they win the eligibility race for their own repos; a config with multiple registries
// matching the same repo, only some of which stream, is a known gap in this v1.
func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	for _, service := range onDemand.services {
		if service.IsStreamingForRepo(repo) {
			return true
		}
	}

	return false
}

// FetchManifestForStream fetches repo:reference's manifest directly from upstream and registers
// it (and its blobs) with the stream manager, then kicks off the real sync into local storage in
// the background and returns the manifest immediately - the caller can start serving/streaming
// it to a client without waiting for that background sync to finish.
//
// If repo:reference is already staged for streaming (e.g. a second client requesting the same
// image while the first client's background sync is still running), the cached manifest is
// returned directly and no second background sync is started. In the remaining race where two
// callers both pass that check before either stages the manifest, both still call the exported
// SyncImage below - which is deduplicated via flight - so at most one real sync ever runs.
func (onDemand *BaseOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
) (manifest.Manifest, error) {
	if cached, ok := onDemand.streamManager.StreamingImageManifest(repo, reference); ok {
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already present in cache")

		return cached.referenceManifest, nil
	}

	var resultManifest manifest.Manifest

	var subManifests []manifest.Manifest

	var lastErr error

	for _, service := range onDemand.services {
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("attempting to fetch manifest")

		fetchedManifest, subs, err := service.FetchManifest(ctx, repo, reference)
		if err != nil {
			lastErr = err

			continue
		}

		resultManifest, subManifests = fetchedManifest, subs

		break
	}

	if resultManifest == nil {
		// Surface the last service's error (e.g. ErrSyncImageNotSigned, ErrSyncImageFilteredOut)
		// instead of always reporting ErrBlobNotFound, so a policy rejection is visible to the
		// caller rather than looking like a plain 404.
		if lastErr != nil {
			return nil, lastErr
		}

		return nil, zerr.ErrBlobNotFound
	}

	if err := onDemand.streamManager.StoreImageForStreaming(repo, reference,
		NewStreamableManifest(resultManifest, subManifests)); err != nil {
		return nil, err
	}

	onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("syncing image in the background")

	go func() {
		syncCtx := context.WithoutCancel(ctx)
		if err := onDemand.SyncImage(syncCtx, repo, reference); err != nil {
			onDemand.log.Err(err).Str("repository", repo).Str("reference", reference).
				Msg("background sync after streaming failed")
		}
	}()

	return resultManifest, nil
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

func onDemandKey(kind, repo, reference string) string {
	return kind + "\x00" + repo + "\x00" + reference
}

// onDemandSyncFn runs one registry sync attempt (image or referrers) under a timeout ctx.
type onDemandSyncFn func(ctx context.Context, service Service) error

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	return onDemand.doOnDemandFlight(onDemandKey(onDemandKindImage, repo, reference), repo, reference,
		"image already demanded, on-demand sync result was shared",
		func() error {
			return onDemand.syncImage(ctx, repo, reference, true)
		})
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	return onDemand.doOnDemandFlight(onDemandKey(onDemandKindReferrers, repo, subjectDigestStr),
		repo, subjectDigestStr,
		"referrers for image already demanded, on-demand sync result was shared",
		func() error {
			return onDemand.syncReferrers(ctx, repo, subjectDigestStr, referenceTypes, true)
		})
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
	return onDemand.runOnDemand(ctx, repo, subjectDigestStr, "starting on-demand referrer sync",
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
	var dockerCompatErr error

	err := onDemand.runOnDemand(ctx, repo, reference, "starting on-demand image sync",
		func(syncCtx context.Context, service Service) error {
			err := service.SyncImage(syncCtx, repo, reference)
			if errors.Is(err, zerr.ErrSyncDockerCompatRequired) {
				dockerCompatErr = err
			}

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

	// Prefer docker-compat over a later content-filter miss from an unrelated registry.
	if err != nil && dockerCompatErr != nil &&
		(errors.Is(err, zerr.ErrSyncImageFilteredOut) || errors.Is(err, zerr.ErrManifestNotFound) ||
			errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrUnauthorizedAccess)) {
		return dockerCompatErr
	}

	return err
}

// runOnDemand tries each configured registry until one succeeds.
func (onDemand *BaseOnDemand) runOnDemand(ctx context.Context, repo, reference, startMsg string,
	syncFn onDemandSyncFn,
) error {
	var err error

	for serviceID, service := range onDemand.services {
		timeout := service.GetSyncTimeout()

		onDemand.log.Debug().
			Str("repo", repo).
			Str("reference", reference).
			Int("serviceID", serviceID).
			Dur("timeout", timeout).
			Msg(startMsg)

		// Detached context with timeout so sync can finish if the HTTP client disconnects.
		syncCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		err = syncFn(syncCtx, service)

		cancel()

		if err == nil {
			break
		}
	}

	return err
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
