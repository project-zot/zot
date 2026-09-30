//go:build sync

package sync

import (
	"context"
	"errors"
	"strconv"
	"sync"

	godigest "github.com/opencontainers/go-digest"
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

// SetStreamManager sets the shared stream manager. Left nil when no registry streams.
func (onDemand *BaseOnDemand) SetStreamManager(sm StreamManager) {
	onDemand.streamManager = sm
}

// StreamManager returns the shared stream manager, or nil when no registry enables streaming.
func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return onDemand.streamManager
}

// IsStreamingEnabledForRepo returns true if any on-demand service streams blobs for repo.
//
// Only streaming registries are asked for the streamed manifest; if none can serve it, the caller
// falls back to a plain SyncImage, which tries every matching registry.
//
// onDemandInBackground wins when a separate registry with it also matches repo: getImageManifest
// checks ShouldQueueOnDemandSync first, so the repo gets a 404 plus a queued sync and is never
// streamed.
func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	for _, service := range onDemand.services {
		if service.IsStreamingForRepo(repo) {
			return true
		}
	}

	return false
}

// FetchManifestForStream fetches repo:reference's manifest from upstream, stages it and its blobs
// for streaming, starts the real sync into local storage in the background, and returns the
// manifest right away.
//
// If repo:reference is already staged (another client is pulling it), the staged manifest is
// returned and no second sync starts. The same applies when two callers race to stage it.
//
// onSynced, if non-nil, is called with the manifest once the background sync serving it commits,
// whether this call started that sync or joined one already staged.
func (onDemand *BaseOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
	onSynced func(manifest.Manifest),
) (manifest.Manifest, error) {
	if onDemand.streamManager == nil {
		return nil, zerr.ErrStreamManagerNotInitialized
	}

	if cached, ok := onDemand.streamManager.JoinStreamingImage(repo, reference, onSynced); ok {
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already present in cache")

		return cached.referenceManifest, nil
	}

	var resultManifest manifest.Manifest

	var subManifests []manifest.Manifest

	var lastErr error

	// selectedIdx is the service that supplies the manifest; the background sync is pinned to it.
	// Only streaming services are asked: a non-streaming one may not meet streaming's TLS
	// requirements, yet its manifest would be served as if it did.
	selectedIdx := -1

	for idx, service := range onDemand.services {
		if !service.IsStreamingForRepo(repo) {
			continue
		}

		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("attempting to fetch manifest")

		fetchedManifest, subs, err := service.FetchManifest(ctx, repo, reference)
		if err != nil {
			lastErr = err

			continue
		}

		resultManifest, subManifests = fetchedManifest, subs
		selectedIdx = idx

		break
	}

	if resultManifest == nil {
		// Return the real error (e.g. not signed, filtered out) rather than a generic not-found.
		if lastErr != nil {
			return nil, lastErr
		}

		return nil, zerr.ErrBlobNotFound
	}

	streamable := NewStreamableManifest(resultManifest, subManifests)
	// Key this manifest's streams by the registry that supplied it (see activeStreams).
	streamable.source = strconv.Itoa(selectedIdx)

	if onSynced != nil {
		streamable.onSynced = []func(manifest.Manifest){onSynced}
	}

	staged, err := onDemand.streamManager.StoreImageForStreaming(repo, reference, streamable)
	if err != nil {
		return nil, err
	}

	// Another caller staged first (only possible if a mutable tag moved between our fetches):
	// serve its manifest, whose blobs are the ones staged, and leave the background sync (and our
	// onSynced, which StoreImageForStreaming moved onto it) to it.
	if staged != streamable {
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
			Msg("lost race to stage streaming manifest, serving the manifest that won instead")

		return staged.referenceManifest, nil
	}

	onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("syncing image in the background")

	// Pin the sync to the digest just staged, so a tag that moves upstream meanwhile can't make
	// it copy different blobs than the clients are being streamed.
	pinnedDigest := resultManifest.GetDescriptor().Digest

	go func() {
		// This goroutine owns the staged entry, so it alone unstages it when the sync ends, on
		// success or failure. Unstaging runs every registered onSynced (ours and joiners') on
		// success, atomically with removal so no joiner's callback is lost.
		syncCtx := context.WithoutCancel(ctx)

		err := onDemand.syncImageDeduped(syncCtx, repo, reference, selectedIdx, pinnedDigest)
		if err != nil {
			onDemand.log.Err(err).Str("repository", repo).Str("reference", reference).
				Msg("background sync after streaming failed")
		}

		onDemand.streamManager.RemoveStreamingImage(repo, reference, err == nil)
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
	return onDemand.syncImageDeduped(ctx, repo, reference, -1, "")
}

// syncImageDeduped runs the singleflight-deduped image sync for repo:reference. pinnedIdx >= 0
// restricts it to that service: the streaming background sync must run on the service that
// supplied the streamed manifest, since only its sync feeds the staged streams. pinnedDigest, if
// set, pins the remote fetch to that digest (see PinnedSyncer).
//
// A pinned sync uses its own singleflight key; otherwise it could join an unrelated unpinned sync
// of the same reference and never feed the streams.
func (onDemand *BaseOnDemand) syncImageDeduped(ctx context.Context, repo, reference string,
	pinnedIdx int, pinnedDigest godigest.Digest,
) error {
	key := onDemandKey(onDemandKindImage, repo, reference)
	if pinnedIdx >= 0 {
		key += "\x00pinned"
	}

	return onDemand.doOnDemandFlight(key, repo, reference,
		"image already demanded, on-demand sync result was shared",
		func() error {
			return onDemand.syncImage(ctx, repo, reference, pinnedIdx, pinnedDigest, true)
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

func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string,
	pinnedIdx int, pinnedDigest godigest.Digest, scheduleBackground bool,
) error {
	var dockerCompatErr error

	// A pinned sync only runs on the service that served the streamed manifest.
	services := onDemand.services
	if pinnedIdx >= 0 {
		services = onDemand.services[pinnedIdx : pinnedIdx+1]
	}

	err := onDemand.runOnDemandServices(ctx, repo, reference, "starting on-demand image sync",
		services,
		func(syncCtx context.Context, service Service) error {
			err := syncImageOnService(syncCtx, service, repo, reference, pinnedDigest)
			if errors.Is(err, zerr.ErrSyncDockerCompatRequired) {
				dockerCompatErr = err
			}

			if scheduleBackground && err != nil && !isSkippableSyncImageErr(err) {
				onDemand.maybeRetryInBackground(ctx, onDemandKindImage, repo, reference,
					"image already demanded, on-demand sync result was shared",
					service, err,
					func(retryCtx context.Context) error {
						return onDemand.syncImage(retryCtx, repo, reference, pinnedIdx, pinnedDigest, false)
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

// syncImageOnService syncs repo:reference on service, pinned to pinnedDigest when it is set and
// service implements PinnedSyncer.
func syncImageOnService(ctx context.Context, service Service, repo, reference string,
	pinnedDigest godigest.Digest,
) error {
	if pinnedDigest != "" {
		if pinnedSyncer, ok := service.(PinnedSyncer); ok {
			return pinnedSyncer.SyncImageAtDigest(ctx, repo, reference, pinnedDigest)
		}
	}

	return service.SyncImage(ctx, repo, reference)
}

// syncImageInBackground tries only onDemandInBackground registries that match the repo.
func (onDemand *BaseOnDemand) syncImageInBackground(ctx context.Context, repo, reference string) error {
	services := onDemand.onDemandInBackgroundServicesForRepo(repo)
	if len(services) == 0 {
		return nil
	}

	var dockerCompatErr error

	err := onDemand.runOnDemandServices(ctx, repo, reference, "starting on-demand-in-background image sync",
		services,
		func(syncCtx context.Context, service Service) error {
			err := service.SyncImage(syncCtx, repo, reference)
			if errors.Is(err, zerr.ErrSyncDockerCompatRequired) {
				dockerCompatErr = err
			}

			return err
		})

	if err != nil && dockerCompatErr != nil &&
		(errors.Is(err, zerr.ErrSyncImageFilteredOut) || errors.Is(err, zerr.ErrManifestNotFound) ||
			errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrUnauthorizedAccess)) {
		return dockerCompatErr
	}

	return err
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

// runOnDemandServices tries each service in order until one succeeds.
func (onDemand *BaseOnDemand) runOnDemandServices(ctx context.Context, repo, reference, startMsg string,
	services []Service, syncFn onDemandSyncFn,
) error {
	var err error

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
