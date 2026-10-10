//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

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
	requestStore *sync.Map
	flight       singleflight.Group
	// staging maps an image flight key to a slot closed once its streaming leader has staged (or
	// given up), so requests that arrived meanwhile can join the stream. Guarded by stagingMu.
	staging       map[string]*stagingSlot
	stagingMu     sync.Mutex
	streamManager StreamManager
	// generation is unique per BaseOnDemand (so per config reload); see streamSource.
	generation uint64
	log        log.Logger
}

// onDemandGenerations hands out BaseOnDemand.generation.
var onDemandGenerations atomic.Uint64 //nolint:gochecknoglobals // process-wide uniqueness

// stagingSlot is one image flight key's staging notification (see BaseOnDemand.staging).
//
// A slot can outlive the flight its waiters joined: a later streaming leader may adopt it. So it is
// removed by the leader that adopted it (which closes done), or else by the last request holding
// it. Removing it earlier would let a second slot appear that no leader closes, and its waiters
// would sit out the whole sync instead of joining the stream.
type stagingSlot struct {
	done chan struct{}
	// refs counts the FetchManifestForStream calls holding this slot.
	refs int
	// led is set once a streaming leader adopts the slot; that leader alone removes and closes it.
	led bool
}

func NewOnDemand(log log.Logger) *BaseOnDemand {
	return &BaseOnDemand{
		log: log, requestStore: &sync.Map{}, staging: map[string]*stagingSlot{},
		generation: onDemandGenerations.Add(1),
	}
}

// streamSource names services[idx] as a stream source (see StreamableManifest.source). The
// generation prefix matters because the stream manager survives reloads: after one, idx may name a
// different registry while the old one's streams are still in flight.
func (onDemand *BaseOnDemand) streamSource(idx int) string {
	return fmt.Sprintf("%d.%d", onDemand.generation, idx)
}

// stagingSlotLocked returns key's staging slot, creating it if absent. stagingMu must be held.
func (onDemand *BaseOnDemand) stagingSlotLocked(key string) *stagingSlot {
	slot, ok := onDemand.staging[key]
	if !ok {
		slot = &stagingSlot{done: make(chan struct{})}
		onDemand.staging[key] = slot
	}

	return slot
}

// acquireStaging returns key's staging slot, held by the caller until releaseStaging.
func (onDemand *BaseOnDemand) acquireStaging(key string) *stagingSlot {
	onDemand.stagingMu.Lock()
	defer onDemand.stagingMu.Unlock()

	slot := onDemand.stagingSlotLocked(key)
	slot.refs++

	return slot
}

// releaseStaging drops an acquireStaging hold. The last holder removes the slot, unless a leader
// adopted it (that leader removes it, see adoptStaging).
func (onDemand *BaseOnDemand) releaseStaging(key string, slot *stagingSlot) {
	onDemand.stagingMu.Lock()
	defer onDemand.stagingMu.Unlock()

	slot.refs--

	if slot.refs == 0 && !slot.led && onDemand.staging[key] == slot {
		delete(onDemand.staging, key)
	}
}

// adoptStaging marks key's slot as led by the calling flight. The returned func removes the slot
// and closes it; call it exactly once.
func (onDemand *BaseOnDemand) adoptStaging(key string) func() {
	onDemand.stagingMu.Lock()
	defer onDemand.stagingMu.Unlock()

	slot := onDemand.stagingSlotLocked(key)
	slot.led = true

	return func() {
		onDemand.stagingMu.Lock()

		if onDemand.staging[key] == slot {
			delete(onDemand.staging, key)
		}

		onDemand.stagingMu.Unlock()

		close(slot.done)
	}
}

func (onDemand *BaseOnDemand) Add(service Service) {
	onDemand.services = append(onDemand.services, service)
}

// SetStreamManager sets the shared stream manager. Left nil when no registry streams and none was
// kept from before a reload.
func (onDemand *BaseOnDemand) SetStreamManager(sm StreamManager) {
	onDemand.streamManager = sm
}

// StreamManager returns the shared stream manager, or nil if there is none. It may be one kept from
// before a reload that turned streaming off, still holding streams that are draining.
func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return onDemand.streamManager
}

// IsStreamingEnabledForRepo reports whether any on-demand service streams repo.
//
// If a separate onDemandInBackground registry also matches repo, that one wins: getImageManifest
// checks ShouldQueueOnDemandSync first, so repo gets a 404 plus a queued sync, never a stream.
func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	for _, service := range onDemand.services {
		if service.IsStreamingForRepo(repo) {
			return true
		}
	}

	return false
}

// FetchManifestForStream fetches repo:reference's manifest from upstream, stages it and its blobs
// for streaming, returns it at once, and syncs the image in the background to feed the streams.
//
// There is one on-demand sync per repo:reference: streaming runs as the leader of the same flight
// SyncImage uses. A request that finds the image staged, or a leader about to stage it, joins
// that stream; one that finds a plain sync in flight joins it and is not streamed.
//
// When the image is not streamed (already local at the upstream digest, an index, the stream cap,
// no streaming registry served it, a storage error, or a joined plain flight), the call waits for
// the sync and returns ErrSyncNotStreamed, wrapping the sync's error if it failed. The caller then
// serves from storage, as after SyncImage.
//
// onSynced, if non-nil, runs with the manifest once the sync serving it commits (streamed only).
// If ctx ends first, the call returns ctx's error; the sync goes on.
func (onDemand *BaseOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
	onSynced func(manifest.Manifest),
) (manifest.Manifest, error) {
	if onDemand.streamManager == nil {
		return nil, zerr.ErrStreamManagerNotInitialized
	}

	if staged, ok := onDemand.joinStaged(repo, reference, onSynced); ok {
		return staged, nil
	}

	key := onDemandKey(onDemandKindImage, repo, reference)

	// Taken before entering the flight, so a request that becomes a waiter just before the leader
	// stages still sees the slot close and joins the stream.
	slot := onDemand.acquireStaging(key)
	defer onDemand.releaseStaging(key, slot)

	// Recheck: a leader may have staged and dropped its slot since the first check, and nothing
	// would close ours. The staged entry lives until its flight ends, so it is still visible.
	if staged, ok := onDemand.joinStaged(repo, reference, onSynced); ok {
		return staged, nil
	}

	stagingDone := slot.done

	// If this request leads, it gets exactly one outcome (the staged manifest, or nil if not
	// streaming) before stagingDone closes and before result. A joiner gets only result.
	outcome := make(chan manifest.Manifest, 1)
	result := make(chan error, 1)

	go func() {
		// Detached: the sync goes on after the client that started it disconnects.
		syncCtx := context.WithoutCancel(ctx)

		result <- onDemand.doOnDemandFlight(key, repo, reference,
			"image already demanded, on-demand sync result was shared",
			func() error {
				return onDemand.streamOrSyncImage(syncCtx, repo, reference, onSynced, outcome)
			})
	}()

	for {
		select {
		case <-ctx.Done():
			// Client gone: stop waiting. The flight goes on; the buffered channels never block it.
			return nil, ctx.Err()
		case staged := <-outcome:
			if staged != nil {
				return staged, nil
			}

			return nil, notStreamedErr(<-result)
		case err := <-result:
			// A leader's outcome precedes its result. Prefer it: our onSynced rides on what we staged.
			select {
			case staged := <-outcome:
				if staged != nil {
					return staged, nil
				}
			default:
			}

			// We joined a plain sync.
			return nil, notStreamedErr(err)
		case <-stagingDone:
			// Fires once; a nil channel never selects again.
			stagingDone = nil

			// If we led, take our outcome; joining what we staged would register onSynced twice.
			select {
			case staged := <-outcome:
				if staged != nil {
					return staged, nil
				}

				return nil, notStreamedErr(<-result)
			default:
			}

			// Another request led and staged: serve its manifest now.
			if staged, ok := onDemand.joinStaged(repo, reference, onSynced); ok {
				return staged, nil
			}
		}
	}
}

// joinStaged returns repo:reference's staged manifest, if any, registering onSynced on its sync.
func (onDemand *BaseOnDemand) joinStaged(repo, reference string, onSynced func(manifest.Manifest),
) (manifest.Manifest, bool) {
	staged, ok := onDemand.streamManager.JoinStreamingImage(repo, reference, onSynced)
	if !ok {
		return nil, false
	}

	onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
		Msg("streaming manifest already present in cache")

	return staged.referenceManifest, true
}

// notStreamedErr is FetchManifestForStream's error for a sync that ran without streaming.
func notStreamedErr(syncErr error) error {
	if syncErr == nil {
		return zerr.ErrSyncNotStreamed
	}

	return fmt.Errorf("%w: %w", zerr.ErrSyncNotStreamed, classifyOnDemandClientError(syncErr))
}

// streamOrSyncImage is the leader's flight body: stage and sync feeding the streams, or, if it
// can't stage, run the plain on-demand sync. It sends outcome exactly once, as soon as it knows.
func (onDemand *BaseOnDemand) streamOrSyncImage(ctx context.Context, repo, reference string,
	onSynced func(manifest.Manifest), outcome chan<- manifest.Manifest,
) error {
	key := onDemandKey(onDemandKindImage, repo, reference)

	// Only this flight closes the slot. It is released after outcome is sent, so this request
	// takes its outcome instead of joining its own stage.
	releaseStaging := onDemand.adoptStaging(key)

	staged, selectedIdx, joined, stageErr := onDemand.stageForStream(ctx, repo, reference, onSynced)
	if stageErr == nil && joined {
		// A flight from before a config reload (each BaseOnDemand has its own) staged
		// repo:reference after our join check. Its sync, pinned to the digest it served, feeds the
		// streams and commits. Serve its manifest and wait for that sync: starting another beside
		// it would download the image twice, and if the tag moved upstream, the older pinned sync
		// could commit last and roll the tag back. Our onSynced rides on it (StoreImageForStreaming),
		// and its flight unstages it.
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
			Msg("joined a streaming sync from before a config reload")

		outcome <- staged.referenceManifest

		releaseStaging()

		if !staged.waitSynced() {
			return zerr.ErrSyncJoinedStreamFailed
		}

		return nil
	}

	if stageErr != nil {
		switch {
		case errors.Is(stageErr, zerr.ErrSyncImageAlreadyLocal):
			onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
				Msg("image already synced locally, using non-streaming on-demand sync")
		case errors.Is(stageErr, zerr.ErrSyncIndexNotStreamed):
			onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
				Msg("image index is not streamed, using non-streaming on-demand sync")
		case errors.Is(stageErr, zerr.ErrSyncNoStreamingRegistry):
			onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
				Msg("no registry streams repo any more, using non-streaming on-demand sync")
		case errors.Is(stageErr, zerr.ErrTooManyConcurrentStreams):
			onDemand.log.Info().Str("repo", repo).Str("reference", reference).
				Msg("max concurrent streams reached, falling back to non-streaming on-demand sync")
		default:
			onDemand.log.Warn().Err(stageErr).Str("repo", repo).Str("reference", reference).
				Msg("failed to stage image for streaming, falling back to non-streaming on-demand sync")
		}

		outcome <- nil

		releaseStaging()

		err := onDemand.syncImage(ctx, repo, reference, -1, "", true)
		onDemand.logImageSyncErr(repo, reference, err)

		return err
	}

	outcome <- staged.referenceManifest

	releaseStaging()

	onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("syncing image in the background")

	// Pinned to the registry and digest just served, so the streams get exactly that manifest's
	// blobs even if the tag moves upstream or another registry also matches repo.
	err := onDemand.syncImage(ctx, repo, reference, selectedIdx, staged.referenceManifest.GetDescriptor().Digest, true)
	onDemand.logImageSyncErr(repo, reference, err)

	// Unstage before the flight ends, so the next flight starts clean. On success this runs every
	// onSynced (ours and joiners'), atomically with removal so none is lost.
	onDemand.streamManager.RemoveStreamingImage(repo, reference, err == nil)

	return err
}

// stageForStream fetches repo:reference from the first streaming registry that serves it and
// stages it. It returns the staged manifest and that registry's index, or, with joined set,
// the manifest another flight (from before a reload) staged meanwhile, whose sync owns it.
func (onDemand *BaseOnDemand) stageForStream(ctx context.Context, repo, reference string,
	onSynced func(manifest.Manifest),
) (*StreamableManifest, int, bool, error) {
	var resultManifest manifest.Manifest

	var lastErr error

	// The sync is pinned to selectedIdx. Only streaming registries are asked: others may not meet
	// streaming's TLS requirements.
	selectedIdx := -1

	for idx, service := range onDemand.services {
		if !service.IsStreamingForRepo(repo) {
			continue
		}

		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).Msg("attempting to fetch manifest")

		// Bounded like a sync attempt: a client is waiting.
		fetchCtx, cancel := context.WithTimeout(ctx, service.GetSyncTimeout())
		fetchedManifest, err := service.FetchManifest(fetchCtx, repo, reference)

		cancel()

		if err != nil {
			lastErr = err

			continue
		}

		resultManifest = fetchedManifest
		selectedIdx = idx

		break
	}

	if resultManifest == nil {
		if lastErr != nil {
			return nil, -1, false, lastErr
		}

		// No registry streams repo: it joined a stream from before a reload that has just ended.
		return nil, -1, false, zerr.ErrSyncNoStreamingRegistry
	}

	// Unchanged tag already committed: nothing to download, so don't take stream slots for it.
	local, err := onDemand.services[selectedIdx].IsImageLocal(repo, reference, resultManifest.GetDescriptor().Digest)
	if err != nil {
		// Don't serve upstream's manifest over a storage failure; the plain sync surfaces it.
		return nil, -1, false, err
	}

	if local {
		return nil, -1, false, zerr.ErrSyncImageAlreadyLocal
	}

	// An index syncs sparsely and would feed no stream. Each platform manifest the client then
	// pulls by digest is staged on its own.
	if resultManifest.IsList() {
		return nil, -1, false, zerr.ErrSyncIndexNotStreamed
	}

	streamable := NewStreamableManifest(resultManifest)
	// Streams are keyed by source, so clients never get another registry's unverified bytes.
	streamable.source = onDemand.streamSource(selectedIdx)

	if onSynced != nil {
		streamable.onSynced = []func(manifest.Manifest){onSynced}
	}

	staged, err := onDemand.streamManager.StoreImageForStreaming(repo, reference, streamable)
	if err != nil {
		return nil, -1, false, err
	}

	// Another flight staged it after our join check (see streamOrSyncImage). StoreImageForStreaming
	// has already added our onSynced to it.
	if staged != streamable {
		return staged, -1, true, nil
	}

	return streamable, selectedIdx, false, nil
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
			err := onDemand.syncImage(ctx, repo, reference, -1, "", true)
			onDemand.logImageSyncErr(repo, reference, err)

			return err
		})

	return classifyOnDemandClientError(err)
}

// logImageSyncErr logs a hard on-demand image sync failure. Called by flight leaders only.
func (onDemand *BaseOnDemand) logImageSyncErr(repo, reference string, err error) {
	if err != nil && !isSoftOnDemandSyncErr(err) {
		onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("on-demand image sync failed")
	}
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

// syncImage tries repo:reference on each matching service until one succeeds. pinnedIdx >= 0
// restricts it to that service and pinnedDigest, if set, pins the remote fetch to that digest and
// feeds the staged streams (see StreamSyncer); both are set only by a streaming flight's leader.
func (onDemand *BaseOnDemand) syncImage(ctx context.Context, repo, reference string,
	pinnedIdx int, pinnedDigest godigest.Digest, scheduleBackground bool,
) error {
	// A pinned sync only runs on the service that served the streamed manifest.
	services := onDemand.services
	if pinnedIdx >= 0 {
		services = onDemand.services[pinnedIdx : pinnedIdx+1]
	}

	return onDemand.runOnDemandServices(ctx, repo, reference, "starting on-demand image sync",
		services,
		func(syncCtx context.Context, service Service) error {
			err := syncImageOnService(syncCtx, service, repo, reference, pinnedDigest)
			if scheduleBackground && err != nil && !isSkippableSyncImageErr(err) {
				onDemand.maybeRetryInBackground(ctx, onDemandKindImage, repo, reference,
					"image already demanded, on-demand sync result was shared",
					service, err,
					func(retryCtx context.Context) error {
						// Unpinned: by the time a retry leads, the streams are gone, so it is a
						// plain sync over every matching registry.
						return onDemand.syncImage(retryCtx, repo, reference, -1, "", false)
					})
			}

			return err
		})
}

// syncImageOnService syncs repo:reference on service. With pinnedDigest set, a StreamSyncer
// service syncs that digest and feeds the staged streams.
func syncImageOnService(ctx context.Context, service Service, repo, reference string,
	pinnedDigest godigest.Digest,
) error {
	if pinnedDigest != "" {
		if streamSyncer, ok := service.(StreamSyncer); ok {
			return streamSyncer.SyncImageForStream(ctx, repo, reference, pinnedDigest)
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
