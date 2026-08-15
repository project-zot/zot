//go:build sync

package stream

import (
	"context"
	"io"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	"zotregistry.dev/zot/v2/pkg/log"
)

// This file implements demand-driven priority fetching for streaming sync.
//
// The background sync downloads every blob of every platform of an image with
// a small per-host concurrency budget and in effectively arbitrary order, so
// the layers a downstream client is actually waiting on can sit queued behind
// multi-GB layers of other platforms for a long time. The priority fetcher
// opens an out-of-band upstream download — through a dedicated client with its
// own concurrency budget — for exactly the blobs clients care about:
//
//   - a blob a client GET is currently waiting on (client demand), and
//   - the config and layers of a platform manifest a client resolved by
//     digest (platform prefetch), since the client will request them next.
//
// The fetched bytes flow through the same ChunkedBlobReader as the background
// sync, so waiting clients are served while the download progresses, and the
// background sync deduplicates against it (it is fed from the in-progress
// temp file instead of opening a second upstream download of the same bytes).
// If a priority fetch fails mid-blob, the chunked reader is marked failed and
// the background sync re-arms it with a resume on its next attempt, so the
// failure degrades to the pre-priority behavior.

const (
	// maxConcurrentPriorityFetches limits concurrent priority fetches of
	// blobs that downstream clients are waiting on.
	maxConcurrentPriorityFetches = 4
	// maxConcurrentPlatformPrefetches limits concurrent prefetches of the
	// blobs of a client-resolved platform manifest.
	maxConcurrentPlatformPrefetches = 2
	// PriorityFetchHostConcurrency is the per-host request budget the
	// dedicated upstream client used for priority fetches should be
	// configured with, so demand fetches and prefetches never starve each
	// other at the HTTP layer.
	PriorityFetchHostConcurrency = maxConcurrentPriorityFetches + maxConcurrentPlatformPrefetches
)

// OpenBlobFunc opens an upstream reader for a blob of the given local repo.
// Implementations resolve the remote repo/reference and must use a client
// whose per-host budget is independent from the background sync (see
// PriorityFetchHostConcurrency).
type OpenBlobFunc func(ctx context.Context, localRepo string, desc descriptor.Descriptor) (*blob.BReader, error)

// PriorityFetcher downloads individual blobs out-of-band and feeds them into
// the stream manager's active streams.
type PriorityFetcher struct {
	manager  Manager
	openBlob OpenBlobFunc
	// timeout bounds a single blob fetch; zero means no explicit bound.
	timeout time.Duration
	logger  log.Logger

	prioritySem chan struct{}
	prefetchSem chan struct{}

	mu       sync.Mutex
	inFlight map[string]struct{}
}

func NewPriorityFetcher(manager Manager, openBlob OpenBlobFunc, timeout time.Duration,
	logger log.Logger,
) *PriorityFetcher {
	return &PriorityFetcher{
		manager:     manager,
		openBlob:    openBlob,
		timeout:     timeout,
		logger:      logger,
		prioritySem: make(chan struct{}, maxConcurrentPriorityFetches),
		prefetchSem: make(chan struct{}, maxConcurrentPlatformPrefetches),
		inFlight:    map[string]struct{}{},
	}
}

// PrioritizeBlob starts an out-of-band upstream download for a blob a
// downstream client is waiting on, unless the blob is already being fed by the
// background sync or another priority fetch. It returns immediately; the
// download runs in the background.
func (pf *PriorityFetcher) PrioritizeBlob(localRepo string, digest godigest.Digest) {
	if !pf.manager.NeedsUpstreamData(digest.String()) {
		return
	}

	if !pf.markInFlight(digest.String()) {
		return
	}

	go func() {
		defer pf.unmarkInFlight(digest.String())

		pf.prioritySem <- struct{}{}
		defer func() { <-pf.prioritySem }()

		// Re-check after waiting for a slot: the background sync (or an
		// earlier fetch) may have started this blob in the meantime.
		if !pf.manager.NeedsUpstreamData(digest.String()) {
			return
		}

		pf.fetch(localRepo, digest, "client demand")
	}()
}

// PrefetchManifestBlobs schedules priority downloads for the config and layers
// (in manifest order) of a platform manifest that a client resolved by digest
// — the client is about to request exactly these blobs.
func (pf *PriorityFetcher) PrefetchManifestBlobs(localRepo string, mfst manifestpkg.Manifest) {
	imager, ok := mfst.(manifestpkg.Imager)
	if !ok {
		return
	}

	descs := []descriptor.Descriptor{}

	if configDesc, err := imager.GetConfig(); err == nil {
		descs = append(descs, configDesc)
	}

	if layers, err := imager.GetLayers(); err == nil {
		descs = append(descs, layers...)
	}

	go func() {
		for _, desc := range descs {
			digest := desc.Digest

			if !pf.manager.NeedsUpstreamData(digest.String()) {
				continue
			}

			if !pf.markInFlight(digest.String()) {
				continue
			}

			// Acquire the slot in submission order so blobs start downloading
			// in manifest order — the order clients request them.
			pf.prefetchSem <- struct{}{}

			go func(dgst godigest.Digest) {
				defer pf.unmarkInFlight(dgst.String())
				defer func() { <-pf.prefetchSem }()

				if !pf.manager.NeedsUpstreamData(dgst.String()) {
					return
				}

				pf.fetch(localRepo, dgst, "platform prefetch")
			}(digest)
		}
	}()
}

// fetch downloads a single blob from upstream and feeds it into the blob's
// active stream. Blocking; called from the scheduling goroutines above with a
// semaphore slot held.
func (pf *PriorityFetcher) fetch(localRepo string, dgst godigest.Digest, reason string) {
	// The stream may have been torn down (commit finished, image aborted)
	// since scheduling; in that case there is nothing to prioritize.
	size, mediaType, err := pf.manager.CachedBlobInfo(dgst.String())
	if err != nil {
		return
	}

	ctx := context.Background()

	if pf.timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, pf.timeout)
		defer cancel()
	}

	pf.logger.Info().Str("repo", localRepo).Str("blob", dgst.String()).Str("reason", reason).
		Msg("starting priority fetch for streamed blob")

	desc := descriptor.Descriptor{Digest: dgst, Size: size, MediaType: mediaType}

	breader, err := pf.openBlob(ctx, localRepo, desc)
	if err != nil {
		pf.logger.Warn().Err(err).Str("repo", localRepo).Str("blob", dgst.String()).
			Msg("priority fetch: failed to open upstream blob")

		return
	}

	wrapped, claimed, err := pf.manager.ClaimBlobStream(breader)
	if err != nil || !claimed {
		if err != nil {
			pf.logger.Warn().Err(err).Str("blob", dgst.String()).
				Msg("priority fetch: failed to claim blob stream")
		}

		_ = breader.Close()

		return
	}

	// Pump the wrapped reader: bytes are written to the stream temp file and
	// announced to connected clients as they arrive.
	written, copyErr := io.Copy(io.Discard, wrapped)

	_ = wrapped.Close()
	_ = breader.Close()

	if copyErr != nil {
		pf.logger.Warn().Err(copyErr).Str("blob", dgst.String()).Int64("written", written).
			Msg("priority fetch failed; background sync will resume this blob")

		return
	}

	pf.logger.Info().Str("repo", localRepo).Str("blob", dgst.String()).
		Int64("size", written).Str("reason", reason).Msg("priority fetch completed")
}

// markInFlight records that a priority fetch of the blob is queued or running.
// Returns false when one already is.
func (pf *PriorityFetcher) markInFlight(digest string) bool {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if _, ok := pf.inFlight[digest]; ok {
		return false
	}

	pf.inFlight[digest] = struct{}{}

	return true
}

func (pf *PriorityFetcher) unmarkInFlight(digest string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	delete(pf.inFlight, digest)
}
