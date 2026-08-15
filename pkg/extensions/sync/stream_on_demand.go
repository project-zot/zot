//go:build sync

package sync

import (
	"context"
	"io"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/sync/stream"
)

// This file contains the streaming-sync specific behavior of BaseOnDemand.
// The methods below (together with IsStreamingEnabledForRepo, CachedBlobInfo
// and ConnectBlobStream) form the optional interface that the API layer
// discovers via a type assertion; the rest of the sync package stays unaware
// of streaming details.

func (onDemand *BaseOnDemand) SetStreamManager(sm stream.Manager) {
	onDemand.streamManager = sm
}

func (onDemand *BaseOnDemand) StreamManager() stream.Manager {
	return onDemand.streamManager
}

// IsStreamingEnabledForRepo returns true if any on-demand service has streaming enabled for the given repo.
func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	if onDemand.streamManager == nil {
		return false
	}

	for _, service := range onDemand.services {
		if service.IsStreamingForRepo(repo) {
			return true
		}
	}

	return false
}

// CachedBlobInfo returns the size and media type of a blob that belongs to an
// active stream, or zerr.ErrBlobNotFound when the blob is not being streamed.
func (onDemand *BaseOnDemand) CachedBlobInfo(blobDigest string) (int64, string, error) {
	if onDemand.streamManager == nil {
		return 0, "", zerr.ErrBlobNotFound
	}

	return onDemand.streamManager.CachedBlobInfo(blobDigest)
}

// ConnectBlobStream subscribes the writer to an in-flight blob download and
// returns a copy function that streams the requested byte range to it. It
// returns zerr.ErrBlobNotFoundInActiveStreams when the blob has no active
// stream (e.g. it was just committed to storage).
func (onDemand *BaseOnDemand) ConnectBlobStream(repo, blobDigest string, writer io.Writer,
) (func(ctx context.Context, start, end int64) error, error) {
	if onDemand.streamManager == nil {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	copier, err := onDemand.streamManager.ConnectClient(blobDigest, writer)
	if err != nil {
		return nil, err
	}

	// A client is now waiting on this blob: make sure its upstream download
	// is not stuck behind unrelated blobs in the background sync queue.
	onDemand.prioritizeStreamedBlob(repo, blobDigest)

	return copier.CopyRange, nil
}

// streamPrioritizerFor returns the first streaming-enabled service for the
// repo that supports priority fetching, or nil when there is none.
func (onDemand *BaseOnDemand) streamPrioritizerFor(repo string) streamPrioritizer {
	for _, service := range onDemand.services {
		if !service.IsStreamingForRepo(repo) {
			continue
		}

		if prioritizer, ok := service.(streamPrioritizer); ok {
			return prioritizer
		}
	}

	return nil
}

// prioritizeStreamedBlob asks the streaming service handling this repo to
// start an out-of-band upstream download for a blob a client is waiting on,
// when nothing is feeding its stream yet.
func (onDemand *BaseOnDemand) prioritizeStreamedBlob(repo, blobDigest string) {
	if !onDemand.streamManager.NeedsUpstreamData(blobDigest) {
		return
	}

	digest, err := godigest.Parse(blobDigest)
	if err != nil {
		return
	}

	if prioritizer := onDemand.streamPrioritizerFor(repo); prioritizer != nil {
		prioritizer.PrioritizeBlobForStream(repo, digest)
	}
}

// FetchManifestForStream directly fetches the manifest from the upstream
// services, prepares the image for streaming and kicks off the actual sync in
// the background. It returns the raw manifest content so the API layer does
// not depend on regclient types.
// This is only intended for use with streaming sync.
func (onDemand *BaseOnDemand) FetchManifestForStream(
	ctx context.Context, repo, reference string,
) ([]byte, godigest.Digest, string, error) {
	// If an image is already streaming, return the one in cache.
	// There is no need to start a new background sync if the manifest is already cached.
	cachedManifest, ok := onDemand.streamManager.StreamingImageManifest(repo, reference)
	if ok {
		onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already present in cache.")

		// A digest lookup of a concrete platform manifest reveals which
		// architecture the client is about to pull: prefetch its blobs so
		// they do not queue behind other platforms in the background sync.
		onDemand.prefetchPlatformForStream(repo, reference, cachedManifest.ReferenceManifest())

		return stream.RawManifestResponse(cachedManifest.ReferenceManifest())
	}

	var resultManifest manifest.Manifest

	var subManifestsInManifest []manifest.Manifest

	for _, service := range onDemand.services {
		onDemand.log.Debug().Str("repo", repo).Str("ref", reference).Msg("attempting to fetch manifest")
		fetchedManifest, subManifests, err := service.FetchManifest(ctx, repo, reference)
		if err != nil {
			onDemand.log.Error().Err(err).Msg("failed to fetch manifest from service")

			continue
		}
		resultManifest = fetchedManifest
		subManifestsInManifest = subManifests

		break
	}

	if resultManifest == nil {
		return nil, "", "", zerr.ErrBlobNotFound
	}

	onDemand.log.Debug().Str("repo", repo).Str("reference", reference).
		Msg("storing image for streaming")

	streamableManifest := stream.NewStreamableManifest(resultManifest, subManifestsInManifest)

	err := onDemand.streamManager.StoreImageForStreaming(repo, reference, streamableManifest)
	if err != nil {
		onDemand.log.Error().Err(err).Str("repo", repo).Str("reference", reference).
			Msg("failed to store manifest for streaming")

		return nil, "", "", err
	}

	// sync the image in the background
	go func() {
		syncCtx := context.WithoutCancel(ctx)
		if errSync := onDemand.SyncImage(syncCtx, repo, reference); errSync != nil {
			onDemand.log.Err(errSync).Str("repository", repo).Str("reference", reference).
				Msg("failed to sync image")
		}
	}()

	return stream.RawManifestResponse(resultManifest)
}

// abortStreaming tears down any streaming state for the image after a terminal
// sync failure so that connected (and late) clients fail fast instead of
// hanging on a stream that will never advance.
func (onDemand *BaseOnDemand) abortStreaming(repo, reference string) {
	if onDemand.streamManager == nil {
		return
	}

	onDemand.streamManager.AbortStreamingImage(repo, reference)
}

// prefetchPlatformForStream schedules priority downloads for the blobs of a
// platform manifest the client resolved by digest. Tag lookups and manifest
// lists carry no platform choice and are ignored.
func (onDemand *BaseOnDemand) prefetchPlatformForStream(repo, reference string, mfst manifest.Manifest) {
	if _, err := godigest.Parse(reference); err != nil {
		return
	}

	if mfst.IsList() {
		return
	}

	if prioritizer := onDemand.streamPrioritizerFor(repo); prioritizer != nil {
		prioritizer.PrefetchManifestBlobsForStream(repo, mfst)
	}
}
