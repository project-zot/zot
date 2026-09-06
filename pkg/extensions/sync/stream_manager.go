//go:build sync

package sync

import (
	"io"
	"os"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// streamDrainTimeout bounds how long RemoveStreamingImage waits for a slow or abandoned client
// to disconnect from a blob before force-closing its subscription. Without a bound, one stalled
// client could block cleanup of its blob indefinitely; the streamLock-scoping in
// RemoveStreamingImage keeps that wait from blocking any other blob/repo in the meantime.
const streamDrainTimeout = 30 * time.Second

// defaultMaxConcurrentStreams bounds how many distinct blobs may be streamed to clients at once
// when a registry config does not set MaxConcurrentStreams explicitly.
const defaultMaxConcurrentStreams = 32

type ChunkingStreamManager struct {
	tempStore StreamTempStore
	// activeStreams maps blob digest to the corresponding chunked blob reader
	// that is currently active and receiving data for that blob. Keyed by bare digest (not
	// repo-scoped) so that concurrent pulls of different tags/repos sharing a blob collapse onto
	// one in-flight download - safe only because ChunkedBlobReader never lets a blob that fails
	// its digest check be treated as a valid, complete download (see chunked_blob_reader.go).
	activeStreams map[string]*ChunkedBlobReader
	// streamingRefs holds the references to the images that are
	// currently being streamed and their corresponding manifest.
	// For multi-arch images, it also holds subManifests for each of the os/arch
	// manifests.
	streamingRefs map[string]*StreamableManifest
	// blobInfo holds blobs and their corresponding descriptor.
	blobInfoMap          map[string]descriptor.Descriptor
	maxConcurrentStreams int
	logger               log.Logger
	streamLock           sync.Mutex
}

// NewChunkingStreamManager creates a ChunkingStreamManager backed by a per-repo temp directory
// (each repo's own ImageStore root, not one global config-wide root), so streaming staging files
// land on whatever volume that repo's real storage already uses. maxConcurrentStreams <= 0 falls
// back to defaultMaxConcurrentStreams.
func NewChunkingStreamManager(storeController storage.StoreController, maxConcurrentStreams int,
	logger log.Logger,
) *ChunkingStreamManager {
	if maxConcurrentStreams <= 0 {
		maxConcurrentStreams = defaultMaxConcurrentStreams
	}

	return &ChunkingStreamManager{
		tempStore:            NewLocalTempStore(storeController, logger),
		activeStreams:        map[string]*ChunkedBlobReader{},
		streamingRefs:        map[string]*StreamableManifest{},
		blobInfoMap:          map[string]descriptor.Descriptor{},
		maxConcurrentStreams: maxConcurrentStreams,
		logger:               logger,
	}
}

func (sm *ChunkingStreamManager) ConnectClient(blobDigest string, writer io.Writer) (BlobCopier, error) {
	// Creates a new inflight blob copier if the blobDigest is an active stream
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	stream, ok := sm.activeStreams[blobDigest]
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	// validate the caller-supplied digest string before using it as a map key/log field
	if _, err := godigest.Parse(blobDigest); err != nil {
		return nil, err
	}

	copier := NewInFlightBlobCopier(stream, stream.OnDiskPath(), writer, sm.logger)
	sm.logger.Debug().Str("blob", blobDigest).Msg("connected client for blob")

	return copier, nil
}

func (sm *ChunkingStreamManager) CachedBlobInfo(blobDigest string) (int64, string, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc, ok := sm.blobInfoMap[blobDigest]
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	return desc.Size, desc.MediaType, nil
}

// StreamingBlobReader is executed inside regclient as part of the reader hook.
func (sm *ChunkingStreamManager) StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc := reader.GetDescriptor()
	digest := desc.Digest.String()

	// This expects the chunked blob reader to be initialized and ready
	// as the code here only supplies the reader and the descriptor.
	chunkingReader, ok := sm.activeStreams[digest]
	if !ok {
		return nil, zerr.ErrBlobReaderMissing
	}

	readerModified := chunkingReader.InitReader(reader, desc)
	if !readerModified {
		// This blob's reader is already set up for stream.
		// This can happen during multi-arch downloads if multiple os/arch
		// share the same layers.
		// To avoid double reads, do not wrap the reader.
		sm.logger.Debug().Str("blob", digest).
			Msg("blob reader is already set up for stream. skipping init and wrap")

		return reader, nil
	}

	sm.logger.Debug().Str("blob", digest).Msg("finished init chunked blob reader")

	return chunkingReader.ToBReader(), nil
}

// prepareActiveStreamForBlob creates an active stream for desc, rooted under repo's own storage,
// unless one already exists for this digest (shared across repos/tags, see activeStreams' doc).
func (sm *ChunkingStreamManager) prepareActiveStreamForBlob(repo string, desc descriptor.Descriptor) error {
	_, ok := sm.activeStreams[desc.Digest.String()]
	if ok {
		sm.logger.Warn().Str("blob", desc.Digest.String()).Msg("active stream already exists for blob")

		return nil
	}

	if len(sm.activeStreams) >= sm.maxConcurrentStreams {
		return zerr.ErrTooManyConcurrentStreams
	}

	sm.logger.Debug().Str("blob", desc.Digest.String()).Msg("adding blob to active stream")

	r, err := NewChunkedBlobReader(sm.tempStore.BlobPath(repo, desc.Digest), sm.logger)
	if err != nil {
		return err
	}

	sm.activeStreams[desc.Digest.String()] = r
	sm.blobInfoMap[desc.Digest.String()] = desc

	return nil
}

func (sm *ChunkingStreamManager) StoreImageForStreaming(repo, reference string,
	manifest *StreamableManifest,
) error {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference

	// A concurrent request for the same repo:reference may already have staged it (no
	// singleflight guard upstream) - treat this as success rather than re-preparing/erroring.
	if _, ok := sm.streamingRefs[key]; ok {
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already exists for repo:reference")

		return nil
	}

	// populate the manifest into streamingRefs
	sm.streamingRefs[key] = manifest

	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest:
		prepErr := sm.prepareManifestAndContentsForStream(repo, reference, manifest.referenceManifest)
		if prepErr != nil {
			sm.logger.Error().Err(prepErr).
				Str("repo", repo).
				Str("reference", reference).
				Str("manifest", manifest.referenceManifest.GetDescriptor().Digest.String()).
				Msg("failed to prepare manifest for stream")

			return zerr.ErrSyncFailedToPrepareManifest
		}
	case manifestpkg.MediaTypeOCI1ManifestList:
		// For multi-arch images, the manifest is actually an index.
		// The individual manifests inside must be prepared as well.
		for _, subManifest := range manifest.subManifests {
			prepErr := sm.prepareManifestAndContentsForStream(repo, reference, subManifest)
			if prepErr != nil {
				sm.logger.Error().Err(prepErr).
					Str("repo", repo).
					Str("reference", reference).
					Str("manifest", subManifest.GetDescriptor().Digest.String()).
					Msg("failed to prepare manifest for stream")

				return zerr.ErrSyncFailedToPrepareManifest
			}
		}
	default:
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")

		return zerr.ErrSyncInvalidManifestMediaType
	}

	return nil
}

// prepareManifestAndContentsForStream stages the manifest, config, and layer blobs, in that
// order. On a mid-way failure (e.g. hitting maxConcurrentStreams on a later blob) only the
// streamingRefs entry is dropped here - activeStreams/blobInfoMap entries already created for
// earlier blobs in this same manifest are left in place, since without the streamingRefs key
// nothing will later call RemoveStreamingImage to clean them up.
func (sm *ChunkingStreamManager) prepareManifestAndContentsForStream(repo, reference string,
	manifest manifestpkg.Manifest,
) error {
	key := repo + ":" + reference

	// pre-load the individual blobs into activeStreams
	// first, the manifest
	err := sm.prepareActiveStreamForBlob(repo, manifest.GetDescriptor())
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", manifest.GetDescriptor().Digest.String()).
			Msg("failed to prepare active stream for blob")

		delete(sm.streamingRefs, key)

		return err
	}

	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager, skipping pre-loading config and layers for streaming")

		return nil
	}

	// then, the config blob
	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get config descriptor from manifest")

		delete(sm.streamingRefs, key)

		return err
	}

	err = sm.prepareActiveStreamForBlob(repo, configDesc)
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", configDesc.Digest.String()).Msg("failed to prepare active stream for blob")

		delete(sm.streamingRefs, key)

		return err
	}

	// finally, the layer blobs
	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		delete(sm.streamingRefs, key)

		return err
	}

	for _, layer := range layers {
		err = sm.prepareActiveStreamForBlob(repo, layer)
		if err != nil {
			sm.logger.Error().Err(err).Str("blob", layer.Digest.String()).Msg("failed to prepare active stream for blob")

			delete(sm.streamingRefs, key)

			return err
		}
	}

	return nil
}

func (sm *ChunkingStreamManager) StreamingImageManifest(repo, reference string) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference
	manifest, ok := sm.streamingRefs[key]

	return manifest, ok
}

// RemoveStreamingImage purges repo:reference's manifest(s) and blobs from the stream cache.
// The manager-wide streamLock is only held while collecting the readers to purge and while
// applying the final map deletes - never across the drain of a slow/abandoned client, so one
// stalled client on this blob cannot block ConnectClient/StreamingBlobReader/CachedBlobInfo for
// any other repo or blob being streamed concurrently.
//
// Note: this purges activeStreams/blobInfoMap by bare digest regardless of whether another
// still-streaming repo:reference also references the same shared blob - the cross-repo dedup
// documented on activeStreams only collapses the download side, not the cleanup side.
func (sm *ChunkingStreamManager) RemoveStreamingImage(repo, reference string) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.streamLock.Unlock()
		// Debug, not Warn: syncImage calls this unconditionally after every sync on any
		// registry sharing this stream manager, so a miss here is the common case for an
		// ordinary (non-streamed) sync, not a sign of anything wrong.
		sm.logger.Debug().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference")

		return
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("removing streaming image")

	blobDigests := map[string]struct{}{}

	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest:
		sm.collectManifestBlobDigests(repo, reference, manifest.referenceManifest, blobDigests)
	case manifestpkg.MediaTypeOCI1ManifestList:
		// For multi-arch images, the manifest is actually an index.
		// The individual manifests inside must be purged as well.
		for _, subManifest := range manifest.subManifests {
			sm.collectManifestBlobDigests(repo, reference, subManifest, blobDigests)
		}
	default:
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")
	}

	// Snapshot the readers to drain, then release streamLock before waiting on any of them -
	// draining must never block other repos/blobs.
	readers := make(map[string]*ChunkedBlobReader, len(blobDigests))

	for digest := range blobDigests {
		if reader, ok := sm.activeStreams[digest]; ok {
			readers[digest] = reader
		}
	}

	delete(sm.streamingRefs, key)

	sm.streamLock.Unlock()

	for digest, reader := range readers {
		reader.WaitForClientEmpty(streamDrainTimeout)
		sm.deleteStreamFile(digest, reader.OnDiskPath())
	}

	sm.streamLock.Lock()

	for digest := range readers {
		delete(sm.activeStreams, digest)
		delete(sm.blobInfoMap, digest)
	}

	sm.streamLock.Unlock()

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
}

// collectManifestBlobDigests adds the digests of manifest's config and layers (and the manifest
// itself) to out. Called with streamLock already held.
func (sm *ChunkingStreamManager) collectManifestBlobDigests(repo, reference string,
	manifest manifestpkg.Manifest, out map[string]struct{},
) {
	out[manifest.GetDescriptor().Digest.String()] = struct{}{}

	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager, skipping removal of active streams for config and layers")

		return
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get config descriptor from manifest")
	} else {
		out[configDesc.Digest.String()] = struct{}{}
	}

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		return
	}

	for _, layer := range layers {
		out[layer.Digest.String()] = struct{}{}
	}
}

// deleteStreamFile removes blobDigest's temp file (at blobPath) from disk, if present. Called
// without streamLock held (I/O only, no shared map access).
func (sm *ChunkingStreamManager) deleteStreamFile(blobDigest, blobPath string) {
	_, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to stat blob in temp store")

		return
	}

	if err := os.Remove(blobPath); err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to remove blob from temp store")
	}
}
