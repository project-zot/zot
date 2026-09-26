//go:build sync

package sync

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// streamDrainTimeout bounds how long RemoveStreamingImage waits for a stalled client to
// disconnect from a blob before force-closing it.
const streamDrainTimeout = 30 * time.Second

type ChunkingStreamManager struct {
	tempStore StreamTempStore
	// activeStreams maps streamKey(source, digest) to the reader downloading that blob. Pulls of
	// the same blob through the same registry share one download. The source registry is part of
	// the key because bytes reach clients before the digest is verified, so a client must never
	// be fed bytes that a different registry is downloading.
	activeStreams map[string]*ChunkedBlobReader
	// streamingRefs maps "repo:reference" to the manifest staged for streaming (plus, for a
	// multi-arch image, its per-platform manifests).
	streamingRefs map[string]*StreamableManifest
	// blobInfoMap holds each stream key's blob descriptor.
	blobInfoMap map[string]descriptor.Descriptor
	// refCounts counts the staged repo:references using each stream key, so a shared blob is only
	// torn down once the last of them is removed.
	refCounts            map[string]int
	maxConcurrentStreams int
	logger               log.Logger
	streamLock           sync.Mutex
	// nextStreamGen suffixes each reader's temp file path, so a digest torn down and immediately
	// re-staged never reuses the old, still-draining reader's file. Guarded by streamLock.
	nextStreamGen uint64
}

// streamKey namespaces a blob digest by the source registry streaming it (see activeStreams).
func streamKey(source, blobDigest string) string {
	return source + "@" + blobDigest
}

// NewChunkingStreamManager creates a ChunkingStreamManager that stages blobs under each repo's
// own sync staging directory. maxConcurrentStreams <= 0 falls back to
// syncConstants.DefaultMaxConcurrentStreams.
func NewChunkingStreamManager(storeController storage.StoreController, maxConcurrentStreams int,
	logger log.Logger,
) *ChunkingStreamManager {
	if maxConcurrentStreams <= 0 {
		maxConcurrentStreams = syncConstants.DefaultMaxConcurrentStreams
	}

	return &ChunkingStreamManager{
		tempStore:            NewLocalTempStore(storeController, logger),
		activeStreams:        map[string]*ChunkedBlobReader{},
		streamingRefs:        map[string]*StreamableManifest{},
		blobInfoMap:          map[string]descriptor.Descriptor{},
		refCounts:            map[string]int{},
		maxConcurrentStreams: maxConcurrentStreams,
		logger:               logger,
	}
}

// ConnectClient attaches a client to blobDigest's active stream for repo.
func (sm *ChunkingStreamManager) ConnectClient(repo, blobDigest string, writer io.Writer) (BlobCopier, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	// validate the caller-supplied digest string before using it as a map key/log field
	if _, err := godigest.Parse(blobDigest); err != nil {
		return nil, err
	}

	// Only serve a digest that belongs to a manifest staged under this repo; otherwise a caller
	// authorized for repo B could read a blob streaming for private repo A by guessing its digest.
	// An unrelated repo gets the same "not found" as an unknown digest.
	source, ok := sm.sourceForRepoDigest(repo, blobDigest)
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	stream, ok := sm.activeStreams[streamKey(source, blobDigest)]
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	// A failed producer will never deliver the rest of the blob; refuse it so the caller can
	// recheck storage before committing to a response.
	if stream.Err() != nil {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	// Subscribe before returning (under streamLock): once this returns the caller writes a 200, so
	// cleanup must already see this client and not delete the temp file under it.
	announceChan, subscriptionID := stream.Subscribe()

	copier := NewInFlightBlobCopier(stream, stream.OnDiskPath(), writer, announceChan, subscriptionID, sm.logger)
	sm.logger.Debug().Str("repo", repo).Str("blob", blobDigest).Msg("connected client for blob")

	return copier, nil
}

// sourceForRepoDigest returns the source registry of the manifests staged under repo that reference
// blobDigest. If they come from different sources it returns false: a client can't be told which
// manifest it followed, and must never get bytes (still unverified) from a registry other than the
// one that served its manifest. Must be called with streamLock held.
func (sm *ChunkingStreamManager) sourceForRepoDigest(repo, blobDigest string) (string, bool) {
	prefix := repo + ":"

	var (
		found  string
		exists bool
	)

	for key, staged := range sm.streamingRefs {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		reference := strings.TrimPrefix(key, prefix)

		digests := map[string]struct{}{}

		// Docker schema2 manifests are accepted alongside OCI: sync never converts a manifest, and
		// Docker registries commonly serve schema2.
		manifestMediaType := manifestpkg.GetMediaType(staged.referenceManifest)
		switch manifestMediaType {
		case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
			sm.collectManifestBlobDigests(repo, reference, staged.referenceManifest, digests)
		case manifestpkg.MediaTypeOCI1ManifestList, manifestpkg.MediaTypeDocker2ManifestList:
			for _, subManifest := range staged.subManifests {
				sm.collectManifestBlobDigests(repo, reference, subManifest, digests)
			}
		}

		if _, ok := digests[blobDigest]; !ok {
			continue
		}

		if exists && found != staged.source {
			sm.logger.Debug().Str("repo", repo).Str("blob", blobDigest).
				Msg("blob staged under repo from more than one source, not streaming it")

			return "", false
		}

		found, exists = staged.source, true
	}

	return found, exists
}

// CachedBlobInfo returns the size and media type of a blob staged for streaming under repo. It is
// known from the staged manifest, before the download starts.
func (sm *ChunkingStreamManager) CachedBlobInfo(repo, blobDigest string) (int64, string, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	source, ok := sm.sourceForRepoDigest(repo, blobDigest)
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	key := streamKey(source, blobDigest)

	// Like ConnectClient, don't advertise a blob whose producer failed: a GET would be refused
	// and fall through to storage, which may not have it yet.
	stream, ok := sm.activeStreams[key]
	if !ok || stream.Err() != nil {
		return 0, "", zerr.ErrBlobNotFound
	}

	desc, ok := sm.blobInfoMap[key]
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	return desc.Size, desc.MediaType, nil
}

// StreamingBlobReader is the regclient reader hook installed by repo:reference's background sync.
// It wraps the upstream reader so each blob is written to disk and announced to clients.
func (sm *ChunkingStreamManager) StreamingBlobReader(repo, reference string, reader *blob.BReader,
) (*blob.BReader, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc := reader.GetDescriptor()
	digest := desc.Digest.String()

	// Feed only the streams of the registry repo:reference was staged from, which is the one this
	// background sync is pinned to (see FetchManifestForStream).
	staged, ok := sm.streamingRefs[repo+":"+reference]
	if !ok {
		return nil, zerr.ErrBlobReaderMissing
	}

	// The stream was created when the manifest was staged; here it only gets its producer.
	chunkingReader, ok := sm.activeStreams[streamKey(staged.source, digest)]
	if !ok {
		return nil, zerr.ErrBlobReaderMissing
	}

	readerModified := chunkingReader.InitReader(reader, desc)
	if !readerModified {
		// Another producer already feeds this blob (a layer shared across platforms, or across
		// concurrent syncs). Return the reader unwrapped so the bytes aren't written twice.
		sm.logger.Debug().Str("blob", digest).
			Msg("blob reader is already set up for stream. skipping init and wrap")

		return reader, nil
	}

	sm.logger.Debug().Str("blob", digest).Msg("finished init chunked blob reader")

	return chunkingReader.ToBReader(), nil
}

// prepareActiveStreamForBlob creates the stream for desc from source, or adds a reference to it
// if one already exists. Must be called with streamLock held.
func (sm *ChunkingStreamManager) prepareActiveStreamForBlob(repo, source string, desc descriptor.Descriptor) error {
	digest := desc.Digest.String()
	key := streamKey(source, digest)

	if _, ok := sm.activeStreams[key]; ok {
		sm.refCounts[key]++
		sm.logger.Debug().Str("blob", digest).Str("source", source).Int("refCount", sm.refCounts[key]).
			Msg("active stream already exists for blob, adding reference")

		return nil
	}

	// The cap counts distinct blobs; joining an existing stream above is always allowed.
	if len(sm.activeStreams) >= sm.maxConcurrentStreams {
		return zerr.ErrTooManyConcurrentStreams
	}

	sm.logger.Debug().Str("blob", digest).Str("source", source).Msg("adding blob to active stream")

	// Unique path per reader (see nextStreamGen): BlobPath alone is the same for every stream of a
	// digest, and a new reader truncating the file of an old one still draining would corrupt it.
	sm.nextStreamGen++
	onDiskPath := fmt.Sprintf("%s.%d", sm.tempStore.BlobPath(repo, desc.Digest), sm.nextStreamGen)

	r, err := NewChunkedBlobReader(onDiskPath, sm.logger)
	if err != nil {
		return err
	}

	sm.activeStreams[key] = r
	sm.blobInfoMap[key] = desc
	sm.refCounts[key] = 1

	return nil
}

// StoreImageForStreaming stages repo:reference's manifest and creates a stream for each of its
// blobs. See StreamManager for why the returned manifest may differ from the one passed in.
func (sm *ChunkingStreamManager) StoreImageForStreaming(repo, reference string,
	manifest *StreamableManifest,
) (*StreamableManifest, error) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	// Already staged by a concurrent request: return the staged manifest, not ours. For a mutable
	// tag the two may differ, and only the staged one's blobs have streams.
	if existing, ok := sm.streamingRefs[key]; ok {
		// The caller is served the staged manifest, so its callbacks ride on that sync.
		existing.onSynced = append(existing.onSynced, manifest.onSynced...)

		sm.streamLock.Unlock()
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already exists for repo:reference")

		return existing, nil
	}

	// Collect the unique blobs first, so a layer shared across platforms is only counted once.
	descs := map[string]descriptor.Descriptor{}

	// Docker schema2 manifests are accepted alongside OCI (see sourceForRepoDigest).
	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
		if err := sm.collectManifestDescriptorsForStream(repo, reference, manifest.referenceManifest, descs); err != nil {
			sm.streamLock.Unlock()
			sm.logger.Error().Err(err).
				Str("repo", repo).
				Str("reference", reference).
				Str("manifest", manifest.referenceManifest.GetDescriptor().Digest.String()).
				Msg("failed to prepare manifest for stream")

			return nil, zerr.ErrSyncFailedToPrepareManifest
		}
	case manifestpkg.MediaTypeOCI1ManifestList, manifestpkg.MediaTypeDocker2ManifestList:
		// A multi-arch index has no blobs of its own; stream each platform manifest's blobs.
		for _, subManifest := range manifest.subManifests {
			if err := sm.collectManifestDescriptorsForStream(repo, reference, subManifest, descs); err != nil {
				sm.streamLock.Unlock()
				sm.logger.Error().Err(err).
					Str("repo", repo).
					Str("reference", reference).
					Str("manifest", subManifest.GetDescriptor().Digest.String()).
					Msg("failed to prepare manifest for stream")

				return nil, zerr.ErrSyncFailedToPrepareManifest
			}
		}
	default:
		sm.streamLock.Unlock()
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")

		return nil, zerr.ErrSyncInvalidManifestMediaType
	}

	// On a mid-way failure (e.g. the stream cap), release only the references this call added;
	// streams shared with other staged references stay up.
	prepared := make(map[string]struct{}, len(descs))

	for digest, desc := range descs {
		if err := sm.prepareActiveStreamForBlob(repo, manifest.source, desc); err != nil {
			sm.logger.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Str("blob", digest).Msg("failed to prepare active stream for blob")

			readers := sm.releaseStreams(prepared)
			sm.streamLock.Unlock()

			sm.drainAndDeleteStreams(readers)

			// Keep ErrTooManyConcurrentStreams distinct: the caller falls back to a plain sync.
			if errors.Is(err, zerr.ErrTooManyConcurrentStreams) {
				return nil, err
			}

			return nil, zerr.ErrSyncFailedToPrepareManifest
		}

		prepared[streamKey(manifest.source, digest)] = struct{}{}
	}

	// Register only once every blob is prepared, so readers never see a partially staged entry.
	sm.streamingRefs[key] = manifest

	sm.streamLock.Unlock()

	return manifest, nil
}

// collectManifestDescriptorsForStream adds manifest, its config and its layers to out, keyed by
// digest. Unlike collectManifestBlobDigests, any failure is fatal: a manifest that can't be fully
// read must not be partially staged.
func (sm *ChunkingStreamManager) collectManifestDescriptorsForStream(repo, reference string,
	manifest manifestpkg.Manifest, out map[string]descriptor.Descriptor,
) error {
	desc := manifest.GetDescriptor()
	out[desc.Digest.String()] = desc

	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager")

		return zerr.ErrBadManifest
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get config descriptor from manifest")

		return err
	}

	out[configDesc.Digest.String()] = configDesc

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		return err
	}

	for _, layer := range layers {
		out[layer.Digest.String()] = layer
	}

	return nil
}

// StreamingImageManifest returns the manifest staged for repo:reference, if any.
func (sm *ChunkingStreamManager) StreamingImageManifest(repo, reference string) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference
	manifest, ok := sm.streamingRefs[key]

	return manifest, ok
}

// JoinStreamingImage returns the manifest staged for repo:reference, if any, and registers
// onSynced on it. Both happen under streamLock, so the callback is either registered before
// RemoveStreamingImage collects the callbacks, or the entry is already gone and ok is false.
func (sm *ChunkingStreamManager) JoinStreamingImage(repo, reference string,
	onSynced func(manifestpkg.Manifest),
) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	manifest, ok := sm.streamingRefs[repo+":"+reference]
	if ok && onSynced != nil {
		manifest.onSynced = append(manifest.onSynced, onSynced)
	}

	return manifest, ok
}

// RemoveStreamingImage unstages repo:reference and releases its blobs' streams; streams still
// used by another staged reference stay up. If synced, it then runs the entry's onSynced
// callbacks. streamLock is never held while running callbacks or draining clients, so a stalled
// client can't block other repos or blobs.
func (sm *ChunkingStreamManager) RemoveStreamingImage(repo, reference string, synced bool) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.streamLock.Unlock()
		sm.logger.Debug().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference")

		return
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("removing streaming image")

	blobDigests := map[string]struct{}{}

	// Docker schema2 manifests are accepted alongside OCI (see sourceForRepoDigest).
	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
		sm.collectManifestBlobDigests(repo, reference, manifest.referenceManifest, blobDigests)
	case manifestpkg.MediaTypeOCI1ManifestList, manifestpkg.MediaTypeDocker2ManifestList:
		// A multi-arch index's streams belong to its platform manifests.
		for _, subManifest := range manifest.subManifests {
			sm.collectManifestBlobDigests(repo, reference, subManifest, blobDigests)
		}
	default:
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")
	}

	delete(sm.streamingRefs, key)

	streamKeys := make(map[string]struct{}, len(blobDigests))
	for digest := range blobDigests {
		streamKeys[streamKey(manifest.source, digest)] = struct{}{}
	}

	readers := sm.releaseStreams(streamKeys)
	callbacks := manifest.onSynced
	manifest.onSynced = nil

	sm.streamLock.Unlock()

	// Before draining, so a slow client doesn't delay the callers' bookkeeping.
	if synced {
		for _, onSynced := range callbacks {
			onSynced(manifest.referenceManifest)
		}
	}

	sm.drainAndDeleteStreams(readers)

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
}

// releaseStreams drops one reference from each stream key and returns the readers whose count
// reached zero. Their map entries are removed right away, under the lock, so a concurrent
// prepareActiveStreamForBlob starts a fresh stream rather than joining one being torn down. Must
// be called with streamLock held; drain the returned readers after releasing it.
func (sm *ChunkingStreamManager) releaseStreams(keys map[string]struct{}) map[string]*ChunkedBlobReader {
	readers := make(map[string]*ChunkedBlobReader, len(keys))

	for key := range keys {
		count, ok := sm.refCounts[key]
		if !ok {
			continue
		}

		count--
		if count > 0 {
			sm.refCounts[key] = count

			continue
		}

		if reader, ok := sm.activeStreams[key]; ok {
			readers[key] = reader
		}

		delete(sm.activeStreams, key)
		delete(sm.blobInfoMap, key)
		delete(sm.refCounts, key)
	}

	return readers
}

// drainAndDeleteStreams waits (up to streamDrainTimeout) for each reader's clients to disconnect,
// then deletes its temp file. Must be called without streamLock held.
func (sm *ChunkingStreamManager) drainAndDeleteStreams(readers map[string]*ChunkedBlobReader) {
	for key, reader := range readers {
		// The sync is over, so nothing will feed this blob again: wake clients waiting for it to
		// start, fail those of a download cut short, and close its temp file either way. A
		// finished download is left for its clients to drain.
		reader.Abort()
		reader.WaitForClientEmpty(streamDrainTimeout)
		sm.deleteStreamFile(key, reader.OnDiskPath())
	}
}

// collectManifestBlobDigests adds the digests of manifest, its config and its layers to out.
// Best-effort (used for cleanup). Called with streamLock held.
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

// deleteStreamFile removes a stream's temp file, if present. streamID is only used for logging.
// Called without streamLock held.
func (sm *ChunkingStreamManager) deleteStreamFile(streamID, blobPath string) {
	_, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		sm.logger.Error().Err(err).Str("blob", streamID).Msg("failed to stat blob in temp store")

		return
	}

	if err := os.Remove(blobPath); err != nil {
		sm.logger.Error().Err(err).Str("blob", streamID).Msg("failed to remove blob from temp store")
	}
}
