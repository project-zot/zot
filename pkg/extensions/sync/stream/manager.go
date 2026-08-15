//go:build sync

package stream

import (
	"io"
	"os"
	"strings"
	"sync"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

type StreamableManifest struct {
	referenceManifest manifestpkg.Manifest
	subManifests      []manifestpkg.Manifest
}

func NewStreamableManifest(mainManifest manifestpkg.Manifest, subManifests []manifestpkg.Manifest) *StreamableManifest {
	return &StreamableManifest{
		referenceManifest: mainManifest,
		subManifests:      subManifests,
	}
}

// ReferenceManifest returns the main (reference) manifest of this streamable image.
func (sm *StreamableManifest) ReferenceManifest() manifestpkg.Manifest {
	return sm.referenceManifest
}

// SubManifests returns the per-platform manifests of a multi-arch streamable image.
func (sm *StreamableManifest) SubManifests() []manifestpkg.Manifest {
	return sm.subManifests
}

type Manager interface {
	ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error)
	StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error)
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest) error
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	RemoveStreamingImage(repo, reference string)
	// AbortStreamingImage tears down the stream state for an image whose sync
	// terminally failed (all retries exhausted): subscribers are closed
	// immediately instead of waiting for them, and partial temp files are kept
	// for a future resume.
	AbortStreamingImage(repo, reference string)
	CachedBlobInfo(blobDigest string) (blen int64, mediaType string, err error)
	// StreamBlobPath returns the on-disk path of a fully-downloaded blob in the stream
	// temp store, or an empty string if the blob is not available (still in-flight or
	// already cleaned up).
	StreamBlobPath(blobDigest string) string
	// RemoveStreamBlob deletes a specific blob's temp file from the stream store.
	// Used to evict corrupt blobs that fail digest verification, so the next retry
	// downloads from scratch instead of resuming from bad data.
	RemoveStreamBlob(blobDigest string)
}

type ChunkingManager struct {
	tempStore TempStore
	// activeStreams maps blob digest to the corresponding chunked blob reader
	// that is currently active and receiving data for that blob.
	activeStreams map[string]*ChunkedBlobReader
	// streamingRefs holds the references to the images that are
	// currently being streamed and their corresponding manifest.
	// For multi-arch images, it also holds subManifests for each of the os/arch
	// manifests.
	streamingRefs map[string]*StreamableManifest
	// blobInfo holds blobs and their corresponding descriptor.
	blobInfoMap map[string]descriptor.Descriptor
	logger      log.Logger
	streamLock  sync.Mutex
}

func NewChunkingManager(rootDir string, logger log.Logger) *ChunkingManager {
	store := NewLocalTempStore(rootDir, logger)

	return &ChunkingManager{
		tempStore:     store,
		activeStreams: map[string]*ChunkedBlobReader{},
		streamingRefs: map[string]*StreamableManifest{},
		blobInfoMap:   map[string]descriptor.Descriptor{},
		logger:        logger,
	}
}

// RemoveStreamBlob deletes a specific blob's temp file from the stream store.
// This is used to evict corrupt blobs (e.g. after a digest mismatch) so the next
// retry downloads from scratch instead of resuming from bad data.
func (sm *ChunkingManager) RemoveStreamBlob(blobDigest string) {
	dig, err := godigest.Parse(blobDigest)
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).
			Msg("failed to parse digest for stream blob removal")

		return
	}

	blobPath := sm.tempStore.BlobPath(dig)
	if err := os.Remove(blobPath); err != nil && !os.IsNotExist(err) {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Str("path", blobPath).
			Msg("failed to remove corrupt stream blob")
	} else {
		sm.logger.Info().Str("blob", blobDigest).
			Msg("removed corrupt stream blob to force fresh download on retry")
	}
}

func (sm *ChunkingManager) ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error) {
	// Creates a new inflight blob copier if the blobDigest is an active stream
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	stream, ok := sm.activeStreams[blobDigest]
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	dig, err := godigest.Parse(blobDigest)
	if err != nil {
		return nil, err
	}

	copier := NewInFlightBlobCopier(stream, sm.tempStore.BlobPath(dig), writer, sm.logger)
	sm.logger.Debug().Str("blob", blobDigest).Msg("connected client for blob")

	return copier, nil
}

func (sm *ChunkingManager) CachedBlobInfo(blobDigest string) (int64, string, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc, ok := sm.blobInfoMap[blobDigest]
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	return desc.Size, desc.MediaType, nil
}

// StreamBlobPath returns the path of a fully-downloaded blob in the stream temp store.
// Returns empty string if the blob file does not exist or has not finished downloading.
func (sm *ChunkingManager) StreamBlobPath(blobDigest string) string {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc, ok := sm.blobInfoMap[blobDigest]
	if !ok {
		return ""
	}

	dig, err := godigest.Parse(blobDigest)
	if err != nil {
		return ""
	}

	blobPath := sm.tempStore.BlobPath(dig)

	info, err := os.Stat(blobPath)
	if err != nil {
		return ""
	}

	// Only return the path if the file is complete (size matches expected).
	if info.Size() < desc.Size {
		return ""
	}

	return blobPath
}

// StreamingBlobReader is executed inside regclient as part of the reader hook.
func (sm *ChunkingManager) StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc := reader.GetDescriptor()
	digest := desc.Digest.String()

	// This expects the chunked blob reader to be initialized and ready
	// as the code here only supplies the reader and the descriptor.
	chunkingReader, ok := sm.activeStreams[digest]
	if !ok {
		// No stream state for this blob (e.g. it was torn down after a terminal
		// failure, purged as a shared layer of another manifest, or this copy
		// does not belong to a streaming pull at all). Fall back to a plain
		// upstream copy instead of failing the sync.
		sm.logger.Warn().Str("blob", digest).
			Msg("no active stream for blob, falling back to plain upstream copy")

		return reader, nil
	}

	// Retry path: a previous attempt already initialized this reader.
	// The ChunkedBlobReader survives across sync retries (regclient-level and
	// on-demand background retries both re-invoke this hook with a fresh
	// upstream reader), so it must be handled explicitly here instead of
	// silently returning the raw reader — otherwise subscribed clients would
	// never receive further byte announcements and would hang forever.
	if chunkingReader.Initialized() {
		// Blob already fully on disk from a previous attempt: serve regclient
		// from the local file and drop the fresh upstream stream.
		if chunkingReader.Completed() {
			sm.logger.Info().Str("blob", digest).
				Msg("blob already complete on disk from previous attempt, serving from file")

			diskFile, err := os.Open(sm.tempStore.BlobPath(desc.Digest))
			if err != nil {
				return nil, err
			}

			rawHeaders := reader.RawHeaders()
			// Drop the fresh upstream connection; it will not be read.
			_ = reader.Close()

			return blob.NewReader(
				blob.WithHeader(rawHeaders),
				blob.WithDesc(desc),
				blob.WithReader(diskFile),
			), nil
		}

		// Previous attempt failed mid-download: re-arm the reader in place so
		// the retry continues appending to disk and announcing to clients.
		if chunkingReader.ReinitReader(reader, desc) {
			sm.logger.Info().Str("blob", digest).
				Msg("re-armed failed blob reader for retry")

			return chunkingReader.ToBReader(), nil
		}

		// Download is still actively in flight: another sync of the same image
		// (e.g. a concurrent pull by tag and by digest, or multi-arch manifests
		// sharing a layer) is already feeding this blob from upstream. Serve
		// this copy from the in-progress on-disk file instead of opening a
		// second upstream download of the same bytes.
		sm.logger.Info().Str("blob", digest).
			Msg("blob download already in flight, serving duplicate sync from the in-progress file")

		return sm.inFlightDuplicateReader(chunkingReader, reader)
	}

	resumeOffset := chunkingReader.ResumeOffset()

	// Plan A: blob is already fully on disk — skip the upstream BlobCopy entirely.
	// Signal the ChunkedBlobReader as complete so waiting clients get served from
	// the existing file. Return a reader over the full on-disk file so regclient
	// can verify the digest without re-downloading.
	if resumeOffset > 0 && resumeOffset >= desc.Size {
		sm.logger.Info().Str("blob", digest).Int64("size", desc.Size).
			Msg("blob already complete on disk, serving from file")

		chunkingReader.InitReaderComplete(reader, desc)

		diskFile, err := os.Open(sm.tempStore.BlobPath(godigest.Digest(desc.Digest.String())))
		if err != nil {
			return nil, err
		}

		fullReader := blob.NewReader(
			blob.WithHeader(reader.RawHeaders()),
			blob.WithDesc(desc),
			blob.WithReader(diskFile),
		)

		return fullReader, nil
	}

	// Plan B: partial file on disk — construct a MultiReader (disk prefix + upstream suffix)
	// so that regclient sees the full blob for digest verification, while the
	// ChunkedBlobReader only appends the new suffix bytes to disk.
	if resumeOffset > 0 {
		sm.logger.Info().Str("blob", digest).Int64("resumeOffset", resumeOffset).Int64("totalSize", desc.Size).
			Msg("resuming blob download: using MultiReader for prefix+suffix")

		// Discard the already-downloaded prefix from the upstream reader.
		discarded, err := io.CopyN(io.Discard, reader, resumeOffset)
		if err != nil {
			sm.logger.Error().Err(err).Str("blob", digest).
				Int64("expected", resumeOffset).Int64("discarded", discarded).
				Msg("failed to discard prefix bytes for resume")

			return nil, err
		}

		// Open the partial file for reading the prefix.
		diskFile, err := os.Open(sm.tempStore.BlobPath(godigest.Digest(desc.Digest.String())))
		if err != nil {
			return nil, err
		}

		// Tell the ChunkedBlobReader to skip writing the first resumeOffset bytes
		// that come from the disk prefix (they are already on disk).
		chunkingReader.SetSkipDiskWriteBytes(resumeOffset)

		// Combine: disk prefix (already downloaded) + upstream suffix (new data).
		combined := io.MultiReader(diskFile, reader)

		// Wrap combined as a blob.BReader for the ChunkedBlobReader.
		combinedBlobReader := blob.NewReader(
			blob.WithHeader(reader.RawHeaders()),
			blob.WithDesc(desc),
			blob.WithReader(combined),
		)

		readerModified := chunkingReader.InitReader(combinedBlobReader, desc)
		if !readerModified {
			sm.logger.Debug().Str("blob", digest).
				Msg("blob reader is already set up for stream. skipping init and wrap")

			return reader, nil
		}

		sm.logger.Debug().Str("blob", digest).Msg("finished init chunked blob reader (resumed)")

		return chunkingReader.ToBReader(), nil
	}

	// Normal path: no resume, fresh download.
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

func (sm *ChunkingManager) prepareActiveStreamForBlob(desc descriptor.Descriptor) error {
	_, ok := sm.activeStreams[desc.Digest.String()]
	if ok {
		sm.logger.Warn().Str("blob", desc.Digest.String()).Msg("active stream already exists for blob")

		return nil
	}

	sm.logger.Debug().Str("blob", desc.Digest.String()).Msg("adding blob to active stream")

	r, err := NewChunkedBlobReader(sm.tempStore.BlobPath(desc.Digest), sm.logger)
	if err != nil {
		return err
	}

	sm.activeStreams[desc.Digest.String()] = r
	sm.blobInfoMap[desc.Digest.String()] = desc

	return nil
}

func (sm *ChunkingManager) StoreImageForStreaming(repo, reference string,
	manifest *StreamableManifest,
) error {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference

	if _, ok := sm.streamingRefs[key]; ok {
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already exists for repo:reference")

		return nil
	}

	// populate the manifest into streamingRefs
	sm.streamingRefs[key] = manifest

	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
		prepErr := sm.prepareManifestAndContentsForStream(repo, reference, manifest.referenceManifest)
		if prepErr != nil {
			sm.logger.Error().Err(prepErr).
				Str("repo", repo).
				Str("reference", reference).
				Str("manifest", manifest.referenceManifest.GetDescriptor().Digest.String()).
				Msg("failed to prepare manifest for stream")

			return zerr.ErrSyncFailedToPrepareManifest
		}
	case manifestpkg.MediaTypeOCI1ManifestList, manifestpkg.MediaTypeDocker2ManifestList:
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

func (sm *ChunkingManager) prepareManifestAndContentsForStream(repo, reference string,
	manifest manifestpkg.Manifest,
) error {
	key := repo + ":" + reference

	// pre-load the individual blobs into activeStreams
	// first, the manifest
	err := sm.prepareActiveStreamForBlob(manifest.GetDescriptor())
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
		sm.logger.Error().Err(err).Str("blob", configDesc.Digest.String()).
			Msg("failed to get config descriptor from manifest")

		delete(sm.streamingRefs, key)

		return err
	}

	err = sm.prepareActiveStreamForBlob(configDesc)
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
		err = sm.prepareActiveStreamForBlob(layer)
		if err != nil {
			sm.logger.Error().Err(err).Str("blob", layer.Digest.String()).Msg("failed to prepare active stream for blob")

			delete(sm.streamingRefs, key)

			return err
		}
	}

	return nil
}

func (sm *ChunkingManager) StreamingImageManifest(repo, reference string) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference
	if manifest, ok := sm.streamingRefs[key]; ok {
		return manifest, ok
	}

	// Digest lookups may target an image that is already streaming under a
	// different reference: clients pulling a multi-arch image by tag follow up
	// with GETs of the sub-manifests by digest, and k8s nodes may pin the same
	// image by digest. Match the digest against each cached index and its
	// sub-manifests so no duplicate background sync is started for content
	// that is already being streamed.
	if _, err := godigest.Parse(reference); err != nil {
		return nil, false
	}

	prefix := repo + ":"

	for entryKey, manifest := range sm.streamingRefs {
		if !strings.HasPrefix(entryKey, prefix) {
			continue
		}

		if manifest.referenceManifest.GetDescriptor().Digest.String() == reference {
			return manifest, true
		}

		for _, subManifest := range manifest.subManifests {
			if subManifest.GetDescriptor().Digest.String() == reference {
				// Return the sub-manifest as a standalone streamable manifest;
				// its blobs already belong to the parent's active streams.
				return NewStreamableManifest(subManifest, nil), true
			}
		}
	}

	return nil, false
}

func (sm *ChunkingManager) RemoveStreamingImage(repo, reference string) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.streamLock.Unlock()

		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference")

		return
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("removing streaming image")

	// Detach all stream entries belonging to this image while holding the lock,
	// but do NOT wait for clients here: waiting under streamLock would freeze
	// every stream operation (client connects, HEAD lookups, sync hooks) until
	// the slowest client of this image finished downloading.
	detached := sm.detachStreams(repo, reference, manifest)

	delete(sm.streamingRefs, key)
	sm.streamLock.Unlock()

	// Wait for the remaining clients of each blob to drain, then delete the
	// temp files, all without holding streamLock.
	for digest, reader := range detached {
		reader.WaitForClientEmpty()
		sm.removeStreamTempFile(digest)
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
}

// AbortStreamingImage tears down the stream state for an image whose sync has
// terminally failed (all retries exhausted). Unlike RemoveStreamingImage it
// never waits for clients: every subscriber is closed immediately so that no
// downstream client hangs on a stream that will never advance. Partial temp
// files are kept so a future on-demand sync can resume from them.
func (sm *ChunkingManager) AbortStreamingImage(repo, reference string) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.streamLock.Unlock()

		sm.logger.Debug().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference, nothing to abort")

		return
	}

	sm.logger.Warn().Str("repo", repo).Str("reference", reference).
		Msg("aborting streaming image after terminal sync failure")

	detached := sm.detachStreams(repo, reference, manifest)

	delete(sm.streamingRefs, key)
	sm.streamLock.Unlock()

	// Abort closes all subscriber channels, unblocks Descriptor() waiters and
	// refuses new subscriptions; it is fast and never waits for clients.
	for _, reader := range detached {
		reader.Abort()
	}
}

// detachStreams removes all active stream entries belonging to the manifest
// (and its sub-manifests) from the manager maps and returns the detached
// readers keyed by blob digest. Shared layers already detached (or already
// cleaned by another manifest) are skipped. Must be called with streamLock held.
func (sm *ChunkingManager) detachStreams(
	repo, reference string, manifest *StreamableManifest,
) map[string]*ChunkedBlobReader {
	detached := map[string]*ChunkedBlobReader{}

	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
		sm.detachManifestStreams(repo, reference, manifest.referenceManifest, detached)
	case manifestpkg.MediaTypeOCI1ManifestList, manifestpkg.MediaTypeDocker2ManifestList:
		// For multi-arch images, the manifest is actually an index.
		// The individual manifests inside must be detached as well.
		for _, subManifest := range manifest.subManifests {
			sm.detachManifestStreams(repo, reference, subManifest, detached)
		}
	default:
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")
	}

	return detached
}

// detachManifestStreams detaches an individual manifest and its contents from
// the stream cache. Must be called with streamLock held.
func (sm *ChunkingManager) detachManifestStreams(
	repo, reference string, manifest manifestpkg.Manifest, detached map[string]*ChunkedBlobReader,
) {
	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager, skipping removal of active streams for config and layers")

		return
	}

	// config blob
	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", configDesc.Digest.String()).
			Msg("failed to get config descriptor from manifest")
	}

	sm.detachActiveStream(configDesc.Digest.String(), detached)

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")
	}

	for _, layer := range layers {
		sm.detachActiveStream(layer.Digest.String(), detached)
	}

	// finally, the manifest itself
	sm.detachActiveStream(manifest.GetDescriptor().Digest.String(), detached)
}

// detachActiveStream removes a single blob's stream entry from the manager
// maps and records its reader in detached. Must be called with streamLock held.
func (sm *ChunkingManager) detachActiveStream(blobDigest string, detached map[string]*ChunkedBlobReader) {
	if _, done := detached[blobDigest]; done {
		return
	}

	reader, ok := sm.activeStreams[blobDigest]
	if !ok {
		// Stream was already removed (e.g. this is a shared layer already
		// cleaned by another manifest).
		sm.logger.Debug().Str("blob", blobDigest).Msg("no active stream found for blob, already cleaned up")

		return
	}

	detached[blobDigest] = reader

	delete(sm.activeStreams, blobDigest)
	delete(sm.blobInfoMap, blobDigest)
}

// removeStreamTempFile deletes a blob's temp file from the stream store, unless
// a new stream re-registered the same digest while the caller was waiting for
// the old clients to drain (in that case the file belongs to the new stream).
func (sm *ChunkingManager) removeStreamTempFile(blobDigest string) {
	dgst, err := godigest.Parse(blobDigest)
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to parse blob digest")

		return
	}

	sm.streamLock.Lock()
	_, reRegistered := sm.activeStreams[blobDigest]
	sm.streamLock.Unlock()

	if reRegistered {
		sm.logger.Info().Str("blob", blobDigest).
			Msg("blob was re-registered by a new stream, keeping temp file")

		return
	}

	blobPath := sm.tempStore.BlobPath(dgst)

	if err := os.Remove(blobPath); err != nil && !os.IsNotExist(err) {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to remove blob from temp store")
	}
}

// inFlightDuplicateReader serves a duplicate sync of a blob whose download is
// already in flight. The fresh upstream connection is dropped, and the caller
// is fed from the in-progress on-disk file through an InFlightBlobCopier via a
// pipe, so the same bytes are never downloaded from upstream twice.
func (sm *ChunkingManager) inFlightDuplicateReader(
	chunkingReader *ChunkedBlobReader, reader *blob.BReader,
) (*blob.BReader, error) {
	desc := reader.GetDescriptor()
	rawHeaders := reader.RawHeaders()
	// Drop the duplicate upstream connection; it will not be read.
	_ = reader.Close()

	pipeReader, pipeWriter := io.Pipe()
	copier := NewInFlightBlobCopier(chunkingReader, sm.tempStore.BlobPath(desc.Digest), pipeWriter, sm.logger)

	go func() {
		// Copy returns nil on success; CloseWithError(nil) yields io.EOF on the
		// read side. If the primary download fails, the error propagates to
		// this sync, which will retry and re-arm the reader via the hook.
		pipeWriter.CloseWithError(copier.Copy())
	}()

	return blob.NewReader(
		blob.WithHeader(rawHeaders),
		blob.WithDesc(desc),
		blob.WithReader(pipeReader),
	), nil
}
