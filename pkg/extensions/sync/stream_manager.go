package sync

import (
	"io"
	"os"
	"path"
	"sync"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/blob"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
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

type StreamManager interface {
	ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error)
	StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error)
	StoreImageForStreaming(repo, reference string, streamManifest *StreamableManifest) error
	StreamingImageManifest(repo, reference string) (*StreamableManifest, bool)
	RemoveStreamingImage(repo, reference string)
	CachedBlobInfo(blobDigest string) (blen int64, mediaType string, err error)
}

type ChunkingStreamManager struct {
	tempStore StreamTempStore
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

func NewChunkingStreamManager(config *config.Config, logger log.Logger) *ChunkingStreamManager {
	store := NewLocalTempStore(path.Join(config.Storage.RootDirectory, "_stream"), logger)

	return &ChunkingStreamManager{
		tempStore:     store,
		activeStreams: map[string]*ChunkedBlobReader{},
		streamingRefs: map[string]*StreamableManifest{},
		blobInfoMap:   map[string]descriptor.Descriptor{},
		logger:        logger,
	}
}

func (sm *ChunkingStreamManager) ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error) {
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

func (sm *ChunkingStreamManager) prepareActiveStreamForBlob(desc descriptor.Descriptor) error {
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

func (sm *ChunkingStreamManager) StoreImageForStreaming(repo, reference string,
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

func (sm *ChunkingStreamManager) prepareManifestAndContentsForStream(repo, reference string,
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

func (sm *ChunkingStreamManager) StreamingImageManifest(repo, reference string) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference
	manifest, ok := sm.streamingRefs[key]

	return manifest, ok
}

func (sm *ChunkingStreamManager) RemoveStreamingImage(repo, reference string) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference")

		return
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("removing streaming image")

	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest:
		sm.purgeManifestFromStreamCache(repo, reference, manifest.referenceManifest)
	case manifestpkg.MediaTypeOCI1ManifestList:
		// For multi-arch images, the manifest is actually an index.
		// The individual manifests inside must be purged as well.
		for _, subManifest := range manifest.subManifests {
			sm.purgeManifestFromStreamCache(repo, reference, subManifest)
		}
	default:
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")
	}

	// remove the active streams for the manifest and its blobs
	delete(sm.streamingRefs, key)

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
}

// purgeManifestFromStreamCache cleans up an individual manifest and its contents from the stream cache.
func (sm *ChunkingStreamManager) purgeManifestFromStreamCache(repo, reference string, manifest manifestpkg.Manifest) {
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

	sm.waitForClientDrainAndDeleteStream(configDesc.Digest.String())

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")
	}

	for _, layer := range layers {
		sm.waitForClientDrainAndDeleteStream(layer.Digest.String())
	}

	// finally, remove the manifest
	sm.waitForClientDrainAndDeleteStream(manifest.GetDescriptor().Digest.String())
}

func (sm *ChunkingStreamManager) waitForClientDrainAndDeleteStream(blobDigest string) {
	reader, ok := sm.activeStreams[blobDigest]
	if !ok {
		sm.logger.Warn().Str("blob", blobDigest).Msg("no active stream found for blob")

		return
	}

	reader.WaitForClientEmpty()

	delete(sm.activeStreams, blobDigest)
	delete(sm.blobInfoMap, blobDigest)

	dgst, err := godigest.Parse(blobDigest)
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to parse blob digest")

		return
	}

	blobPath := sm.tempStore.BlobPath(dgst)
	_, err = os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to stat blob in temp store")

		return
	}

	err = os.Remove(sm.tempStore.BlobPath(dgst))
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to remove blob from temp store")
	}
}
