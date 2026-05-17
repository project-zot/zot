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

type StreamManager interface {
	ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error)
	StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error)
	StoreImageForStreaming(repo, reference string, manifest manifestpkg.Manifest) error
	StreamingImageManifest(repo, reference string) (manifestpkg.Manifest, bool)
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
	streamingRefs map[string]manifestpkg.Manifest
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
		streamingRefs: map[string]manifestpkg.Manifest{},
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
	sm.logger.Info().Str("blob", blobDigest).Msg("connected client for blob")

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
	size := desc.Size

	// This expects the chunked blob reader to be initialized and ready
	// as the code here only supplies the reader and the number of bytes.
	chunkingReader, ok := sm.activeStreams[digest]
	if !ok {
		return nil, zerr.ErrBlobReaderMissing
	}

	chunkingReader.InitReader(reader, size)
	sm.logger.Debug().Str("blob", digest).Msg("finished init chunked blob reader")

	return chunkingReader.ToBReader(), nil
}

func (sm *ChunkingStreamManager) prepareActiveStreamForBlob(descriptor descriptor.Descriptor) error {
	_, ok := sm.activeStreams[descriptor.Digest.String()]
	if ok {
		sm.logger.Warn().Str("blob", descriptor.Digest.String()).Msg("active stream already exists for blob")

		return nil
	}

	r, err := NewChunkedBlobReader(sm.tempStore.BlobPath(descriptor.Digest), sm.logger)
	if err != nil {
		return err
	}

	sm.activeStreams[descriptor.Digest.String()] = r
	sm.blobInfoMap[descriptor.Digest.String()] = descriptor

	return nil
}

func (sm *ChunkingStreamManager) StoreImageForStreaming(repo, reference string, manifest manifestpkg.Manifest) error {
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

	// pre-load the individual blobs into activeStreams
	// first, the manifest
	err := sm.prepareActiveStreamForBlob(manifest.GetDescriptor())
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", manifest.GetDescriptor().Digest.String()).
			Msg("failed to prepare active stream for blob")

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

		return err
	}

	err = sm.prepareActiveStreamForBlob(configDesc)
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", configDesc.Digest.String()).Msg("failed to prepare active stream for blob")

		return err
	}

	// finally, the layer blobs
	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		return err
	}

	for _, layer := range layers {
		err = sm.prepareActiveStreamForBlob(layer)
		if err != nil {
			sm.logger.Error().Err(err).Str("blob", layer.Digest.String()).Msg("failed to prepare active stream for blob")

			return err
		}
	}

	return nil
}

func (sm *ChunkingStreamManager) StreamingImageManifest(repo, reference string) (manifestpkg.Manifest, bool) {
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

	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager, skipping removal of active streams for config and layers")

		return
	}

	// config blob
	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", configDesc.Digest.String()).
			Msg("failed to get config descriptor from manifest")

		return
	}

	sm.waitForClientDrainAndDeleteStream(configDesc.Digest.String())

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		return
	}

	for _, layer := range layers {
		sm.waitForClientDrainAndDeleteStream(layer.Digest.String())
	}

	// finally, remove the manifest
	sm.waitForClientDrainAndDeleteStream(manifest.GetDescriptor().Digest.String())

	// remove the active streams for the manifest and its blobs
	delete(sm.streamingRefs, key)

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
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

	blobPath := sm.tempStore.BlobPath(godigest.FromString(blobDigest))
	_, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to stat blob in temp store")

		return
	}

	err = os.Remove(sm.tempStore.BlobPath(godigest.FromString(blobDigest)))
	if err != nil {
		sm.logger.Error().Err(err).Str("blob", blobDigest).Msg("failed to remove blob from temp store")
	}
}
