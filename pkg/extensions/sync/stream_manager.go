package sync

import (
	"errors"
	"io"
	"path"
	"sync"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/blob"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

type StreamManager interface {
	ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error)
	StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error)
}

type ChunkingStreamManager struct {
	tempStore     StreamTempStore
	activeStreams map[string]*ChunkedBlobReader
	logger        log.Logger
	streamLock    sync.Mutex
}

func NewChunkingStreamManager(config *config.Config, logger log.Logger) *ChunkingStreamManager {
	store := NewLocalTempStore(path.Join(config.Storage.RootDirectory, "stream"))
	return &ChunkingStreamManager{
		tempStore:     store,
		activeStreams: map[string]*ChunkedBlobReader{},
		logger:        logger,
	}
}

func (sm *ChunkingStreamManager) ConnectClient(blobDigest string, writer io.Writer) (*InFlightBlobCopier, error) {
	// Creates a new inflight blob copier if the blobDigest is an active stream
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	// TODO: this can result in a race condition if the ImageCopy with Options hasn't triggered the hook yet
	stream, ok := sm.activeStreams[blobDigest]
	if !ok {
		return nil, errors.New("blob not found in active streams")
	}

	dig, err := godigest.Parse(blobDigest)
	if err != nil {
		return nil, err
	}

	copier := NewInFlightBlobCopier(stream, sm.tempStore.BlobPath(dig), writer, sm.logger)
	sm.logger.Info().Str("blob", blobDigest).Msg("connected client for blob")

	return copier, nil
}

func (sm *ChunkingStreamManager) Manifest(name, ref string) (ispec.Manifest, error) {
	return sm.tempStore.Manifest(name, ref)
}

func (sm *ChunkingStreamManager) StreamingBlobReader(reader *blob.BReader) (*blob.BReader, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	desc := reader.GetDescriptor()
	digest := desc.Digest.String()
	size := desc.Size
	wrappedReader, err := NewChunkedBlobReader(reader, chunkCount(size), sm.tempStore.BlobPath(desc.Digest), sm.logger)
	if err != nil {
		return nil, err
	}
	sm.logger.Info().Str("blob", digest).Msg("setup chunked blob reader")

	sm.activeStreams[digest] = wrappedReader
	return wrappedReader.ToBReader(), nil
}

func chunkCount(blobSize int64) int64 {
	chunkCount := blobSize / constants.StreamChunkSizeBytes
	remainder := blobSize % constants.StreamChunkSizeBytes

	if remainder > 0 {
		chunkCount++
	}

	return chunkCount
}
