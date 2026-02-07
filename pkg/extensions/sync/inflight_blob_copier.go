package sync

import (
	"errors"
	"io"
	"os"
	"sync"

	"zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

// InFlightBlobCopier represents a client that wants to stream an image while it is being downloaded.
// The data is copied first from disk up to the latest chunk and further copies wait for an announcement
// over a channel when a new chunk is available.
type InFlightBlobCopier struct {
	numChunksCopied int64
	source          *ChunkedBlobReader
	onDiskPath      string
	dest            io.Writer
	log             log.Logger
	sync.Mutex
}

func NewInFlightBlobCopier(source *ChunkedBlobReader, onDiskPath string, dest io.Writer, logger log.Logger) *InFlightBlobCopier {
	return &InFlightBlobCopier{
		numChunksCopied: 0,
		source:          source,
		dest:            dest,
		onDiskPath:      onDiskPath,
		log:             logger,
	}
}

func (ifbc *InFlightBlobCopier) Copy() (err error) {
	onDiskFile, err := os.Open(ifbc.onDiskPath)
	if err != nil {
		ifbc.log.Error().Err(err).Msg("failed to open on disk path")
		return err
	}
	defer onDiskFile.Close()

	// Register channel for latest chunk count updates
	chunkChan := make(chan int64, 1)

	id := ifbc.source.Subscribe(chunkChan)

	for {
		latestChunkNum := <-chunkChan

		ifbc.Lock()
		if latestChunkNum <= ifbc.numChunksCopied {
			ifbc.Unlock()
			continue
		}

		_, err = io.CopyN(ifbc.dest, onDiskFile, (int64(latestChunkNum)-int64(ifbc.numChunksCopied))*constants.StreamChunkSizeBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				ifbc.log.Error().Err(err).Msg("failed to read from source")
				return err
			}
		}
		ifbc.numChunksCopied = latestChunkNum
		ifbc.Unlock()

		if latestChunkNum == ifbc.source.numChunksTotal {
			// transfer is complete
			break
		}
	}

	ifbc.source.Unsubscribe(id)
	close(chunkChan)

	return nil
}
